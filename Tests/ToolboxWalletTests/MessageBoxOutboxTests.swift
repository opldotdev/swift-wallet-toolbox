import XCTest
import Foundation
import BSVCore
import BSVKeys
import BSVOverlay
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxStorage
@testable import ToolboxWallet

private actor OutboxTransport: AuthenticatedTransport {
    enum Delivery { case lost, refused, accepted }
    var delivery = Delivery.lost
    var bodies: [[UInt8]] = []
    var recipientFee = 0
    func allowDelivery() { delivery = .accepted }
    func refuseDelivery() { delivery = .refused }
    func requireFee() { recipientFee = 5 }
    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        if method == "GET" {
            return AuthenticatedResponse(statusCode: 200, headers: [:],
                body: Array("{\"status\":\"success\",\"quote\":{\"recipientFee\":\(recipientFee),\"deliveryFee\":0}}".utf8))
        }
        bodies.append(body ?? [])
        switch delivery {
        case .lost:
            throw URLError(.networkConnectionLost)
        case .refused:
            // What the 1Sat host's account gate sends before its auth runs.
            throw AuthTransportError.unauthenticatedReply(status: 403, body: Array(
                #"{"status":"error","code":"ERR_ACCOUNT_REQUIRED","description":"Recipient has no account on this host"}"#.utf8))
        case .accepted:
            return AuthenticatedResponse(statusCode: 200, headers: [:], body: Array(#"{"status":"success"}"#.utf8))
        }
    }
}

private actor OutboxWallet: MessageBoxPayingWallet {
    nonisolated let messageBoxIdentity: String
    nonisolated let protoWallet: ProtoWallet
    nonisolated let sender: PublicKey
    var creates = 0
    var resumes = 0
    var broadcasts = 0
    var aborts = 0
    let loseBroadcastResponse: Bool
    var storageAborts = true
    init(loseBroadcastResponse: Bool = false) throws {
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        sender = key.publicKey
        messageBoxIdentity = Hex.encode(key.publicKey.compressedBytes)
        protoWallet = ProtoWallet(rootKey: key)
        self.loseBroadcastResponse = loseBroadcastResponse
    }
    func refuseAborts() { storageAborts = false }
    /// As `RemoteWallet.payToCounterparty`: the hook runs before the broadcast, and a hook that
    /// throws aborts the funded action and broadcasts nothing.
    func createMessageBoxPayment(recipient: PublicKey, satoshis: UInt64,
        derivationPrefix: String, derivationSuffix: String, description: String,
        beforeBroadcast: @escaping @Sendable (CounterpartyPayment) async throws -> Void) async throws -> CounterpartyPayment {
        creates += 1
        let id = try TransactionID(displayHex: String(repeating: String(format: "%02x", 0xa0 + creates), count: 32))
        let payment = CounterpartyPayment(transactionID: id, outputIndex: 2,
            atomicBEEF: [1, 1, 1, 1], reference: "original-reference",
            results: [SendWithResult(txid: id.displayHex, status: .unproven)])
        do {
            try await beforeBroadcast(payment)
        } catch {
            aborts += 1
            throw error
        }
        broadcasts += 1
        if loseBroadcastResponse { throw URLError(.networkConnectionLost) }
        return payment
    }
    func resumeMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws {
        resumes += 1
        XCTAssertEqual(pending.reference, "original-reference")
        XCTAssertEqual(pending.atomicBEEF, [1, 1, 1, 1])
    }
    func abandonMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws -> Bool {
        XCTAssertEqual(pending.reference, "original-reference")
        guard storageAborts else { return false }
        aborts += 1
        return true
    }
}

/// Answers ls_messagebox with one advertisement, as an overlay would.
private struct OutboxAdvertisementResolver: OverlayLookupResolving {
    let answer: LookupAnswer
    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer { answer }
}

/// Records which hosts discovery asks, and answers every lookup with no outputs.
private actor OutboxRecordingFacilitator: LookupFacilitator {
    var hosts: [String] = []
    func lookup(question: LookupQuestion, at host: OverlayHost) async throws -> LookupAnswer {
        hosts.append(host.rawValue)
        return try LookupAnswer(outputList: [])
    }
}

final class MessageBoxOutboxTests: XCTestCase, @unchecked Sendable {
    private func make(_ directory: URL, _ transport: OutboxTransport) -> MessageBoxOutbox {
        MessageBoxOutbox(directory: directory, resolveHost: { _, fallback in fallback },
            makeClient: { try MessageBoxClient(host: $0, wallet: $1, transport: transport) })
    }
    private func directory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("messagebox-test-" + UUID().uuidString)
    }
    private func recipient() throws -> PublicKey {
        try PrivateKey(Array(repeating: 0, count: 31) + [2]).publicKey
    }

    private func other() throws -> PublicKey {
        try PrivateKey(Array(repeating: 0, count: 31) + [3]).publicKey
    }
    private let host = URL(string: "https://original.example")!

    func test_failedDeliverySurvivesRestartAndRetryNeverCreatesAnotherPayment() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        let outbox = make(directory, transport)
        let payee = try recipient()
        do {
            _ = try await outbox.send(wallet: wallet, to: payee, satoshis: 10,
                description: "Test PeerPay", fallbackHost: host)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.notDelivered(_, let reason) {
            XCTAssertFalse(reason.isEmpty, "the delivery's own failure must reach the caller")
        }
        let stored = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(stored.count, 1)
        XCTAssertEqual(stored.first?.amount, 10)
        XCTAssertEqual(stored.first?.host.host, "original.example")
        XCTAssertEqual(stored.first?.broadcastAccepted, true, "an undecided delivery does not stop the broadcast")
        // A new payment to the same recipient, with any amount or host, cannot overwrite it.
        do {
            _ = try await outbox.send(wallet: wallet, to: payee, satoshis: 20,
                description: "Do not double spend", fallbackHost: URL(string: "https://changed.example")!)
            XCTFail("A saved payment must block a second one to the same recipient")
        } catch MessageBoxOutboxError.pending {}
        await transport.allowDelivery()
        let restarted = make(directory, transport)
        let id = try await restarted.retry(wallet: wallet, recipient: Hex.encode(payee.compressedBytes))
        XCTAssertEqual(id, stored.first?.txid)
        let creates = await wallet.creates, resumes = await wallet.resumes
        XCTAssertEqual(creates, 1)
        XCTAssertEqual(resumes, 0)
        // Before the broadcast, after it, and the retry: one envelope each time.
        let bodies = await transport.bodies
        XCTAssertEqual(bodies.count, 3)
        XCTAssertEqual(Set(bodies).count, 1)
        let remaining = try await restarted.pending(for: wallet.sender)
        XCTAssertTrue(remaining.isEmpty)
    }

    func test_lostBroadcastResponsePersistsBeforeBroadcastAndResumesSameTransaction() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet(loseBroadcastResponse: true)
        let outbox = make(directory, transport)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Test PeerPay", fallbackHost: host)
            XCTFail("Lost response must be pending")
        } catch MessageBoxOutboxError.notDelivered {}
        let pending = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending.first?.broadcastAccepted, false)
        await transport.allowDelivery()
        _ = try await make(directory, transport).retry(wallet: wallet,
            recipient: Hex.encode(try recipient().compressedBytes))
        let creates = await wallet.creates, resumes = await wallet.resumes
        XCTAssertEqual(creates, 1)
        XCTAssertEqual(resumes, 1)
    }

    /// The 1Sat host refuses delivery to a recipient with no account there. Nothing may go on
    /// chain and nothing may be left waiting: the action is aborted and the reason is the host's.
    func test_aRefusedDeliveryBroadcastsNothingAndSavesNothing() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        await transport.refuseDelivery()
        do {
            _ = try await make(directory, transport).send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Test PeerPay", fallbackHost: host)
            XCTFail("A refused delivery must fail the send")
        } catch MessageBoxError.recipientAccountRequired {}
        let broadcasts = await wallet.broadcasts, aborts = await wallet.aborts
        XCTAssertEqual(broadcasts, 0)
        XCTAssertEqual(aborts, 1)
        let pending = try await make(directory, transport).pending(for: wallet.sender)
        XCTAssertTrue(pending.isEmpty)
    }

    func test_aSavedPaymentDoesNotBlockAPaymentToSomeoneElse() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        let outbox = make(directory, transport)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Stuck", fallbackHost: host)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.notDelivered {}
        await transport.allowDelivery()
        let txid = try await outbox.send(wallet: wallet, to: other(), satoshis: 20,
            description: "Someone else", fallbackHost: host)
        XCTAssertFalse(txid.isEmpty)
        let pending = try await outbox.pending(for: wallet.sender)
        let stuck = Hex.encode(try recipient().compressedBytes)
        XCTAssertEqual(pending.map(\.recipient), [stuck])
    }

    func test_discardingABroadcastPaymentForgetsItWithoutAborting() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        let outbox = make(directory, transport)
        let payee = Hex.encode(try recipient().compressedBytes)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Stuck", fallbackHost: host)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.notDelivered {}
        let saved = try await outbox.pending(for: wallet.sender)
        let txid = try XCTUnwrap(saved.first?.txid)
        let outcome = try await outbox.discard(wallet: wallet, recipient: payee)
        XCTAssertEqual(outcome, .forgotten(txid: txid))
        let aborts = await wallet.aborts
        XCTAssertEqual(aborts, 0, "a broadcast payment cannot be aborted")
        let pending = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(pending.isEmpty)
    }

    func test_discardingAnUnbroadcastPaymentAbortsItFirst() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet(loseBroadcastResponse: true)
        let outbox = make(directory, transport)
        let payee = Hex.encode(try recipient().compressedBytes)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Stuck", fallbackHost: host)
            XCTFail("Lost response must be pending")
        } catch MessageBoxOutboxError.notDelivered {}

        await wallet.refuseAborts()
        do {
            _ = try await outbox.discard(wallet: wallet, recipient: payee)
            XCTFail("A payment storage will not abort must be kept")
        } catch MessageBoxOutboxError.abortRefused {}
        let kept = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(kept.count, 1)

        let fresh = try OutboxWallet(loseBroadcastResponse: true)
        let keptTxid = try XCTUnwrap(kept.first?.txid)
        let outcome = try await outbox.discard(wallet: fresh, recipient: payee)
        XCTAssertEqual(outcome, .released(txid: keptTxid))
        let aborts = await fresh.aborts
        XCTAssertEqual(aborts, 1)
        let pending = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(pending.isEmpty)
    }

    /// A payment saved by an earlier version, one file per sender, is still found and retried.
    func test_aPaymentSavedPerSenderIsStillRetried() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        let payee = Hex.encode(try recipient().compressedBytes)
        do {
            _ = try await make(directory, transport).send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Old", fallbackHost: host)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.notDelivered {}
        let current = directory.appendingPathComponent(wallet.messageBoxIdentity + "." + payee + ".json")
        let legacy = directory.appendingPathComponent(wallet.messageBoxIdentity + ".json")
        try FileManager.default.moveItem(at: current, to: legacy)

        let restarted = make(directory, transport)
        let pending = try await restarted.pending(for: wallet.sender)
        XCTAssertEqual(pending.map(\.recipient), [payee])
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacy.path))
        await transport.allowDelivery()
        _ = try await restarted.retry(wallet: wallet, recipient: payee)
        let remaining = try await restarted.pending(for: wallet.sender)
        XCTAssertTrue(remaining.isEmpty)
    }

    func test_injectedDiscoverySelectsTheAdvertisedHost() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let payee = try recipient()
        let script = try PushDrop.lockingScript(
            fields: [payee.compressedBytes, Array("https://testnet-box.example/mb".utf8)],
            publicKey: PrivateKey(Array(repeating: 0, count: 31) + [1]).publicKey,
            lockPosition: .beforeCompatibility)
        let transaction = Transaction(version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: script)], lockTime: 0)
        let beef = try BEEF(version: .v2, merklePaths: [], transactions: [.raw(transaction)],
            limits: StorageLimits.beef)
        let item = try OutputListItem(beef: beef.serialized(limits: StorageLimits.beef), outputIndex: 0)
        let discovery = MessageBoxDiscovery(resolver: OutboxAdvertisementResolver(
            answer: try LookupAnswer(outputList: [item])))
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        let outbox = MessageBoxOutbox(directory: directory, discovery: discovery,
            makeClient: { try MessageBoxClient(host: $0, wallet: $1, transport: transport) })
        do {
            _ = try await outbox.send(wallet: wallet, to: payee, satoshis: 10,
                description: "Test PeerPay", fallbackHost: URL(string: "https://fallback.example")!)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.notDelivered {}
        let stored = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(stored.first?.host.absoluteString, "https://testnet-box.example/mb")
    }

    func test_networkInitLooksUpOnThatNetworksTrackers() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let facilitator = OutboxRecordingFacilitator()
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        let outbox = MessageBoxOutbox(directory: directory, network: .testnet, facilitator: facilitator,
            makeClient: { try MessageBoxClient(host: $0, wallet: $1, transport: transport) })
        do {
            _ = try await outbox.send(wallet: wallet, to: try recipient(), satoshis: 10,
                description: "Test PeerPay", fallbackHost: URL(string: "https://fallback.example")!)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.notDelivered {}
        let hosts = await facilitator.hosts
        XCTAssertFalse(hosts.isEmpty)
        XCTAssertEqual(Set(hosts), Set(MessageBoxDiscovery.testnetSLAPTrackers))
        let stored = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(stored.first?.host.host, "fallback.example")
    }

    func test_paidDeliveryIsRefusedBeforeCreatingAnyPayment() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        await transport.requireFee()
        do {
            _ = try await make(directory, transport).send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "No fee consent", fallbackHost: URL(string: "https://original.example")!)
            XCTFail("Fees require separate consent")
        } catch MessageBoxError.deliveryFeeRequired {}
        let creates = await wallet.creates
        XCTAssertEqual(creates, 0)
    }
}
