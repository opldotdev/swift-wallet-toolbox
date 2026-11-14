import XCTest
import Foundation
import BSVCore
import BSVKeys
import BSVOverlay
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxWallet

private actor OutboxTransport: AuthenticatedTransport {
    enum Delivery { case lost, refused, accepted, duplicate }
    var delivery = Delivery.lost
    /// Answers for the next deliveries, in order, before `delivery` applies again.
    var script: [Delivery] = []
    var bodies: [[UInt8]] = []
    var recipientFee = 0
    func allowDelivery() { delivery = .accepted }
    func refuseDelivery() { delivery = .refused }
    func answer(_ delivery: Delivery) { self.delivery = delivery }
    func answerNext(_ deliveries: [Delivery]) { script = deliveries }
    func requireFee() { recipientFee = 5 }
    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        if method == "GET" {
            return AuthenticatedResponse(statusCode: 200, headers: [:],
                body: Array("{\"status\":\"success\",\"quote\":{\"recipientFee\":\(recipientFee),\"deliveryFee\":0}}".utf8))
        }
        bodies.append(body ?? [])
        let answer = script.isEmpty ? delivery : script.removeFirst()
        switch answer {
        case .lost:
            throw URLError(.networkConnectionLost)
        case .refused:
            // What the 1Sat host's account gate sends before its auth runs.
            throw AuthTransportError.unauthenticatedReply(status: 403, body: Array(
                #"{"status":"error","code":"ERR_ACCOUNT_REQUIRED","description":"Recipient has no account on this host"}"#.utf8))
        case .accepted:
            return AuthenticatedResponse(statusCode: 200, headers: [:], body: Array(#"{"status":"success"}"#.utf8))
        case .duplicate:
            // Stock message-box-server, signed, for a message ID it already stores.
            return AuthenticatedResponse(statusCode: 400, headers: [:], body: Array(
                #"{"status":"error","code":"ERR_DUPLICATE_MESSAGE","description":"Duplicate message."}"#.utf8))
        }
    }
}

private actor OutboxWallet: MessageBoxPayingWallet {
    enum Abort: Equatable { case releases, answersFalse, storageRefuses, fails(WireError) }
    nonisolated let messageBoxIdentity: String
    nonisolated let protoWallet: ProtoWallet
    nonisolated let sender: PublicKey
    var creates = 0
    var resumes = 0
    var broadcasts = 0
    var aborts = 0
    var probes = 0
    let loseBroadcastResponse: Bool
    var abort = Abort.releases
    /// What storage says when asked whether it sent the transaction.
    var storageSent = false
    /// What a broadcast of the saved transaction throws, if anything.
    var resumeError: WireError?
    init(loseBroadcastResponse: Bool = false) throws {
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        sender = key.publicKey
        messageBoxIdentity = Hex.encode(key.publicKey.compressedBytes)
        protoWallet = ProtoWallet(rootKey: key)
        self.loseBroadcastResponse = loseBroadcastResponse
    }
    func refuseAborts() { abort = .answersFalse }
    func abortsAre(_ abort: Abort) { self.abort = abort }
    func storageHasSent() { storageSent = true }
    func resumeThrows(_ error: WireError?) { resumeError = error }
    /// As `RemoteWallet.payToCounterparty`: the hook runs before the broadcast, and a hook that
    /// throws aborts the funded action and broadcasts nothing. The hook's error is rethrown once
    /// the abort is confirmed, and `notReleased` otherwise.
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
            guard abort == .releases else { throw BRC29PaymentError.notReleased(reference: payment.reference) }
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
        if let resumeError { throw resumeError }
    }
    func abandonMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws -> Bool {
        XCTAssertEqual(pending.reference, "original-reference")
        switch abort {
        case .releases:
            aborts += 1
            return true
        case .answersFalse:
            return false
        case .storageRefuses:
            throw WireError.invalidParameter(name: "reference",
                message: "an inprocess, outgoing action that has not been signed and shared to the network.")
        case .fails(let error):
            throw error
        }
    }
    func messageBoxPaymentWasSent(_ pending: MessageBoxPendingPayment) async throws -> Bool {
        probes += 1
        return storageSent
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

    /// The delivery went out with no answer and the broadcast's answer was lost. The server may
    /// hold the signed transaction and the recipient may broadcast it, so Discard must not abort
    /// it: Retry broadcasts it first, then delivers.
    func test_anOfferedPaymentIsNeverAbortedAndRetryBroadcastsIt() async throws {
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
        let saved = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(saved.first?.delivery, .offered)
        XCTAssertEqual(saved.first?.broadcastAccepted, false)

        do {
            _ = try await outbox.discard(wallet: wallet, recipient: payee)
            XCTFail("An offered payment must not be aborted")
        } catch MessageBoxOutboxError.offered(let txid) {
            XCTAssertEqual(txid, saved.first?.txid)
        }
        let aborts = await wallet.aborts
        XCTAssertEqual(aborts, 0)
        let listed1 = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(listed1.count, 1)

        // The server stays silent: Retry still puts the payment on chain, and keeps it for delivery.
        do {
            _ = try await outbox.retry(wallet: wallet, recipient: payee)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.notDelivered {}
        var resumes = await wallet.resumes
        XCTAssertEqual(resumes, 1)
        let broadcast = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(broadcast.first?.broadcastAccepted, true)
        XCTAssertEqual(broadcast.first?.delivery, .offered)

        await transport.allowDelivery()
        _ = try await outbox.retry(wallet: wallet, recipient: payee)
        resumes = await wallet.resumes
        XCTAssertEqual(resumes, 1, "a payment storage accepted is not broadcast again")
        let listed2 = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(listed2.isEmpty)
    }

    /// The server took the payment, then the broadcast's answer was lost. Retry broadcasts and
    /// resends the same envelope; stock message-box-server answers ERR_DUPLICATE_MESSAGE for it,
    /// which is delivery, not a refusal.
    func test_retryReadsADuplicateMessageAsDelivered() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet(loseBroadcastResponse: true)
        await transport.allowDelivery()
        let outbox = make(directory, transport)
        let payee = Hex.encode(try recipient().compressedBytes)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Delivered", fallbackHost: host)
            XCTFail("Lost response must be pending")
        } catch MessageBoxOutboxError.notDelivered {}
        do {
            _ = try await outbox.discard(wallet: wallet, recipient: payee)
            XCTFail("A delivered payment must not be aborted")
        } catch MessageBoxOutboxError.offered {}

        await transport.answer(.duplicate)
        let txid = try await outbox.retry(wallet: wallet, recipient: payee)
        XCTAssertFalse(txid.isEmpty)
        let resumes = await wallet.resumes, aborts = await wallet.aborts
        XCTAssertEqual(resumes, 1)
        XCTAssertEqual(aborts, 0)
        let bodies = await transport.bodies
        XCTAssertEqual(bodies.count, 2)
        XCTAssertEqual(Set(bodies).count, 1, "the same envelope, so the same message ID")
        let listed3 = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(listed3.isEmpty)
    }

    func test_aDuplicateMessageIsNotARefusal() {
        let duplicate = MessageBoxError.refused(status: 400, code: "ERR_DUPLICATE_MESSAGE")
        XCTAssertTrue(duplicate.isDuplicate)
        XCTAssertFalse(duplicate.isRefusal)
        XCTAssertFalse(MessageBoxError.refused(status: 400, code: "ERR_INVALID_BODY").isDuplicate)
        XCTAssertFalse(MessageBoxError.recipientAccountRequired.isDuplicate)
    }

    /// A refusal whose abort storage did not confirm keeps the payment, never offered, so Discard
    /// can release its coins: nothing is left reserved without a record.
    func test_aRefusedPaymentWhoseAbortFailedIsKeptForDiscard() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        await transport.refuseDelivery()
        await wallet.refuseAborts()
        let outbox = make(directory, transport)
        let payee = Hex.encode(try recipient().compressedBytes)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Refused", fallbackHost: host)
            XCTFail("A refused delivery must fail the send")
        } catch MessageBoxOutboxError.notReleased(_, let reason) {
            XCTAssertTrue(reason.contains("no account"), reason)
        }
        let broadcasts = await wallet.broadcasts
        XCTAssertEqual(broadcasts, 0)
        let kept = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(kept.first?.delivery, .notOffered)
        XCTAssertEqual(kept.first?.broadcastAccepted, false)

        // Storage still answers no: the payment stays.
        do {
            _ = try await outbox.discard(wallet: wallet, recipient: payee)
            XCTFail("A payment storage will not abort must be kept")
        } catch MessageBoxOutboxError.abortRefused {}
        let listed4 = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(listed4.count, 1)

        // A refused payment is never offered again: storage may already have released it.
        let offers = await transport.bodies.count
        do {
            _ = try await outbox.retry(wallet: wallet, recipient: payee)
            XCTFail("A refused payment must not be retried")
        } catch MessageBoxOutboxError.neverSent(let txid) {
            XCTAssertEqual(txid, kept.first?.txid)
        }
        let resumes = await wallet.resumes, reoffers = await transport.bodies.count
        XCTAssertEqual(resumes, 0, "a refused payment is not broadcast")
        XCTAssertEqual(reoffers, offers, "a refused payment is not offered again")
        let listed5 = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(listed5.first?.delivery, .notOffered)

        await wallet.abortsAre(.releases)
        let outcome = try await outbox.discard(wallet: wallet, recipient: payee)
        XCTAssertEqual(outcome, .released(txid: try XCTUnwrap(kept.first?.txid)))
        let aborts = await wallet.aborts
        XCTAssertEqual(aborts, 1)
        let listed6 = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(listed6.isEmpty)
    }

    /// TS `abortAction` throws for an action it already sent. Discard then asks storage, marks the
    /// payment broadcast, and lets the next Discard forget it.
    func test_aDiscardStorageRefusesFindsThePaymentSentAndOffersToForgetIt() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        await transport.refuseDelivery()
        await wallet.refuseAborts()
        let outbox = make(directory, transport)
        let payee = Hex.encode(try recipient().compressedBytes)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Refused", fallbackHost: host)
            XCTFail("A refused delivery must fail the send")
        } catch MessageBoxOutboxError.notReleased {}
        await wallet.abortsAre(.storageRefuses)
        await wallet.storageHasSent()
        do {
            _ = try await outbox.discard(wallet: wallet, recipient: payee)
            XCTFail("A sent payment's coins do not come back")
        } catch MessageBoxOutboxError.alreadySent {}
        let probes = await wallet.probes
        XCTAssertEqual(probes, 1)
        let marked = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(marked.first?.broadcastAccepted, true)
        let outcome = try await outbox.discard(wallet: wallet, recipient: payee)
        XCTAssertEqual(outcome, .forgotten(txid: try XCTUnwrap(marked.first?.txid)))
        let listed7 = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(listed7.isEmpty)
    }

    /// An abort that went through but whose answer was lost: storage then refuses the abort and
    /// holds nothing as sent, so nothing is reserved and the payment is dropped as released.
    func test_aDiscardStorageRefusesForAnUnsentPaymentReleasesIt() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        await transport.refuseDelivery()
        await wallet.refuseAborts()
        let outbox = make(directory, transport)
        let payee = Hex.encode(try recipient().compressedBytes)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Refused", fallbackHost: host)
            XCTFail("A refused delivery must fail the send")
        } catch MessageBoxOutboxError.notReleased {}
        await wallet.abortsAre(.storageRefuses)
        let outcome = try await outbox.discard(wallet: wallet, recipient: payee)
        guard case .released = outcome else { return XCTFail("\(outcome)") }
        let listed8 = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(listed8.isEmpty)
    }

    /// Only the one error TS `findAbortableTransaction` throws for a sent, failed or unknown action
    /// counts as storage having let go. Any other storage error decided nothing, so the payment
    /// and its reservation are kept for another Discard.
    func test_aTransientAbortFailureKeepsThePayment() async throws {
        for transient in [WireError.internalFailure("database busy"), .notActive("not the active store"),
                          .unauthorized("session"), .invalidParameter(name: "auth.userId", message: "valid")] {
            let directory = directory()
            defer { try? FileManager.default.removeItem(at: directory) }
            let transport = OutboxTransport(), wallet = try OutboxWallet()
            await transport.refuseDelivery()
            await wallet.refuseAborts()
            let outbox = make(directory, transport)
            let payee = Hex.encode(try recipient().compressedBytes)
            do {
                _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                    description: "Refused", fallbackHost: host)
                XCTFail("A refused delivery must fail the send")
            } catch MessageBoxOutboxError.notReleased {}
            await wallet.abortsAre(.fails(transient))
            do {
                _ = try await outbox.discard(wallet: wallet, recipient: payee)
                XCTFail("\(transient) must not release the payment")
            } catch let error as WireError {
                XCTAssertEqual(error, transient)
            }
            let kept = try await outbox.pending(for: wallet.sender)
            XCTAssertEqual(kept.count, 1, "\(transient)")
            XCTAssertEqual(kept.first?.delivery, .notOffered)
            await wallet.abortsAre(.releases)
            let outcome = try await outbox.discard(wallet: wallet, recipient: payee)
            guard case .released = outcome else { return XCTFail("\(outcome)") }
        }
    }

    /// Storage failed an offered payment's unsigned action (it expired as abandoned), so its
    /// broadcast is refused for good. The payment is marked so instead of blocking the recipient
    /// forever, and Discard forgets it without an abort.
    func test_aBroadcastStorageRefusesForGoodLetsDiscardForgetIt() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet(loseBroadcastResponse: true)
        let outbox = make(directory, transport)
        let payee = Hex.encode(try recipient().compressedBytes)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Expired", fallbackHost: host)
            XCTFail("Lost response must be pending")
        } catch MessageBoxOutboxError.notDelivered {}

        // A storage error that decides nothing leaves it offered, for another Retry.
        await wallet.resumeThrows(.internalFailure("database busy"))
        do {
            _ = try await outbox.retry(wallet: wallet, recipient: payee)
            XCTFail("A failed broadcast must fail the retry")
        } catch MessageBoxOutboxError.notDelivered {}
        let stillOffered = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(stillOffered.first?.broadcastRefused, false)
        do {
            _ = try await outbox.discard(wallet: wallet, recipient: payee)
            XCTFail("An offered payment must not be dropped")
        } catch MessageBoxOutboxError.offered {}

        await wallet.resumeThrows(.invalidOperation("invalid transaction status failed"))
        do {
            _ = try await outbox.retry(wallet: wallet, recipient: payee)
            XCTFail("A failed action cannot be broadcast")
        } catch MessageBoxOutboxError.broadcastRefused(let txid) {
            XCTAssertEqual(txid, stillOffered.first?.txid)
        }
        let marked = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(marked.first?.broadcastRefused, true)
        XCTAssertEqual(marked.first?.broadcastAccepted, false)

        let resumesBefore = await wallet.resumes
        do {
            _ = try await outbox.retry(wallet: wallet, recipient: payee)
            XCTFail("A failed action is not retried")
        } catch MessageBoxOutboxError.broadcastRefused {}
        let resumesAfter = await wallet.resumes
        XCTAssertEqual(resumesAfter, resumesBefore, "storage is not asked again")

        let outcome = try await outbox.discard(wallet: wallet, recipient: payee)
        XCTAssertEqual(outcome, .abandoned(txid: try XCTUnwrap(marked.first?.txid)))
        let aborts = await wallet.aborts
        XCTAssertEqual(aborts, 0, "a failed action is not aborted")
        let left = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(left.isEmpty)
    }

    func test_onlyAFailedActionCountsAsAFinalBroadcastRefusal() {
        XCTAssertTrue(MessageBoxOutbox.isFailedAction(WireError.invalidOperation("invalid transaction status failed")))
        XCTAssertFalse(MessageBoxOutbox.isFailedAction(WireError.invalidOperation("invalid transaction status nosend")))
        XCTAssertFalse(MessageBoxOutbox.isFailedAction(WireError.internalFailure("invalid transaction status failed")))
        XCTAssertFalse(MessageBoxOutbox.isFailedAction(URLError(.timedOut)))
    }

    /// A payment saved before delivery was tracked might have been offered, so it is never aborted.
    func test_aRecordWithoutDeliveryStateIsTreatedAsOffered() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet(loseBroadcastResponse: true)
        let outbox = make(directory, transport)
        let payee = Hex.encode(try recipient().compressedBytes)
        await transport.refuseDelivery()
        await wallet.refuseAborts()
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Old", fallbackHost: host)
            XCTFail("A refused delivery must fail the send")
        } catch MessageBoxOutboxError.notReleased {}
        let url = directory.appendingPathComponent(wallet.messageBoxIdentity + "." + payee + ".json")
        var object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        XCTAssertEqual(object.removeValue(forKey: "delivery") as? String, "not-offered")
        try JSONSerialization.data(withJSONObject: object).write(to: url)
        let listed9 = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(listed9.first?.delivery, .offered)
        await wallet.abortsAre(.releases)
        do {
            _ = try await outbox.discard(wallet: wallet, recipient: payee)
            XCTFail("A payment that may have been offered must not be aborted")
        } catch MessageBoxOutboxError.offered {}
        let aborts = await wallet.aborts
        XCTAssertEqual(aborts, 0)
    }

    /// An unreadable record from the one-file-per-sender layout is set aside, not left to fail
    /// every send, retry and listing from that sender.
    func test_anUnreadableOldRecordIsSetAside() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let legacy = directory.appendingPathComponent(wallet.messageBoxIdentity + ".json")
        try Data("{not json".utf8).write(to: legacy)
        let outbox = make(directory, transport)
        let listed10 = try await outbox.pending(for: wallet.sender)
        XCTAssertTrue(listed10.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacy.path))
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        XCTAssertEqual(names.filter { $0.hasPrefix(wallet.messageBoxIdentity + ".json.unreadable-") }.count, 1,
            "the bytes are kept on disk")
        await transport.allowDelivery()
        let txid = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
            description: "After", fallbackHost: host)
        XCTAssertFalse(txid.isEmpty)
    }

    func test_anOldRecordForARecipientWithASavedPaymentIsSetAside() async throws {
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
        let current = directory.appendingPathComponent(wallet.messageBoxIdentity + "." + payee + ".json")
        let legacy = directory.appendingPathComponent(wallet.messageBoxIdentity + ".json")
        try FileManager.default.copyItem(at: current, to: legacy)
        let pending = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(pending.map(\.recipient), [payee])
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacy.path))
    }

    /// A stray file that only looks like a saved payment does not hide the real ones.
    func test_aStrayFileDoesNotFailTheListing() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        let outbox = make(directory, transport)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Stuck", fallbackHost: host)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.notDelivered {}
        try Data("{}".utf8).write(to: directory.appendingPathComponent(wallet.messageBoxIdentity + ".backup.json"))
        try Data("{}".utf8).write(to: directory.appendingPathComponent(wallet.messageBoxIdentity + ".json.unreadable-x"))
        let pending = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(pending.map(\.recipient), [Hex.encode(try recipient().compressedBytes)])
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
