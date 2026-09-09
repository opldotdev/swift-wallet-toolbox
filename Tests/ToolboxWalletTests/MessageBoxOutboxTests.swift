import XCTest
import Foundation
import BSVCore
import BSVKeys
import BSVWallet
import ToolboxAuth
import ToolboxStorage
@testable import ToolboxWallet

private actor OutboxTransport: AuthenticatedTransport {
    var failDelivery = true
    var bodies: [[UInt8]] = []
    var recipientFee = 0
    func allowDelivery() { failDelivery = false }
    func requireFee() { recipientFee = 5 }
    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        if method == "GET" {
            return AuthenticatedResponse(statusCode: 200, headers: [:],
                body: Array("{\"status\":\"success\",\"quote\":{\"recipientFee\":\(recipientFee),\"deliveryFee\":0}}".utf8))
        }
        bodies.append(body ?? [])
        if failDelivery { throw URLError(.networkConnectionLost) }
        return AuthenticatedResponse(statusCode: 200, headers: [:], body: Array(#"{"status":"success"}"#.utf8))
    }
}

private actor OutboxWallet: MessageBoxPayingWallet {
    nonisolated let messageBoxIdentity: String
    nonisolated let protoWallet: ProtoWallet
    nonisolated let sender: PublicKey
    var creates = 0
    var resumes = 0
    let loseBroadcastResponse: Bool
    init(loseBroadcastResponse: Bool = false) throws {
        let key = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        sender = key.publicKey
        messageBoxIdentity = Hex.encode(key.publicKey.compressedBytes)
        protoWallet = ProtoWallet(rootKey: key)
        self.loseBroadcastResponse = loseBroadcastResponse
    }
    func createMessageBoxPayment(recipient: PublicKey, satoshis: UInt64,
        derivationPrefix: String, derivationSuffix: String, description: String,
        beforeBroadcast: @escaping @Sendable (CounterpartyPayment) async throws -> Void) async throws -> CounterpartyPayment {
        creates += 1
        let id = try TransactionID(displayHex: String(repeating: "ab", count: 32))
        let payment = CounterpartyPayment(transactionID: id, outputIndex: 2,
            atomicBEEF: [1, 1, 1, 1], reference: "original-reference",
            results: [SendWithResult(txid: id.displayHex, status: .unproven)])
        try await beforeBroadcast(payment)
        if loseBroadcastResponse { throw URLError(.networkConnectionLost) }
        return payment
    }
    func resumeMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws {
        resumes += 1
        XCTAssertEqual(pending.reference, "original-reference")
        XCTAssertEqual(pending.atomicBEEF, [1, 1, 1, 1])
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

    func test_failedDeliverySurvivesRestartAndRetryNeverCreatesAnotherPayment() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet()
        let outbox = make(directory, transport)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Test PeerPay", fallbackHost: URL(string: "https://original.example")!)
            XCTFail("Delivery must fail")
        } catch MessageBoxOutboxError.pending {}
        let stored = try await outbox.pending(for: wallet.sender)
        XCTAssertEqual(stored?.amount, 10)
        XCTAssertEqual(stored?.host.host, "original.example")
        // A new Send request with any amount or host cannot overwrite the original.
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 20,
                description: "Do not double spend", fallbackHost: URL(string: "https://changed.example")!)
            XCTFail("A pending payment must block a new one")
        } catch MessageBoxOutboxError.pending {}
        await transport.allowDelivery()
        let restarted = make(directory, transport)
        let id = try await restarted.retry(wallet: wallet)
        XCTAssertEqual(id, stored?.txid)
        let creates = await wallet.creates, resumes = await wallet.resumes
        XCTAssertEqual(creates, 1)
        XCTAssertEqual(resumes, 0)
        let bodies = await transport.bodies
        XCTAssertEqual(bodies.count, 2)
        XCTAssertEqual(bodies[0], bodies[1])
        let remaining = try await restarted.pending(for: wallet.sender)
        XCTAssertNil(remaining)
    }

    func test_lostBroadcastResponsePersistsBeforeBroadcastAndResumesSameTransaction() async throws {
        let directory = directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = OutboxTransport(), wallet = try OutboxWallet(loseBroadcastResponse: true)
        let outbox = make(directory, transport)
        do {
            _ = try await outbox.send(wallet: wallet, to: recipient(), satoshis: 10,
                description: "Test PeerPay", fallbackHost: URL(string: "https://original.example")!)
            XCTFail("Lost response must be pending")
        } catch MessageBoxOutboxError.pending {}
        let pending = try await outbox.pending(for: wallet.sender)
        XCTAssertNotNil(pending)
        XCTAssertEqual(pending?.broadcastAccepted, false)
        let sentBefore = await transport.bodies.count
        XCTAssertEqual(sentBefore, 0)
        await transport.allowDelivery()
        _ = try await make(directory, transport).retry(wallet: wallet)
        let creates = await wallet.creates, resumes = await wallet.resumes
        XCTAssertEqual(creates, 1)
        XCTAssertEqual(resumes, 1)
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
