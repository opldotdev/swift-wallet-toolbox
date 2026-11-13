import XCTest
import Foundation
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxBRC29
import ToolboxCore
import ToolboxStorage
@testable import ToolboxWallet

/// The order things happen in, across the wallet and the server.
private actor EventLog {
    var events: [String] = []
    var internalized: [WalletInternalizeActionRequest] = []
    func add(_ event: String) { events.append(event) }
    func keep(_ request: WalletInternalizeActionRequest) { internalized.append(request) }
}

/// Replies with queued responses in order and logs each endpoint. With `holdFirst`, the first
/// request waits until `release()`.
private actor LoggingTransport: AuthenticatedTransport {
    let log: EventLog
    var responses: [AuthenticatedResponse]
    var requests: [(path: String, body: [UInt8]?)] = []
    var holdFirst: Bool
    var held: CheckedContinuation<Void, Never>?

    init(log: EventLog, _ responses: [(status: Int, body: String)], holdFirst: Bool = false) {
        self.log = log
        self.responses = responses.map { AuthenticatedResponse(statusCode: $0.status, headers: [:], body: Array($0.body.utf8)) }
        self.holdFirst = holdFirst
    }

    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        requests.append((path, body))
        await log.add(String(path.split(separator: "/").last ?? ""))
        if holdFirst {
            holdFirst = false
            await withCheckedContinuation { held = $0 }
        }
        guard !responses.isEmpty else { throw URLError(.badServerResponse) }
        return responses.removeFirst()
    }

    func isHolding() -> Bool { held != nil }
    func release() { held?.resume(); held = nil }
}

/// Derives keys with a real wallet and records what it is asked to internalize.
private struct StubReceiver: MessageBoxReceivingWallet {
    enum Outcome: Sendable { case accepted, refused, fails }
    let keys: ProtoWallet
    let log: EventLog
    var outcome: Outcome = .accepted

    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult {
        await log.add("getPublicKey")
        return try await keys.getPublicKey(request)
    }

    func internalizeAction(_ request: WalletInternalizeActionRequest) async throws -> WalletInternalizeActionResult {
        await log.add("internalizeAction")
        await log.keep(request)
        switch outcome {
        case .accepted: return WalletInternalizeActionResult(accepted: true)
        case .refused: return WalletInternalizeActionResult(accepted: false)
        case .fails: throw URLError(.cannotConnectToHost)
        }
    }
}

/// A token decode vector produced by the TS `paymentFromMessage` (live ts-stack source), fed the
/// stored text after the client's one `tryParse`, as `listMessages` does.
private struct Vector: Decodable {
    struct Expected: Decodable {
        let messageId: String
        let sender: String
        let token: MessageBoxPaymentToken
    }
    let name: String
    let stored: String
    let messageId: String
    let sender: String
    let expected: Expected?
}

final class IncomingPaymentsTests: XCTestCase, @unchecked Sendable {
    private let host = URL(string: "https://mb.example")!
    private let prefix = "cHJlZml4", suffix = "c3VmZml4"

    private func key(_ value: UInt8) throws -> PrivateKey { try PrivateKey(Array(repeating: 0, count: 31) + [value]) }
    private func hex(_ key: PrivateKey) -> String { Hex.encode(key.publicKey.compressedBytes) }
    private func json(_ bytes: [UInt8]?) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(XCTUnwrap(bytes))) as? [String: Any])
    }
    private func listing(_ rows: [Any], hasMore: Bool = false) throws -> String {
        var object: [String: Any] = ["status": "success", "messages": rows]
        if hasMore { object["hasMore"] = true }
        return String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]), as: UTF8.self)
    }

    /// Atomic BEEF of a transaction whose one output pays `satoshis` to the BRC-29 key `sender`
    /// derives for `recipient`.
    private func paymentTransaction(to recipient: PublicKey, from sender: PrivateKey, satoshis: UInt64 = 1_000) throws -> [UInt8] {
        let paying = try BRC29.payingPublicKey(recipient: recipient, sender: sender, prefix: prefix, suffix: suffix)
        let output = TransactionOutput(satoshis: satoshis, lockingScript: try BRC29.lockingScript(for: paying))
        let tx = Transaction(version: 1, inputs: [], outputs: [output], lockTime: 0)
        let beef = try BEEF(merklePaths: [], transactions: [.raw(tx)], limits: StorageLimits.beef)
        let id = try tx.transactionID(limits: StorageLimits.transaction)
        return try AtomicBEEF(subjectTransactionID: id, beef: beef, limits: StorageLimits.beef).serialized(limits: StorageLimits.beef)
    }

    /// The stored body a TS sender's `sendPayment` leaves: the token, encrypted.
    private func encryptedBody(_ token: MessageBoxPaymentToken, from sender: PrivateKey, to recipient: PublicKey) async throws -> String {
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: sender),
            transport: LoggingTransport(log: EventLog(), []))
        return try await client.preparePayment(to: recipient, token: token).body
    }

    private func encryptedText(_ text: String, from sender: PrivateKey, to recipient: PublicKey) async throws -> String {
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: sender),
            transport: LoggingTransport(log: EventLog(), []))
        return try await client.prepareMessage(to: recipient, messageBox: MessageBoxClient.paymentInbox, body: text).body
    }

    // MARK: - Token decoding

    func test_tokenDecodingMatchesTheTypeScriptVectors() throws {
        let vectors = try JSONDecoder().decode([Vector].self, from: Data(Self.vectors.utf8))
        XCTAssertEqual(vectors.count, 40)
        XCTAssertEqual(vectors.filter { $0.expected != nil }.count, 10)
        for vector in vectors {
            let decoded = MessageBoxIncomingPayment.decode(messageId: vector.messageId, sender: vector.sender, plaintext: vector.stored)
            let expected = vector.expected.map {
                MessageBoxIncomingPayment(messageId: $0.messageId, sender: $0.sender, token: $0.token)
            }
            XCTAssertEqual(decoded, expected, vector.name)
        }
    }

    // MARK: - Listing

    func test_listingUnwrapsStoredEnvelopes() async throws {
        let sender = hex(try key(3))
        let rows: [[String: Any]] = [
            ["messageId": "a", "sender": sender, "body": #"{"message":"hello","payment":{"outputs":[],"tx":[1,2]}}"#],
            ["messageId": "b", "sender": sender, "body": ["message": ["encryptedMessage": "AAAA"]]],
            ["messageId": "c", "sender": sender, "body": #"{"message":null,"x":1}"#],
            ["messageId": "d", "sender": sender, "body": #"{"message":"m","payment":null}"#],
            ["messageId": "e", "sender": sender, "body": #"{"x":1}"#],
        ]
        let transport = LoggingTransport(log: EventLog(), [(200, try listing(rows))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let messages = try await client.listMessages(messageBox: MessageBoxClient.paymentInbox).messages
        XCTAssertEqual(messages.map(\.body), [
            "hello", #"{"encryptedMessage":"AAAA"}"#, #"{"message":null,"x":1}"#, "m", #"{"x":1}"#,
        ])
        XCTAssertEqual(messages[0].payment, .object(["outputs": .array([]), "tx": .array([1, 2])]))
        XCTAssertEqual(messages.dropFirst().map(\.payment), [nil, nil, nil, nil])
    }

    func test_anEnvelopePaymentThatIsNotAnObjectMakesTheMessageUnreadable() async throws {
        let sender = hex(try key(3))
        let body = #"{"message":"m","payment":[1]}"#
        let strict = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)),
            transport: LoggingTransport(log: EventLog(), [(200, try listing([["messageId": "a", "sender": sender, "body": body]]))]))
        do { _ = try await strict.listMessages(messageBox: MessageBoxClient.paymentInbox); XCTFail("must not drop the payment") }
        catch MessageBoxError.invalidResponse {}

        let lenient = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)),
            transport: LoggingTransport(log: EventLog(), [(200, try listing([["messageId": "a", "sender": sender, "body": body]]))]))
        let payments = try await lenient.incomingPayments()
        XCTAssertEqual(payments, MessageBoxPaymentListing(payments: [], truncated: false))
    }

    func test_incomingPaymentsReadPlainAndWrappedBodiesAndSkipTheRest() async throws {
        let receiver = try key(1), sender = try key(2), other = try key(4)
        let token = MessageBoxPaymentToken(derivationPrefix: prefix, derivationSuffix: suffix,
            transaction: [1, 1, 1, 1, 222, 173], amount: 1_000, outputIndex: 0)
        let encrypted = try await encryptedBody(token, from: sender, to: receiver.publicKey)
        let plain = String(decoding: try JSONEncoder().encode(token), as: UTF8.self)
        let claimsOther = try await encryptedText(
            #"{"amount":1000,"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"sender":"\#(hex(other))","transaction":[1]}"#,
            from: sender, to: receiver.publicKey)
        let rows: [Any] = [
            ["messageId": "p1", "sender": hex(sender), "body": encrypted],
            ["messageId": "p2", "sender": hex(sender),
             "body": ["message": encrypted, "payment": ["tx": [1]]] as [String: Any]] as [String: Any],
            ["messageId": "bad1", "sender": hex(sender), "body": "hello"],
            ["messageId": "bad2", "sender": hex(sender), "body": 7] as [String: Any],
            ["messageId": "bad3", "sender": "zz", "body": encrypted],
            ["messageId": "bad4", "sender": hex(sender), "body": claimsOther],
            ["messageId": "bad5", "sender": hex(sender), "body": #"{"encryptedMessage":"AAAA"}"#],
            ["messageId": "bad6", "sender": hex(other), "body": encrypted],
            "not a row",
            ["messageId": "p1", "sender": hex(sender), "body": plain],
            ["messageId": "p3", "sender": hex(sender), "body": plain],
        ]
        let transport = LoggingTransport(log: EventLog(), [(200, try listing(rows))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: receiver), transport: transport)
        let listed = try await client.incomingPayments()
        XCTAssertFalse(listed.truncated)
        let payments = listed.payments
        XCTAssertEqual(payments.map(\.messageId), ["p1", "p2", "p3"])
        XCTAssertEqual(payments.map(\.sender), Array(repeating: hex(sender), count: 3))
        XCTAssertEqual(payments.map(\.token), [token, token, token])

        let requests = await transport.requests
        XCTAssertEqual(requests.map(\.path), ["/listMessages"])
        let request = try json(requests[0].body)
        XCTAssertEqual(request["messageBox"] as? String, "payment_inbox")
        XCTAssertEqual(request["offset"] as? Int, 0)
        XCTAssertEqual(request["limit"] as? Int, 100)
        XCTAssertNil(request["messageId"])
    }

    func test_incomingPaymentsStopAtOneThousandMessages() async throws {
        let sender = try key(2)
        let plain = String(decoding: try JSONEncoder().encode(MessageBoxPaymentToken(derivationPrefix: prefix,
            derivationSuffix: suffix, transaction: [1], amount: 5, outputIndex: 0)), as: UTF8.self)
        // A server that ignores the page size and returns everything at once.
        let rows: [[String: Any]] = (0..<1_001).map { ["messageId": "m\($0)", "sender": hex(sender), "body": plain] }
        let transport = LoggingTransport(log: EventLog(), [(200, try listing(rows))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listed = try await client.incomingPayments()
        XCTAssertEqual(listed.payments.count, 1_000)
        XCTAssertEqual(listed.payments.last?.messageId, "m999")
        // The row the limit cut is still on the server.
        XCTAssertTrue(listed.truncated)
    }

    func test_incomingPaymentsStopAtTenPagesAsTruncated() async throws {
        let page = try listing([], hasMore: true)
        let transport = LoggingTransport(log: EventLog(), Array(repeating: (status: 200, body: page), count: 10))
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listed = try await client.incomingPayments()
        XCTAssertEqual(listed, MessageBoxPaymentListing(payments: [], truncated: true))
        let count = await transport.requests.count
        XCTAssertEqual(count, 10)
    }

    func test_exactlyOneThousandMessagesWithMoreToComeReturnThePaymentsAsTruncated() async throws {
        let sender = try key(2)
        let plain = String(decoding: try JSONEncoder().encode(MessageBoxPaymentToken(derivationPrefix: prefix,
            derivationSuffix: suffix, transaction: [1], amount: 5, outputIndex: 0)), as: UTF8.self)
        // Ten full pages of 100, each opening with a row that cannot be read, and the server
        // still has more. Junk that is never acknowledged must not hide the payments behind it.
        let pages: [(status: Int, body: String)] = try (0..<10).map { page -> (status: Int, body: String) in
            var rows: [Any] = ["junk \(page)"]
            for index in 1..<100 {
                rows.append(["messageId": "m\(page * 100 + index)", "sender": hex(sender), "body": plain])
            }
            return (200, try listing(rows, hasMore: true))
        }
        let transport = LoggingTransport(log: EventLog(), pages)
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listed = try await client.incomingPayments()
        XCTAssertTrue(listed.truncated)
        XCTAssertEqual(listed.payments.count, 990)
        XCTAssertEqual(listed.payments.first?.messageId, "m1")
        XCTAssertEqual(listed.payments.last?.messageId, "m999")
        let requests = await transport.requests
        XCTAssertEqual(requests.count, 10)
        let offsets = try requests.map { try json($0.body)["offset"] as? Int }
        XCTAssertEqual(offsets, (0..<10).map { Optional($0 * 100) })
        let limits = try requests.map { try json($0.body)["limit"] as? Int }
        XCTAssertEqual(limits, Array(repeating: Optional(100), count: 10))
    }

    func test_incomingPaymentsUnderTheLimitAreNotTruncated() async throws {
        let sender = try key(2)
        let plain = String(decoding: try JSONEncoder().encode(MessageBoxPaymentToken(derivationPrefix: prefix,
            derivationSuffix: suffix, transaction: [1], amount: 5, outputIndex: 0)), as: UTF8.self)
        let first: [[String: Any]] = (0..<100).map { ["messageId": "a\($0)", "sender": hex(sender), "body": plain] }
        let last: [[String: Any]] = (0..<99).map { ["messageId": "b\($0)", "sender": hex(sender), "body": plain] }
        let transport = LoggingTransport(log: EventLog(), [(200, try listing(first, hasMore: true)), (200, try listing(last))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listed = try await client.incomingPayments()
        XCTAssertFalse(listed.truncated)
        XCTAssertEqual(listed.payments.count, 199)
        let count = await transport.requests.count
        XCTAssertEqual(count, 2)
    }

    // MARK: - Accepting

    private struct Fixture {
        let receiver: PrivateKey
        let sender: PrivateKey
        let token: MessageBoxPaymentToken
        let payment: MessageBoxIncomingPayment
        let row: [String: Any]
    }

    /// `envelope` is stored as the message's `{"message", "payment"}` envelope payment.
    private func fixture(satoshis: UInt64 = 1_000, claimed: UInt64 = 1_000, outputIndex: Int = 0,
                         payTo: PublicKey? = nil, envelope: Any? = nil) async throws -> Fixture {
        let receiver = try key(1), sender = try key(2)
        let transaction = try paymentTransaction(to: payTo ?? receiver.publicKey, from: sender, satoshis: satoshis)
        let token = MessageBoxPaymentToken(derivationPrefix: prefix, derivationSuffix: suffix,
            transaction: transaction, amount: claimed, outputIndex: outputIndex)
        let body = try await encryptedBody(token, from: sender, to: receiver.publicKey)
        let stored: Any
        if let envelope {
            stored = ["message": body, "payment": envelope] as [String: Any]
        } else {
            stored = body
        }
        return Fixture(receiver: receiver, sender: sender, token: token,
            payment: MessageBoxIncomingPayment(messageId: "p1", sender: hex(sender), token: token),
            row: ["messageId": "p1", "sender": hex(sender), "body": stored])
    }

    /// A MessageBox recipient payment as a TS sender puts it in the envelope: one wallet-payment
    /// output to the recipient and one basket insertion that is not the recipient's to claim.
    private func recipientPayment(remittance: Bool = true, extra: [String: Any] = [:]) throws -> [String: Any] {
        let sender = try key(2), receiver = try key(1)
        let tx = try paymentTransaction(to: receiver.publicKey, from: sender, satoshis: 10)
        var walletOutput: [String: Any] = ["outputIndex": 0, "protocol": "wallet payment"]
        if remittance {
            walletOutput["paymentRemittance"] = [
                "derivationPrefix": prefix, "derivationSuffix": suffix, "senderIdentityKey": hex(sender),
            ]
        }
        var payment: [String: Any] = [
            "tx": tx.map { Int($0) },
            "outputs": [walletOutput, ["outputIndex": 1, "protocol": "basket insertion",
                                       "insertionRemittance": ["basket": "fees"]] as [String: Any]],
        ]
        payment.merge(extra) { $1 }
        return payment
    }

    func test_acceptInternalizesBeforeAcknowledging() async throws {
        let f = try await fixture()
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let result = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))

        XCTAssertTrue(result.acknowledged)
        XCTAssertFalse(result.recipientPaymentInternalized)
        XCTAssertEqual(result.payment, f.payment)
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "acknowledgeMessage"])

        let requests = await transport.requests
        let lookup = try json(requests[0].body)
        XCTAssertEqual(lookup["messageBox"] as? String, "payment_inbox")
        XCTAssertEqual(lookup["messageId"] as? String, "p1")
        XCTAssertEqual(lookup["offset"] as? Int, 0)
        XCTAssertEqual(lookup["limit"] as? Int, 2)
        XCTAssertEqual(try json(requests[1].body)["messageIds"] as? [String], ["p1"])

        let internalized = await log.internalized
        let request = try XCTUnwrap(internalized.first)
        XCTAssertEqual(request.description, "BRC-29 payment received")
        XCTAssertEqual(request.labels, ["peerpay"])
        XCTAssertEqual(try request.transaction.serialized(limits: StorageLimits.beef), f.token.transaction)
        XCTAssertEqual(request.outputs.count, 1)
        XCTAssertEqual(request.outputs.first?.outputIndex, 0)
        guard case .walletPayment(let remittance)? = request.outputs.first?.remittance else {
            return XCTFail("a BRC-29 wallet payment")
        }
        XCTAssertEqual(remittance.senderIdentityKey, f.sender.publicKey)
        XCTAssertEqual(remittance.derivationPrefix.base64, prefix)
        XCTAssertEqual(remittance.derivationSuffix.base64, suffix)
    }

    func test_anEnvelopePaymentIsInternalizedBeforeTheMessageIsAcknowledged() async throws {
        let envelope = try recipientPayment()
        let f = try await fixture(envelope: envelope)
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let result = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))

        XCTAssertTrue(result.recipientPaymentInternalized)
        XCTAssertTrue(result.acknowledged)
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "internalizeAction", "getPublicKey", "internalizeAction", "acknowledgeMessage"])

        let internalized = await log.internalized
        XCTAssertEqual(internalized.count, 2)
        let fee = try XCTUnwrap(internalized.first)
        XCTAssertEqual(fee.description, "MessageBox recipient payment")
        XCTAssertEqual(fee.labels, [])
        XCTAssertEqual(try fee.transaction.serialized(limits: StorageLimits.beef).map { Int($0) }, envelope["tx"] as? [Int])
        // Only the wallet-payment output is claimed, as TS `snapshotIncomingPayment` filters.
        XCTAssertEqual(fee.outputs.map(\.outputIndex), [0])
        guard case .walletPayment(let remittance)? = fee.outputs.first?.remittance else {
            return XCTFail("a wallet payment")
        }
        XCTAssertEqual(remittance.senderIdentityKey, f.sender.publicKey)
        XCTAssertEqual(remittance.derivationPrefix.base64, prefix)
        XCTAssertEqual(internalized.last?.labels, ["peerpay"])
    }

    func test_anEnvelopePaymentTheWalletDoesNotTakeLeavesTheMessageUnacknowledged() async throws {
        let f = try await fixture(envelope: try recipientPayment())
        for outcome in [StubReceiver.Outcome.refused, .fails] {
            let log = EventLog()
            let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
            let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
            do {
                _ = try await client.accept(f.payment,
                    receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log, outcome: outcome))
                XCTFail("\(outcome) must not be acknowledged")
            } catch MessageBoxPaymentError.recipientPaymentFailed {}
            let events = await log.events
            XCTAssertEqual(events, ["listMessages", "internalizeAction"])
        }
    }

    func test_anUnreadableEnvelopePaymentLeavesTheMessageUnacknowledged() async throws {
        let unreadable: [[String: Any]] = [
            try recipientPayment(remittance: false),
            try recipientPayment(extra: ["tx": [Int]()]),
            try recipientPayment(extra: ["tx": [1, 256]]),
            try recipientPayment(extra: ["outputs": "none"]),
            try recipientPayment(extra: ["outputs": [["outputIndex": -1, "protocol": "wallet payment"] as [String: Any]]]),
            try recipientPayment(extra: ["outputs": [7]]),
            try recipientPayment(extra: ["description": "fee\u{1}"]),
            try recipientPayment(extra: ["description": String(repeating: "d", count: 51)]),
        ]
        for envelope in unreadable {
            let f = try await fixture(envelope: envelope)
            let log = EventLog()
            let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
            let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
            do {
                _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
                XCTFail("must not be acknowledged")
            } catch MessageBoxPaymentError.recipientPaymentFailed {}
            let events = await log.events
            XCTAssertEqual(events, ["listMessages"])
        }

        // A payment that is not an object makes the message unreadable, so it is not found.
        let f = try await fixture(envelope: [1])
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row]))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        do {
            _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
            XCTFail("must not be acknowledged")
        } catch MessageBoxPaymentError.notInInbox {}
        let events = await log.events
        XCTAssertEqual(events, ["listMessages"])
    }

    func test_anEnvelopePaymentWithNoWalletOutputsInternalizesNothing() async throws {
        // TS reports `no-wallet-outputs` and internalizes nothing; the token is still accepted.
        let envelope = try recipientPayment(extra: ["outputs": [["outputIndex": 0, "protocol": "basket insertion"] as [String: Any]]])
        let f = try await fixture(envelope: envelope)
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let result = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
        XCTAssertFalse(result.recipientPaymentInternalized)
        XCTAssertTrue(result.acknowledged)
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "acknowledgeMessage"])
    }

    // MARK: - Envelope payments on other messages

    /// Lists one `inbox` row whose stored body is `body` and returns the message and the client,
    /// with a response queued for the caller's own acknowledge.
    private func listedMessage(body: Any, log: EventLog) async throws -> (MessageBoxMessage, MessageBoxClient) {
        let row: [String: Any] = ["messageId": "m1", "sender": hex(try key(2)), "body": body]
        let transport = LoggingTransport(log: log, [(200, try listing([row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let messages = try await client.listMessages(messageBox: "inbox").messages
        XCTAssertEqual(messages.count, 1)
        return (try XCTUnwrap(messages.first), client)
    }

    func test_anEnvelopePaymentIsInternalizedAndTheCallerAcknowledgesAfter() async throws {
        let envelope = try recipientPayment()
        let log = EventLog()
        let (message, client) = try await listedMessage(body: ["message": "paymail", "payment": envelope] as [String: Any], log: log)
        XCTAssertEqual(message.body, "paymail")
        let receiver = StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log)

        let internalized = try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
        XCTAssertTrue(internalized)
        // The step itself never acknowledges; the caller does, last.
        var events = await log.events
        XCTAssertEqual(events, ["listMessages", "internalizeAction"])
        try await client.acknowledge(messageIds: [message.messageId])
        events = await log.events
        XCTAssertEqual(events, ["listMessages", "internalizeAction", "acknowledgeMessage"])

        let requests = await log.internalized
        XCTAssertEqual(requests.count, 1)
        let fee = try XCTUnwrap(requests.first)
        XCTAssertEqual(fee.description, "MessageBox recipient payment")
        XCTAssertEqual(try fee.transaction.serialized(limits: StorageLimits.beef).map { Int($0) }, envelope["tx"] as? [Int])
        XCTAssertEqual(fee.outputs.map(\.outputIndex), [0])
    }

    func test_aFailedEnvelopePaymentLeavesTheMessageUnacknowledged() async throws {
        let cases: [(envelope: [String: Any], outcome: StubReceiver.Outcome, events: [String])] = [
            (try recipientPayment(), .refused, ["listMessages", "internalizeAction"]),
            (try recipientPayment(), .fails, ["listMessages", "internalizeAction"]),
            (try recipientPayment(remittance: false), .accepted, ["listMessages"]),
        ]
        for test in cases {
            let log = EventLog()
            let (message, client) = try await listedMessage(
                body: ["message": "paymail", "payment": test.envelope] as [String: Any], log: log)
            let receiver = StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log, outcome: test.outcome)
            do {
                try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
                try await client.acknowledge(messageIds: [message.messageId])
                XCTFail("\(test.outcome) must not be acknowledged")
            } catch MessageBoxPaymentError.recipientPaymentFailed {}
            let events = await log.events
            XCTAssertEqual(events, test.events)
        }
    }

    func test_aMessageWithNoEnvelopePaymentIsANoOp() async throws {
        let bodies: [Any] = [
            "plain",
            #"{"message":"paymail","payment":null}"#,
            ["message": "paymail", "payment": try recipientPayment(extra: [
                "outputs": [["outputIndex": 0, "protocol": "basket insertion"] as [String: Any]],
            ])] as [String: Any],
        ]
        for body in bodies {
            let log = EventLog()
            let (message, client) = try await listedMessage(body: body, log: log)
            let receiver = StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log)
            let internalized = try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
            XCTAssertFalse(internalized)
            let events = await log.events
            XCTAssertEqual(events, ["listMessages"])
        }
    }

    func test_aLookupThatReportsMoreIsNotAccepted() async throws {
        let f = try await fixture()
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row], hasMore: true))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        do {
            _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
            XCTFail("a lookup with more cannot show the message is there once")
        } catch MessageBoxPaymentError.notInInbox {}
        let events = await log.events
        XCTAssertEqual(events, ["listMessages"])
    }

    func test_aFailedAcknowledgementIsNotAnError() async throws {
        let f = try await fixture()
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (500, "")])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let result = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
        XCTAssertFalse(result.acknowledged)
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "acknowledgeMessage"])
    }

    func test_nothingIsAcknowledgedWhenTheWalletDoesNotAccept() async throws {
        let f = try await fixture()
        for outcome in [StubReceiver.Outcome.refused, .fails] {
            let log = EventLog()
            let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
            let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
            do {
                _ = try await client.accept(f.payment,
                    receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log, outcome: outcome))
                XCTFail("\(outcome) must not be reported as accepted")
            } catch MessageBoxPaymentError.settlementFailed {}
            let events = await log.events
            XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction"])
        }
    }

    func test_aSettlementThatDoesNotPayThisWalletIsRefusedBeforeInternalizing() async throws {
        let stranger = try key(9).publicKey
        for f in [
            try await fixture(satoshis: 1_000, claimed: 999),
            try await fixture(outputIndex: 1),
            try await fixture(payTo: stranger),
        ] {
            let log = EventLog()
            let transport = LoggingTransport(log: log, [(200, try listing([f.row]))])
            let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
            do {
                _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
                XCTFail("must be refused")
            } catch MessageBoxPaymentError.settlementFailed {}
            let events = await log.events
            XCTAssertEqual(events, ["listMessages", "getPublicKey"])
        }
    }

    func test_thePaymentMustBeInTheInboxExactlyOnce() async throws {
        let f = try await fixture()
        var elsewhere = f.row
        elsewhere["messageId"] = "p2"
        let listings: [[[String: Any]]] = [[], [f.row, f.row], [elsewhere]]
        for rows in listings {
            let log = EventLog()
            let transport = LoggingTransport(log: log, [(200, try listing(rows))])
            let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
            do {
                _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
                XCTFail("must not be accepted")
            } catch MessageBoxPaymentError.notInInbox {}
            let events = await log.events
            XCTAssertEqual(events, ["listMessages"])
        }
    }

    func test_anInvalidMessageIDIsRefusedBeforeAnyRequest() async throws {
        let f = try await fixture()
        let log = EventLog()
        let transport = LoggingTransport(log: log, [])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        for id in ["", "a\u{0}b", "a\u{85}b", String(repeating: "x", count: 1_025)] {
            let payment = MessageBoxIncomingPayment(messageId: id, sender: f.payment.sender, token: f.token)
            do {
                _ = try await client.accept(payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
                XCTFail("id \(id.debugDescription)")
            } catch MessageBoxPaymentError.invalidMessageID {}
        }
        let events = await log.events
        XCTAssertEqual(events, [])
    }

    func test_aPaymentBeingAcceptedCannotBeAcceptedAgainAtTheSameTime() async throws {
        let f = try await fixture()
        let log = EventLog()
        let transport = LoggingTransport(log: log,
            [(200, try listing([f.row])), (200, #"{"status":"success"}"#)], holdFirst: true)
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let receiver = StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log)
        let payment = f.payment
        let first = Task { try await client.accept(payment, receiver: receiver) }
        while !(await transport.isHolding()) { await Task.yield() }

        do { _ = try await client.accept(payment, receiver: receiver); XCTFail("second accept must wait its turn") }
        catch MessageBoxPaymentError.alreadyProcessing {}

        await transport.release()
        let result = try await first.value
        XCTAssertTrue(result.acknowledged)
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "acknowledgeMessage"])
    }

    func test_errorMessagesMatchTheTypeScriptClient() {
        XCTAssertEqual(MessageBoxPaymentError.invalidMessageID.errorDescription, "Incoming payment message ID is invalid")
        XCTAssertEqual(MessageBoxPaymentError.alreadyProcessing.errorDescription,
            "Payment message is already being processed by this client")
        XCTAssertEqual(MessageBoxPaymentError.notInInbox.errorDescription,
            "Incoming payment is not present exactly once in the authenticated inbox")
        XCTAssertEqual(MessageBoxPaymentError.settlementFailed.errorDescription,
            "BRC-29 settlement failed recipient, amount, transaction, or wallet validation.")
    }

    // Generated from the TS source by running `paymentFromMessage` over each stored body.
    private static let vectors = #"""
[
{"name":"plain token","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":0}}},
{"name":"double-encoded token","stored":"\"{\\\"customInstructions\\\":{\\\"derivationPrefix\\\":\\\"cHJlZml4\\\",\\\"derivationSuffix\\\":\\\"c3VmZml4\\\"},\\\"transaction\\\":[1,1,1,1,222,173],\\\"amount\\\":1000,\\\"outputIndex\\\":2}\"","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":2}}},
{"name":"base64 transaction","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":\"AQEBAd6t\",\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":0}}},
{"name":"outputIndex absent defaults to 0","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":0}}},
{"name":"outputIndex null defaults to 0","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":null}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":0}}},
{"name":"matching body sender","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0,\"sender\":\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":0}}},
{"name":"null body sender","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0,\"sender\":null}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":0}}},
{"name":"other body sender","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0,\"sender\":\"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\"}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"historical byte object","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":{\"0\":1,\"1\":2,\"2\":3},\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,2,3],"amount":1000,"outputIndex":0}}},
{"name":"trimmed derivation","stored":"{\"customInstructions\":{\"derivationPrefix\":\" cHJlZml4 \",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":0}}},
{"name":"extra fields ignored","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0,\"note\":\"hi\",\"recipient\":\"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\"}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":{"messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","token":{"customInstructions":{"derivationPrefix":"cHJlZml4","derivationSuffix":"c3VmZml4"},"transaction":[1,1,1,1,222,173],"amount":1000,"outputIndex":0}}},
{"name":"amount zero","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":0,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"amount fraction","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1.5,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"amount string","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":\"1000\",\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"amount above safe integer","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1],\"amount\":9007199254740992,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"outputIndex negative","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":-1}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"outputIndex above uint32","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":4294967296}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"outputIndex string","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":\"0\"}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"empty transaction","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"transaction byte out of range","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,256],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"transaction byte negative","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,-1],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"transaction boolean byte","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[true],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"non-canonical base64 transaction","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":\"AR==\",\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"unpadded base64 transaction","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":\"AQE\",\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"sparse byte object","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":{\"0\":1,\"2\":3},\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"empty byte object","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":{},\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"missing customInstructions","stored":"{\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"customInstructions array","stored":"{\"customInstructions\":[],\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"invalid base64 prefix","stored":"{\"customInstructions\":{\"derivationPrefix\":\"***\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"empty suffix","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"missing suffix","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"body not JSON","stored":"hello","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"body JSON array","stored":"[1,2]","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"body JSON number","stored":"7","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"body null","stored":"null","messageId":"m1","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"empty messageId","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"control character in messageId","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m\u0001","sender":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","expected":null},
{"name":"uppercase sender","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798","expected":null},
{"name":"sender not on curve","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"020000000000000000000000000000000000000000000000000000000000000000","expected":null},
{"name":"uncompressed-length sender","stored":"{\"customInstructions\":{\"derivationPrefix\":\"cHJlZml4\",\"derivationSuffix\":\"c3VmZml4\"},\"transaction\":[1,1,1,1,222,173],\"amount\":1000,\"outputIndex\":0}","messageId":"m1","sender":"04abababababababababababababababababababababababababababababababab","expected":null}
]
"""#
}
