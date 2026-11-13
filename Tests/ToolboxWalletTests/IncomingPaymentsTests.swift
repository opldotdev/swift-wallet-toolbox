import XCTest
import Foundation
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVAuth
import BSVWallet
import ToolboxAuth
import ToolboxBRC29
import ToolboxCore
import ToolboxStorage
import ToolboxStorageClient
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
    /// `refused` answers `accepted: false`; `fails` cannot reach storage; `locked` also refuses to
    /// derive keys, as a wallet that locked does; `cancelled` throws what a cancelled `URLSession`
    /// request throws, here in a task that was not cancelled; `failsOnceCancelled` waits for its
    /// task to be cancelled, then throws the same `URLError(.cancelled)`.
    enum Outcome: Sendable { case accepted, refused, fails, locked, cancelled, failsOnceCancelled }
    let keys: ProtoWallet
    let log: EventLog
    var outcome: Outcome = .accepted
    /// What the wallet does with an envelope payment (anything not labelled `peerpay`), when that
    /// differs from what it does with the token.
    var envelopeOutcome: Outcome? = nil
    /// The derived-key request, counted from 1, that fails as a locked wallet would.
    var failDerivation: Int? = nil
    /// Thrown when the wallet is asked to internalize an envelope payment, in place of its outcome.
    var envelopeError: (any Error)? = nil

    /// Logs `identity` for the identity key and `getPublicKey` for a derived key.
    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult {
        if request.selection == .identity {
            await log.add("identity")
        } else {
            await log.add("getPublicKey")
            let derivations = await log.events.filter { $0 == "getPublicKey" }.count
            if derivations == failDerivation { throw WalletLocked() }
        }
        if outcome == .locked { throw WalletLocked() }
        return try await keys.getPublicKey(request)
    }

    func internalizeAction(_ request: WalletInternalizeActionRequest) async throws -> WalletInternalizeActionResult {
        await log.add("internalizeAction")
        await log.keep(request)
        let isToken = request.labels == ["peerpay"]
        if !isToken, let envelopeError { throw envelopeError }
        switch isToken ? outcome : (envelopeOutcome ?? outcome) {
        case .accepted: return WalletInternalizeActionResult(accepted: true)
        case .refused: return WalletInternalizeActionResult(accepted: false)
        case .fails, .locked: throw URLError(.cannotConnectToHost)
        case .cancelled: throw URLError(.cancelled)
        case .failsOnceCancelled:
            while !Task.isCancelled { await Task.yield() }
            throw URLError(.cancelled)
        }
    }
}

/// What a caller's wallet-lock check throws.
private struct WalletLocked: Error {}

/// A `RecipientPaymentFailure` without the error `unavailable` carries, to compare in tables.
private enum FailureKind: Equatable {
    case unreadable, refused, unavailable

    init(_ failure: MessageBoxPaymentError.RecipientPaymentFailure) {
        switch failure {
        case .unreadable: self = .unreadable
        case .refused: self = .refused
        case .unavailable: self = .unavailable
        }
    }
}

/// Counts calls to a caller's check.
private actor CallCounter {
    var count = 0
    func increment() -> Int { count += 1; return count }
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

    func test_anEnvelopePaymentThatIsNotAnObjectIsKeptAsStored() async throws {
        // TS `listMessagesLite` keeps the message and drops such a payment; here the message is
        // kept with the payment as stored, so the envelope step can report it unreadable.
        let sender = hex(try key(3))
        let rows: [[String: Any]] = [
            ["messageId": "a", "sender": sender, "body": #"{"message":"m","payment":[1]}"#],
            ["messageId": "b", "sender": sender, "body": #"{"message":"n","payment":"x"}"#],
            ["messageId": "c", "sender": sender, "body": #"{"message":"o","payment":7}"#],
        ]
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)),
            transport: LoggingTransport(log: EventLog(), [(200, try listing(rows))]))
        let listed = try await client.listMessages(messageBox: MessageBoxClient.paymentInbox)
        XCTAssertTrue(listed.isComplete)
        XCTAssertEqual(listed.messages.map(\.body), ["m", "n", "o"])
        XCTAssertEqual(listed.messages.map(\.payment), [.array([1]), .string("x"), .number(7)])

        let log = EventLog()
        let receiver = StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log)
        for message in listed.messages {
            do {
                try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
                XCTFail("\(message.messageId) must not be taken")
            } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
                XCTAssertEqual(reason, .unreadable)
            }
        }
        // Only the wallet's identity is asked for; nothing is derived or internalized.
        let events = await log.events
        XCTAssertEqual(events, ["identity", "identity", "identity"])
    }

    func test_aPeerPayTokenBehindAnEnvelopePaymentThatIsNotAnObjectIsListed() async throws {
        let f = try await fixture(envelope: [1])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver),
            transport: LoggingTransport(log: EventLog(), [(200, try listing([f.row]))]))
        let payments = try await client.incomingPayments()
        XCTAssertEqual(payments, MessageBoxPaymentListing(payments: [f.payment], truncated: false, nextOffset: 1))
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
        // A body that is a number, a sender that is not a key, and a row that is not an object
        // cannot be read as messages at all; the rest were messages that are not payments.
        XCTAssertEqual(listed.skipped, 3)
        // Every page was read, but rows were left out, so the listing is not complete.
        XCTAssertFalse(listed.isComplete)
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
        // The row the limit cut is still on the server, and the next listing can start at it.
        XCTAssertTrue(listed.truncated)
        XCTAssertEqual(listed.nextOffset, 1_000)
    }

    func test_incomingPaymentsStopAtTenPagesAsTruncated() async throws {
        let page = try listing([], hasMore: true)
        let transport = LoggingTransport(log: EventLog(), Array(repeating: (status: 200, body: page), count: 10))
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listed = try await client.incomingPayments()
        XCTAssertEqual(listed, MessageBoxPaymentListing(payments: [], truncated: true, nextOffset: 1_000))
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
        XCTAssertEqual(listed.skipped, 10)
        XCTAssertFalse(listed.isComplete)
        XCTAssertEqual(listed.payments.count, 990)
        XCTAssertEqual(listed.payments.first?.messageId, "m1")
        XCTAssertEqual(listed.payments.last?.messageId, "m999")
        let requests = await transport.requests
        XCTAssertEqual(requests.count, 10)
        let offsets = try requests.map { try json($0.body)["offset"] as? Int }
        XCTAssertEqual(offsets, (0..<10).map { Optional($0 * 100) })
        let limits = try requests.map { try json($0.body)["limit"] as? Int }
        XCTAssertEqual(limits, Array(repeating: Optional(100), count: 10))
        XCTAssertEqual(listed.nextOffset, 1_000)
    }

    private func plainToken() throws -> String {
        String(decoding: try JSONEncoder().encode(MessageBoxPaymentToken(derivationPrefix: prefix,
            derivationSuffix: suffix, transaction: [1], amount: 5, outputIndex: 0)), as: UTF8.self)
    }

    func test_exactlyOneThousandMessagesWithNothingMoreAreNotTruncated() async throws {
        let sender = try key(2)
        let plain = try plainToken()
        // Ten full pages of 100; the last says there is nothing more.
        let pages: [(status: Int, body: String)] = try (0..<10).map { page -> (status: Int, body: String) in
            let rows: [[String: Any]] = (0..<100).map {
                ["messageId": "m\(page * 100 + $0)", "sender": hex(sender), "body": plain]
            }
            return (200, try listing(rows, hasMore: page < 9))
        }
        let transport = LoggingTransport(log: EventLog(), pages)
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listed = try await client.incomingPayments()
        XCTAssertFalse(listed.truncated)
        XCTAssertEqual(listed.payments.count, 1_000)
        XCTAssertEqual(listed.nextOffset, 1_000)
        let count = await transport.requests.count
        XCTAssertEqual(count, 10)

        // The same thousand from a server that ignores the page size.
        let all: [[String: Any]] = (0..<1_000).map { ["messageId": "m\($0)", "sender": hex(sender), "body": plain] }
        let whole = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)),
            transport: LoggingTransport(log: EventLog(), [(200, try listing(all))]))
        let once = try await whole.incomingPayments()
        XCTAssertFalse(once.truncated)
        XCTAssertEqual(once.payments.count, 1_000)
    }

    func test_aFullWindowOfUnreadableRowsCanBeListedPast() async throws {
        let sender = try key(2)
        let plain = try plainToken()
        // The inbox opens with a thousand rows that are never payments, so never acknowledged;
        // the payment behind them is only reachable by listing on from where the window ended.
        var responses: [(status: Int, body: String)] = try (0..<10).map { page -> (status: Int, body: String) in
            let junk: [Any] = (0..<100).map { "junk \(page * 100 + $0)" }
            return (200, try listing(junk, hasMore: true))
        }
        responses.append((200, try listing([["messageId": "late", "sender": hex(sender), "body": plain]])))
        let transport = LoggingTransport(log: EventLog(), responses)
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)

        let first = try await client.incomingPayments()
        XCTAssertEqual(first, MessageBoxPaymentListing(payments: [], truncated: true, nextOffset: 1_000, skipped: 1_000))
        let next = try await client.incomingPayments(offset: first.nextOffset)
        XCTAssertEqual(next.payments.map(\.messageId), ["late"])
        XCTAssertFalse(next.truncated)
        XCTAssertEqual(next.nextOffset, 1_001)

        let requests = await transport.requests
        XCTAssertEqual(requests.count, 11)
        let last = try json(requests[10].body)
        XCTAssertEqual(last["offset"] as? Int, 1_000)
        XCTAssertEqual(last["limit"] as? Int, 100)
        XCTAssertEqual(last["messageBox"] as? String, "payment_inbox")
    }

    func test_aNegativeIncomingPaymentOffsetIsRefusedBeforeAnyRequest() async throws {
        let transport = LoggingTransport(log: EventLog(), [])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        do { _ = try await client.incomingPayments(offset: -1); XCTFail("negative offset") }
        catch MessageBoxError.invalidMessage {}
        let count = await transport.requests.count
        XCTAssertEqual(count, 0)
    }

    func test_theBeforeOpeningCheckRunsForEachMessageAndCanStopTheListing() async throws {
        let sender = try key(2)
        let plain = try plainToken()
        let rows: [[String: Any]] = ["a", "a", "b", "c"].map { ["messageId": $0, "sender": hex(sender), "body": plain] }
        let counter = CallCounter()
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)),
            transport: LoggingTransport(log: EventLog(), [(200, try listing(rows))]))
        let listed = try await client.incomingPayments(beforeOpening: { _ = await counter.increment() })
        XCTAssertEqual(listed.payments.map(\.messageId), ["a", "b", "c"])
        // Once for each distinct message.
        let calls = await counter.count
        XCTAssertEqual(calls, 3)

        let stopping = CallCounter()
        let locking = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: key(1)),
            transport: LoggingTransport(log: EventLog(), [(200, try listing(rows))]))
        do {
            _ = try await locking.incomingPayments(beforeOpening: {
                if await stopping.increment() == 2 { throw WalletLocked() }
            })
            XCTFail("the check must stop the listing")
        } catch is WalletLocked {}
        let stoppedAt = await stopping.count
        XCTAssertEqual(stoppedAt, 2)
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
        XCTAssertTrue(listed.isComplete)
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
    /// output to the recipient (key 1, unless `payTo` says otherwise) and one basket insertion
    /// that is not the recipient's to claim.
    private func recipientPayment(remittance: Bool = true, payTo: PublicKey? = nil,
                                  extra: [String: Any] = [:]) throws -> [String: Any] {
        let sender = try key(2), receiver = try key(1)
        let tx = try paymentTransaction(to: payTo ?? receiver.publicKey, from: sender, satoshis: 10)
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

    func test_anEnvelopePaymentIsInternalizedAfterTheTokenAndBeforeTheMessageIsAcknowledged() async throws {
        let envelope = try recipientPayment()
        let f = try await fixture(envelope: envelope)
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let result = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))

        XCTAssertTrue(result.recipientPaymentInternalized)
        XCTAssertTrue(result.acknowledged)
        // The token first, then the wallet's identity, then the envelope payment's ownership check
        // and internalize.
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "identity", "getPublicKey",
                                "internalizeAction", "acknowledgeMessage"])

        let internalized = await log.internalized
        XCTAssertEqual(internalized.count, 2)
        XCTAssertEqual(internalized.first?.labels, ["peerpay"])
        let fee = try XCTUnwrap(internalized.last)
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
    }

    func test_anEnvelopePaymentTheWalletDoesNotTakeStillLetsTheTokenIn() async throws {
        let f = try await fixture(envelope: try recipientPayment())
        // The wallet answered no; or storage could not be reached, which decided nothing.
        let cases: [(outcome: StubReceiver.Outcome, kind: FailureKind)] = [(.refused, .refused), (.fails, .unavailable)]
        for test in cases {
            let log = EventLog()
            let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
            let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
            do {
                _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver),
                    log: log, envelopeOutcome: test.outcome), beforeAcknowledge: { await log.add("beforeAcknowledge") })
                XCTFail("\(test.outcome) must not be acknowledged")
            } catch MessageBoxPaymentError.envelopePaymentNotTaken(let notTaken) {
                XCTAssertEqual(FailureKind(notTaken.reason), test.kind)
                XCTAssertEqual(notTaken.payment, f.payment)
                XCTAssertEqual(notTaken.message.messageId, "p1")
                XCTAssertNotNil(notTaken.message.payment)
            }
            // The token is in; the envelope payment was asked for and not taken; nothing is acknowledged.
            let events = await log.events
            XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "identity", "getPublicKey",
                                    "internalizeAction"])
            let internalized = await log.internalized
            XCTAssertEqual(internalized.first?.labels, ["peerpay"])
            let paths = await transport.requests.map(\.path)
            XCTAssertEqual(paths, ["/listMessages"])
        }
    }

    func test_aRefusedEnvelopePaymentCanBeRetriedOnItsOwn() async throws {
        let f = try await fixture(envelope: try recipientPayment())
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let notTaken: MessageBoxEnvelopePaymentNotTaken
        do {
            _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver),
                log: log, envelopeOutcome: .refused))
            return XCTFail("must not be acknowledged")
        } catch MessageBoxPaymentError.envelopePaymentNotTaken(let error) {
            notTaken = error
        }

        // Later, the envelope payment alone, then the acknowledgement; the token is not asked again.
        let taken = try await client.internalizeEnvelopePayment(of: notTaken.message,
            receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
        XCTAssertTrue(taken)
        try await client.acknowledge(messageIds: [notTaken.message.messageId])
        let events = await log.events
        XCTAssertEqual(events, [
            "listMessages", "getPublicKey", "internalizeAction", "identity", "getPublicKey", "internalizeAction",
            "identity", "getPublicKey", "internalizeAction", "acknowledgeMessage",
        ])
        let internalized = await log.internalized
        XCTAssertEqual(internalized.map(\.labels), [["peerpay"], [], []])
        XCTAssertEqual(internalized[1], internalized[2])
    }

    func test_acceptingAgainAfterARefusedEnvelopePaymentTakesBothAndAcknowledgesOnce() async throws {
        let f = try await fixture(envelope: try recipientPayment())
        let log = EventLog()
        let transport = LoggingTransport(log: log, [
            (200, try listing([f.row])), (200, try listing([f.row])), (200, #"{"status":"success"}"#),
        ])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        do {
            _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver),
                log: log, envelopeOutcome: .refused))
            XCTFail("must not be acknowledged")
        } catch MessageBoxPaymentError.envelopePaymentNotTaken(let notTaken) {
            XCTAssertEqual(notTaken.reason, .refused)
        }

        // The token goes to the wallet a second time, which storage merges; then the envelope
        // payment; then the one acknowledgement.
        let result = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
        XCTAssertTrue(result.acknowledged)
        XCTAssertTrue(result.recipientPaymentInternalized)
        let internalized = await log.internalized
        XCTAssertEqual(internalized.map(\.labels), [["peerpay"], [], ["peerpay"], []])
        XCTAssertEqual(internalized[0], internalized[2])
        XCTAssertEqual(internalized[1], internalized[3])
        let paths = await transport.requests.map(\.path)
        XCTAssertEqual(paths, ["/listMessages", "/listMessages", "/acknowledgeMessage"])
    }

    func test_aKeyDerivationThatFailsOnTheEnvelopeStepOnlyIsUnavailable() async throws {
        // The token's key derives; the envelope payment's does not, as when the wallet locks
        // between the two. Nothing was decided about the payment, so it is unavailable, carrying
        // the wallet's error: neither unreadable nor refused.
        let f = try await fixture(envelope: try recipientPayment())
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        do {
            _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver),
                log: log, failDerivation: 2))
            XCTFail("must not be acknowledged")
        } catch MessageBoxPaymentError.envelopePaymentNotTaken(let notTaken) {
            guard case .unavailable(let error) = notTaken.reason else { return XCTFail("\(notTaken.reason)") }
            XCTAssertTrue(error is WalletLocked)
        }
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "identity", "getPublicKey"])

        // The envelope step on its own, failing at its one derivation.
        let (message, stepClient) = try await listedMessage(
            body: ["message": "paymail", "payment": try recipientPayment()] as [String: Any], log: EventLog())
        do {
            try await stepClient.internalizeEnvelopePayment(of: message,
                receiver: StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: EventLog(), failDerivation: 1))
            XCTFail("must not be taken")
        } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
            XCTAssertEqual(FailureKind(reason), .unavailable)
        }
    }

    func test_anEnvelopePaymentLargerThanStorageTakesIsRefused() async throws {
        // An Atomic BEEF that declares more merkle paths than `StorageLimits.beef` allows: the
        // limit, not the payment, stands in the way, so the message is kept.
        var tooMany: [UInt8] = [1, 1, 1, 1] + Array(repeating: 0, count: 32)
        tooMany += [0x01, 0x00, 0xbe, 0xef]
        tooMany += [0xfd, 0x11, 0x27]  // 10,001 merkle paths
        let oversize = try recipientPayment(extra: ["tx": tooMany.map { Int($0) }])

        let log = EventLog()
        let (message, client) = try await listedMessage(
            body: ["message": "paymail", "payment": oversize] as [String: Any], log: log)
        do {
            try await client.internalizeEnvelopePayment(of: message, receiver: StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log))
            XCTFail("must not be taken")
        } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
            XCTAssertEqual(reason, .refused)
        }
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "identity"])

        // The same through accept: the token is in, the envelope payment is kept to retry.
        let f = try await fixture(envelope: oversize)
        let acceptLog = EventLog()
        let acceptClient = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver),
            transport: LoggingTransport(log: acceptLog, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)]))
        do {
            _ = try await acceptClient.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: acceptLog))
            XCTFail("must not be acknowledged")
        } catch MessageBoxPaymentError.envelopePaymentNotTaken(let notTaken) {
            XCTAssertEqual(notTaken.reason, .refused)
        }
        let acceptEvents = await acceptLog.events
        XCTAssertEqual(acceptEvents, ["listMessages", "getPublicKey", "internalizeAction", "identity"])

        // A truncated transaction of ordinary size is still unreadable.
        let (short, shortClient) = try await listedMessage(body: ["message": "paymail",
            "payment": try recipientPayment(extra: ["tx": [1, 1, 1, 1]])] as [String: Any], log: EventLog())
        do {
            try await shortClient.internalizeEnvelopePayment(of: short, receiver: StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: EventLog()))
            XCTFail("must not be taken")
        } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
            XCTAssertEqual(reason, .unreadable)
        }
    }

    func test_anEnvelopePaymentForAnotherWalletIsRefused() async throws {
        // The client is key 1; the wallet is key 5. Whatever the payment, it is kept for the
        // wallet it was sent to, never called unreadable.
        for envelope in [try recipientPayment(), try recipientPayment(remittance: false)] {
            let log = EventLog()
            let (message, client) = try await listedMessage(
                body: ["message": "paymail", "payment": envelope] as [String: Any], log: log)
            do {
                try await client.internalizeEnvelopePayment(of: message, receiver: StubReceiver(keys: ProtoWallet(rootKey: try key(5)), log: log))
                XCTFail("must not be taken")
            } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
                XCTAssertEqual(reason, .refused)
            }
            let events = await log.events
            XCTAssertEqual(events, ["listMessages", "identity"])
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
        // Each is read before the wallet is asked anything about it but its identity; a payment
        // that is not an object is kept by the listing and unreadable here.
        let tokenOnly = ["listMessages", "getPublicKey", "internalizeAction", "identity"]
        var cases: [(envelope: Any, events: [String])] = unreadable.map { (envelope: $0 as Any, events: tokenOnly) }
        cases.append((envelope: [1] as Any, events: tokenOnly))
        // Pays a key this wallet does not hold: refused by the ownership check, not the wallet.
        cases.append((envelope: try recipientPayment(payTo: try key(9).publicKey) as Any,
                      events: tokenOnly + ["getPublicKey"]))
        // Names an output the transaction does not have.
        let missingOutput: [String: Any] = [
            "outputIndex": 5, "protocol": "wallet payment",
            "paymentRemittance": ["derivationPrefix": prefix, "derivationSuffix": suffix, "senderIdentityKey": hex(try key(2))],
        ]
        cases.append((envelope: try recipientPayment(extra: ["outputs": [missingOutput]]) as Any, events: tokenOnly))
        for test in cases {
            let f = try await fixture(envelope: test.envelope)
            let log = EventLog()
            let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
            let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
            do {
                _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
                XCTFail("must not be acknowledged")
            } catch MessageBoxPaymentError.envelopePaymentNotTaken(let notTaken) {
                XCTAssertEqual(notTaken.reason, .unreadable)
                XCTAssertEqual(notTaken.payment, f.payment)
            }
            // The token is in the wallet either way.
            let events = await log.events
            XCTAssertEqual(events, test.events)
            let internalized = await log.internalized
            XCTAssertEqual(internalized.map(\.labels), [["peerpay"]])
        }
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
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "identity", "acknowledgeMessage"])
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
        XCTAssertEqual(events, ["listMessages", "identity", "getPublicKey", "internalizeAction"])
        try await client.acknowledge(messageIds: [message.messageId])
        events = await log.events
        XCTAssertEqual(events, ["listMessages", "identity", "getPublicKey", "internalizeAction", "acknowledgeMessage"])

        let requests = await log.internalized
        XCTAssertEqual(requests.count, 1)
        let fee = try XCTUnwrap(requests.first)
        XCTAssertEqual(fee.description, "MessageBox recipient payment")
        XCTAssertEqual(try fee.transaction.serialized(limits: StorageLimits.beef).map { Int($0) }, envelope["tx"] as? [Int])
        XCTAssertEqual(fee.outputs.map(\.outputIndex), [0])
    }

    func test_theEnvelopeStepTwiceAsksTheWalletTwice() async throws {
        // There is no in-flight guard here; wallet storage merges the repeat.
        let log = EventLog()
        let (message, client) = try await listedMessage(
            body: ["message": "paymail", "payment": try recipientPayment()] as [String: Any], log: log)
        let receiver = StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log)
        let first = try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
        let second = try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
        XCTAssertTrue(first)
        XCTAssertTrue(second)
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "identity", "getPublicKey", "internalizeAction",
                                "identity", "getPublicKey", "internalizeAction"])
        let requests = await log.internalized
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests.first, requests.last)
    }

    func test_theEnvelopeStepThenAcceptOnTheSameMessage() async throws {
        let f = try await fixture(envelope: try recipientPayment())
        let log = EventLog()
        let transport = LoggingTransport(log: log, [
            (200, try listing([f.row])), (200, try listing([f.row])), (200, #"{"status":"success"}"#),
        ])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let messages = try await client.listMessages(messageBox: MessageBoxClient.paymentInbox).messages
        let message = try XCTUnwrap(messages.first)
        let receiver = StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log)
        let stepped = try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
        XCTAssertTrue(stepped)

        // Accept looks the message up again and internalizes the envelope payment again after
        // the token; the repeat is the storage merge the step relies on.
        let result = try await client.accept(f.payment, receiver: receiver)
        XCTAssertTrue(result.recipientPaymentInternalized)
        XCTAssertTrue(result.acknowledged)
        let events = await log.events
        XCTAssertEqual(events, [
            "listMessages", "identity", "getPublicKey", "internalizeAction",
            "listMessages", "getPublicKey", "internalizeAction", "identity", "getPublicKey", "internalizeAction",
            "acknowledgeMessage",
        ])
        let internalized = await log.internalized
        XCTAssertEqual(internalized.count, 3)
        XCTAssertEqual(internalized[0], internalized[2])
        XCTAssertEqual(internalized[1].labels, ["peerpay"])
    }

    func test_aFailedEnvelopePaymentSaysWhetherItCanBeRetried() async throws {
        let cases: [(envelope: [String: Any], outcome: StubReceiver.Outcome, reason: FailureKind, events: [String])] = [
            // The wallet answered no.
            (try recipientPayment(), .refused, .refused, ["listMessages", "identity", "getPublicKey", "internalizeAction"]),
            // Storage could not be reached, or the wallet locked: nothing was decided.
            (try recipientPayment(), .fails, .unavailable, ["listMessages", "identity", "getPublicKey", "internalizeAction"]),
            (try recipientPayment(), .locked, .unavailable, ["listMessages", "identity"]),
            // Never takeable: unreadable, or paying a key this wallet does not hold.
            (try recipientPayment(remittance: false), .accepted, .unreadable, ["listMessages", "identity"]),
            (try recipientPayment(payTo: try key(9).publicKey), .accepted, .unreadable,
             ["listMessages", "identity", "getPublicKey"]),
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
            } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
                XCTAssertEqual(FailureKind(reason), test.reason, "\(test.outcome)")
            }
            let events = await log.events
            XCTAssertEqual(events, test.events, "\(test.outcome)")
        }
    }

    func test_whatTheWalletThrowsSaysWhetherItDecided() async throws {
        // Errors that mean the wallet or storage gave no decision about the payment are
        // unavailable and carry the error; errors that are the wallet's or storage's own answer
        // are refused.
        let cases: [(error: any Error, kind: FailureKind)] = [
            (URLError(.notConnectedToInternet), .unavailable),
            (URLError(.timedOut), .unavailable),
            (URLError(.networkConnectionLost), .unavailable),
            (URLError(.cancelled), .unavailable),
            (AuthTransportError.transportFailed("reset"), .unavailable),
            (AuthTransportError.sessionExpired, .unavailable),
            (AuthTransportError.responseNotAuthenticated("no frame"), .unavailable),
            (AuthError.invalidSignature, .unavailable),
            (AuthError.peerMismatch, .unavailable),
            (AuthError.invalidNonce, .unavailable),
            (AuthError.replay, .unavailable),
            (StorageClientError.unreadableResponse(method: "internalizeAction"), .unavailable),
            (StorageClientError.httpFailure(method: "internalizeAction", statusCode: 503), .unavailable),
            (StorageClientError.httpFailure(method: "internalizeAction", statusCode: 429), .unavailable),
            (StorageClientError.httpFailure(method: "internalizeAction", statusCode: 408), .unavailable),
            (WireError.internalFailure("database down"), .unavailable),
            (WireError.notActive("switching"), .unavailable),
            (WireError.broadcastUnavailable("no broadcaster"), .unavailable),
            (WireError.reviewActions("broadcast failed"), .unavailable),
            (WireError.unauthorized("session"), .unavailable),
            (StorageClientError.httpFailure(method: "internalizeAction", statusCode: 413), .refused),
            (WireError.invalidParameter(name: "tx", message: "bad"), .refused),
            (WireError.badRequest("no"), .refused),
            (WireError.unrecognized(name: "WERR_NEW", message: "new"), .refused),
            (WalletError.outputIsNotBRC29Payment(outputIndex: 0), .refused),
            (WalletError.internalizeSubjectMissing, .refused),
        ]
        for test in cases {
            let log = EventLog()
            let (message, client) = try await listedMessage(
                body: ["message": "paymail", "payment": try recipientPayment()] as [String: Any], log: log)
            let receiver = StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log, envelopeError: test.error)
            do {
                try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
                XCTFail("\(test.error) must not be taken")
            } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
                XCTAssertEqual(FailureKind(reason), test.kind, "\(test.error)")
                if case .unavailable(let carried) = reason {
                    XCTAssertEqual(String(reflecting: carried), String(reflecting: test.error))
                }
            }
            let events = await log.events
            XCTAssertEqual(events, ["listMessages", "identity", "getPublicKey", "internalizeAction"], "\(test.error)")
        }

        // The carried error is the one thrown, so a caller can tell a storage error from a
        // network one.
        let (message, client) = try await listedMessage(
            body: ["message": "paymail", "payment": try recipientPayment()] as [String: Any], log: EventLog())
        do {
            try await client.internalizeEnvelopePayment(of: message, receiver: StubReceiver(keys: ProtoWallet(rootKey: try key(1)),
                log: EventLog(), envelopeError: WireError.internalFailure("Could not determine transaction index")))
            XCTFail("must not be taken")
        } catch MessageBoxPaymentError.recipientPaymentFailed(.unavailable(let error)) {
            XCTAssertEqual(error as? WireError, .internalFailure("Could not determine transaction index"))
        }

        // An `NSError` in the URL domain is a network failure like the `URLError` it stands for,
        // and not a cancellation outside a cancelled task.
        XCTAssertTrue(MessageBoxClient.isUndecided(NSError(domain: NSURLErrorDomain, code: URLError.Code.timedOut.rawValue)))
        XCTAssertTrue(MessageBoxClient.isUndecided(NSError(domain: NSURLErrorDomain, code: URLError.Code.cancelled.rawValue)))
        XCTAssertFalse(MessageBoxClient.isCancellation(NSError(domain: NSURLErrorDomain, code: URLError.Code.cancelled.rawValue)))
    }

    func test_unavailableFailuresCompareByTheirError() {
        typealias Failure = MessageBoxPaymentError.RecipientPaymentFailure
        let failures: [Failure] = [
            .unreadable, .refused,
            .unavailable(WireError.internalFailure("x")), .unavailable(WireError.internalFailure("y")),
            .unavailable(WireError.notActive("x")),
            .unavailable(WalletLocked()),
            .unavailable(URLError(.timedOut)), .unavailable(URLError(.notConnectedToInternet)),
            .unavailable(NSError(domain: "storage", code: 1)), .unavailable(NSError(domain: "storage", code: 2)),
        ]
        // Reflexive, for Equatable errors, errors that are not Equatable, and NSErrors alike.
        for failure in failures {
            XCTAssertEqual(failure, failure, "\(failure)")
        }
        // Symmetric, and distinct failures are not equal.
        for (i, left) in failures.enumerated() {
            for (j, right) in failures.enumerated() {
                XCTAssertEqual(left == right, right == left, "\(left) vs \(right)")
                if i != j { XCTAssertNotEqual(left, right, "\(left) vs \(right)") }
            }
        }
        // Equal values, not the same instance.
        XCTAssertEqual(Failure.unavailable(WireError.internalFailure("x")), .unavailable(WireError.internalFailure("x")))
        XCTAssertEqual(Failure.unavailable(WalletLocked()), .unavailable(WalletLocked()))
        XCTAssertEqual(Failure.unavailable(NSError(domain: "storage", code: 1, userInfo: ["a": 1])),
            .unavailable(NSError(domain: "storage", code: 1)))
    }

    func test_aCancelledRequestIsACancellationOnlyInACancelledTask() async throws {
        // `URLError(.cancelled)` in a task that was not cancelled is how `URLSession` reports a
        // rejected authentication challenge or an invalidated session: not a decision, not a
        // cancellation.
        let log = EventLog()
        let (message, client) = try await listedMessage(
            body: ["message": "paymail", "payment": try recipientPayment()] as [String: Any], log: log)
        do {
            try await client.internalizeEnvelopePayment(of: message,
                receiver: StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log, outcome: .cancelled))
            XCTFail("a failed wallet call must not be a result")
        } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
            guard case .unavailable(let error) = reason else { return XCTFail("\(reason)") }
            XCTAssertEqual((error as? URLError)?.code, .cancelled)
        }
        var events = await log.events
        XCTAssertEqual(events, ["listMessages", "identity", "getPublicKey", "internalizeAction"])

        // The same error from a request in a cancelled task is a cancellation.
        let receiver = StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log, outcome: .failsOnceCancelled)
        let step = Task { try await client.internalizeEnvelopePayment(of: message, receiver: receiver) }
        // Cancel once the wallet is internalizing, so nothing before it sees the cancellation.
        while await log.events.count < 7 { await Task.yield() }
        step.cancel()
        do {
            _ = try await step.value
            XCTFail("a wallet call failing in a cancelled task must not be a result")
        } catch is CancellationError {}
        events = await log.events
        XCTAssertEqual(events, ["listMessages", "identity", "getPublicKey", "internalizeAction",
                                "identity", "getPublicKey", "internalizeAction"])

        // In a cancelled task any failure is a cancellation; outside one only `CancellationError` is.
        XCTAssertTrue(MessageBoxClient.isCancellation(CancellationError()))
        XCTAssertFalse(MessageBoxClient.isCancellation(URLError(.cancelled)))
        XCTAssertFalse(MessageBoxClient.isCancellation(URLError(.timedOut)))
        let inCancelledTask = Task { () -> [Bool] in
            while !Task.isCancelled { await Task.yield() }
            return [MessageBoxClient.isCancellation(URLError(.cancelled)), MessageBoxClient.isCancellation(WalletLocked())]
        }
        inCancelledTask.cancel()
        let cancelled = await inCancelledTask.value
        XCTAssertEqual(cancelled, [true, true])
    }

    func test_acceptReportsAFailureInACancelledTaskAsACancellation() async throws {
        // On the envelope payment: the token is in, the message stays, and this is not
        // `envelopePaymentNotTaken`.
        let f = try await fixture(envelope: try recipientPayment())
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let receiver = StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log, envelopeOutcome: .failsOnceCancelled)
        let payment = f.payment
        let accepting = Task {
            try await client.accept(payment, receiver: receiver, beforeAcknowledge: { await log.add("beforeAcknowledge") })
        }
        while await log.events.count < 6 { await Task.yield() }
        accepting.cancel()
        do {
            _ = try await accepting.value
            XCTFail("must not be acknowledged")
        } catch is CancellationError {}
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "identity", "getPublicKey",
                                "internalizeAction"])
        let paths = await transport.requests.map(\.path)
        XCTAssertEqual(paths, ["/listMessages"])

        // On the token: a cancellation, not `settlementFailed`; and the message is free to accept again.
        let tokenLog = EventLog()
        let tokenTransport = LoggingTransport(log: tokenLog, [
            (200, try listing([f.row])), (200, try listing([f.row])), (200, #"{"status":"success"}"#),
        ])
        let tokenClient = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: tokenTransport)
        let tokenReceiver = StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: tokenLog, outcome: .failsOnceCancelled)
        let tokenAccepting = Task { try await tokenClient.accept(payment, receiver: tokenReceiver) }
        while await tokenLog.events.count < 3 { await Task.yield() }
        tokenAccepting.cancel()
        do {
            _ = try await tokenAccepting.value
            XCTFail("must not be acknowledged")
        } catch is CancellationError {}
        let again = try await tokenClient.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver),
            log: tokenLog))
        XCTAssertTrue(again.acknowledged)

        // The same `URLError(.cancelled)` outside a cancelled task leaves the envelope payment
        // unavailable and the token a settlement failure.
        let plainLog = EventLog()
        let plainClient = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver),
            transport: LoggingTransport(log: plainLog, [(200, try listing([f.row])), (200, try listing([f.row]))]))
        do {
            _ = try await plainClient.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver),
                log: plainLog, envelopeOutcome: .cancelled))
            XCTFail("must not be acknowledged")
        } catch MessageBoxPaymentError.envelopePaymentNotTaken(let notTaken) {
            XCTAssertEqual(FailureKind(notTaken.reason), .unavailable)
        }
        do {
            _ = try await plainClient.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver),
                log: plainLog, outcome: .cancelled))
            XCTFail("must not be acknowledged")
        } catch MessageBoxPaymentError.settlementFailed {}
    }

    func test_acceptRefusesTheEnvelopePaymentForAnotherWallet() async throws {
        // The client is key 1. The token pays key 5, so a key-5 wallet takes it; the envelope
        // payment was sent to the client's identity, so the key-5 wallet is refused it before it
        // is derived or internalized, and the message is kept.
        let other = try key(5)
        let f = try await fixture(payTo: other.publicKey, envelope: try recipientPayment())
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        do {
            _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: other), log: log),
                beforeAcknowledge: { await log.add("beforeAcknowledge") })
            XCTFail("another wallet must not take the envelope payment")
        } catch MessageBoxPaymentError.envelopePaymentNotTaken(let notTaken) {
            XCTAssertEqual(notTaken.reason, .refused)
            XCTAssertEqual(notTaken.payment, f.payment)
        }
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "identity"])
        let internalized = await log.internalized
        XCTAssertEqual(internalized.map(\.labels), [["peerpay"]])
        let paths = await transport.requests.map(\.path)
        XCTAssertEqual(paths, ["/listMessages"])
    }

    func test_aMessageWithNoEnvelopePaymentIsANoOp() async throws {
        // No payment asks nothing of the wallet; a payment with no wallet outputs asks only for
        // the wallet's identity.
        let cases: [(body: Any, events: [String])] = [
            ("plain", ["listMessages"]),
            (#"{"message":"paymail","payment":null}"#, ["listMessages"]),
            (["message": "paymail", "payment": try recipientPayment(extra: [
                "outputs": [["outputIndex": 0, "protocol": "basket insertion"] as [String: Any]],
            ])] as [String: Any], ["listMessages", "identity"]),
        ]
        for test in cases {
            let log = EventLog()
            let (message, client) = try await listedMessage(body: test.body, log: log)
            let receiver = StubReceiver(keys: ProtoWallet(rootKey: try key(1)), log: log)
            let internalized = try await client.internalizeEnvelopePayment(of: message, receiver: receiver)
            XCTAssertFalse(internalized)
            let events = await log.events
            XCTAssertEqual(events, test.events)
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

    func test_aLookupThatReturnsMoreThanTwoRowsIsNotAccepted() async throws {
        // A server that ignores the lookup's limit of two: the third row is cut, so the lookup
        // cannot show the message is there exactly once, even though it matches only once.
        let f = try await fixture()
        var second = f.row, third = f.row
        second["messageId"] = "p2"; third["messageId"] = "p3"
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row, second, third]))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        do {
            _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
            XCTFail("a cut lookup cannot show the message is there once")
        } catch MessageBoxPaymentError.notInInbox {}
        let events = await log.events
        XCTAssertEqual(events, ["listMessages"])
    }

    func test_theBeforeAcknowledgeCheckRunsRightBeforeTheAcknowledgement() async throws {
        let f = try await fixture()
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row])), (200, #"{"status":"success"}"#)])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let result = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log),
            beforeAcknowledge: { await log.add("beforeAcknowledge") })
        XCTAssertTrue(result.acknowledged)
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "beforeAcknowledge", "acknowledgeMessage"])
    }

    func test_aBeforeAcknowledgeCheckThatThrowsKeepsTheMessage() async throws {
        let f = try await fixture(envelope: try recipientPayment())
        let log = EventLog()
        let transport = LoggingTransport(log: log, [
            (200, try listing([f.row])), (200, try listing([f.row])), (200, #"{"status":"success"}"#),
        ])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        let result = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log),
            beforeAcknowledge: { await log.add("beforeAcknowledge"); throw WalletLocked() })
        // The funds are in the wallet, so this is a result, not an error; the message stays.
        XCTAssertFalse(result.acknowledged)
        XCTAssertTrue(result.recipientPaymentInternalized)
        XCTAssertEqual(result.payment, f.payment)
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey", "internalizeAction", "identity", "getPublicKey",
                                "internalizeAction", "beforeAcknowledge"])
        let paths = await transport.requests.map(\.path)
        XCTAssertEqual(paths, ["/listMessages"])

        // The message is no longer in flight, so accepting it again once the wallet is unlocked
        // runs to the acknowledgement.
        let again = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log))
        XCTAssertTrue(again.acknowledged)
        let retried = await transport.requests.map(\.path)
        XCTAssertEqual(retried, ["/listMessages", "/listMessages", "/acknowledgeMessage"])
    }

    func test_theBeforeAcknowledgeCheckDoesNotRunWhenTheSettlementFails() async throws {
        let f = try await fixture(satoshis: 1_000, claimed: 999)
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row]))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        do {
            _ = try await client.accept(f.payment, receiver: StubReceiver(keys: ProtoWallet(rootKey: f.receiver), log: log),
                beforeAcknowledge: { await log.add("beforeAcknowledge") })
            XCTFail("must be refused")
        } catch MessageBoxPaymentError.settlementFailed {}
        let events = await log.events
        XCTAssertEqual(events, ["listMessages", "getPublicKey"])
    }

    // MARK: - The RemoteWallet overloads

    /// A RemoteWallet whose storage is never reached: every case here is refused by the wallet's
    /// own BRC-29 ownership check, or by the settlement check, before storage is called.
    private func remoteWallet(root: PrivateKey) throws -> RemoteWallet {
        let storage = try RemoteStorage.client(at: XCTUnwrap(URL(string: "https://storage.invalid")),
            wallet: ProtoWallet(rootKey: root))
        return RemoteWallet(storage: storage, identityKey: root, auth: AuthID(identityKey: hex(root)))
    }

    func test_acceptWithARemoteWalletChecksTheSettlementAndAcknowledgesNothing() async throws {
        let stranger = try key(9)
        let f = try await fixture(payTo: stranger.publicKey)
        let log = EventLog()
        let transport = LoggingTransport(log: log, [(200, try listing([f.row]))])
        let client = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver), transport: transport)
        do {
            _ = try await client.accept(f.payment, wallet: remoteWallet(root: f.receiver))
            XCTFail("a payment to another key must be refused")
        } catch MessageBoxPaymentError.settlementFailed {}
        let events = await log.events
        XCTAssertEqual(events, ["listMessages"])
    }

    func test_anEnvelopePaymentWithARemoteWallet() async throws {
        // The client is key 1. A RemoteWallet for key 5 is not the client's identity: refused.
        let other = try key(5)
        let (message, client) = try await listedMessage(
            body: ["message": "paymail", "payment": try recipientPayment()] as [String: Any], log: EventLog())
        do {
            try await client.internalizeEnvelopePayment(of: message, wallet: remoteWallet(root: other))
            XCTFail("another wallet must be refused")
        } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
            XCTAssertEqual(reason, .refused)
        }

        // The client's own RemoteWallet, with a payment to a key it does not hold: the ownership
        // check refuses it before storage is asked, and says it can never be taken.
        let (foreign, foreignClient) = try await listedMessage(
            body: ["message": "paymail", "payment": try recipientPayment(payTo: try key(9).publicKey)] as [String: Any],
            log: EventLog())
        do {
            try await foreignClient.internalizeEnvelopePayment(of: foreign, wallet: remoteWallet(root: try key(1)))
            XCTFail("an output this wallet does not own must be refused")
        } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
            XCTAssertEqual(reason, .unreadable)
        }

        // Accepting through the RemoteWallet overload checks the token first, which also does
        // not pay this wallet.
        let f = try await fixture(envelope: try recipientPayment())
        let acceptLog = EventLog()
        let acceptClient = try MessageBoxClient(host: host, wallet: ProtoWallet(rootKey: f.receiver),
            transport: LoggingTransport(log: acceptLog, [(200, try listing([f.row]))]))
        do {
            _ = try await acceptClient.accept(f.payment, wallet: remoteWallet(root: other))
            XCTFail("must not be acknowledged")
        } catch MessageBoxPaymentError.settlementFailed {}
        let events = await acceptLog.events
        XCTAssertEqual(events, ["listMessages"])

        // A message with no envelope payment asks nothing of the wallet.
        let (plain, plainClient) = try await listedMessage(body: "plain", log: EventLog())
        let internalized = try await plainClient.internalizeEnvelopePayment(of: plain, wallet: remoteWallet(root: other))
        XCTAssertFalse(internalized)
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
        let descriptions = [
            MessageBoxPaymentError.recipientPaymentFailed(.unreadable),
            .recipientPaymentFailed(.refused),
            .recipientPaymentFailed(.unavailable(URLError(.notConnectedToInternet))),
        ].map(\.errorDescription)
        XCTAssertEqual(Set(descriptions).count, 3)
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
