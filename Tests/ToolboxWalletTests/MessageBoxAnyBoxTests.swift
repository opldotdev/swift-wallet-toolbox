import XCTest
import Foundation
import BSVCore
import BSVKeys
import BSVWallet
import ToolboxAuth
@testable import ToolboxWallet

/// Replies with queued responses in order, recording every request.
private actor ScriptedTransport: AuthenticatedTransport {
    var responses: [AuthenticatedResponse]
    var requests: [(method: String, path: String, headers: [String: String], body: [UInt8]?)] = []
    init(_ bodies: [String], status: Int = 200) {
        responses = bodies.map { AuthenticatedResponse(statusCode: status, headers: [:], body: Array($0.utf8)) }
    }
    init(raw: [UInt8], status: Int) {
        responses = [AuthenticatedResponse(statusCode: status, headers: [:], body: raw)]
    }
    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        requests.append((method, path, headers, body))
        return responses.removeFirst()
    }
}

final class MessageBoxAnyBoxTests: XCTestCase, @unchecked Sendable {
    private func key(_ value: UInt8) throws -> PrivateKey { try PrivateKey(Array(repeating: 0, count: 31) + [value]) }
    private func json(_ bytes: [UInt8]?) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(XCTUnwrap(bytes))) as? [String: Any])
    }

    func test_aMessageForAnyBoxIsEncryptedAndSentToThatBox() async throws {
        let sender = try key(1), receiver = try key(2)
        let transport = ScriptedTransport([#"{"status":"success"}"#])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: sender), transport: transport)
        let envelope = try await client.prepareMessage(to: receiver.publicKey, messageBox: "transaction-delivery", body: "hello")
        XCTAssertEqual(envelope.messageBox, "transaction-delivery")
        try await client.deliver(envelope)
        let sent = await transport.requests
        let request = try json(sent.first?.body)
        let message = try XCTUnwrap(request["message"] as? [String: Any])
        XCTAssertEqual(message["messageBox"] as? String, "transaction-delivery")
        XCTAssertEqual(message["messageId"] as? String, envelope.messageId)

        // The recipient lists it and reads the plaintext back.
        let listed = MessageBoxMessage(messageId: envelope.messageId, body: envelope.body,
            sender: Hex.encode(sender.publicKey.compressedBytes))
        let recipient = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: receiver), transport: ScriptedTransport([]))
        let opened = try await recipient.open(listed)
        XCTAssertEqual(opened, "hello")
    }

    func test_thePaymentInboxStillUsesTheSameMessageIDAsBefore() async throws {
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: ScriptedTransport([]))
        let token = MessageBoxPaymentToken(derivationPrefix: "cHJlZml4", derivationSuffix: "c3VmZml4",
            transaction: [1, 1, 1, 1, 255], amount: 123, outputIndex: 2)
        let envelope = try await client.preparePayment(to: key(2).publicKey, token: token)
        XCTAssertEqual(envelope.messageBox, "payment_inbox")
        XCTAssertEqual(envelope.messageId, "2c14b9ed5aa1df1f385b544e479d5a042d9cd5f7da8bbd208cb4b1e0f4fc87d1")
    }

    func test_listingFollowsPagesAndAcknowledgeSendsUniqueIDs() async throws {
        let sender = Hex.encode(try key(3).publicKey.compressedBytes)
        let transport = ScriptedTransport([
            #"{"status":"success","hasMore":true,"messages":[{"messageId":"a","body":"one","sender":"\#(sender)","created_at":"2026-11-13T00:00:00Z"}]}"#,
            #"{"status":"success","messages":[{"messageId":"b","body":{"x":1},"sender":"\#(sender)"}]}"#,
            #"{"status":"success"}"#,
        ])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example/base")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listing = try await client.listMessages(messageBox: "transaction-delivery", pageSize: 1)
        XCTAssertFalse(listing.truncated)
        let messages = listing.messages
        XCTAssertEqual(messages.map(\.messageId), ["a", "b"])
        XCTAssertEqual(messages[1].body, #"{"x":1}"#)
        XCTAssertEqual(messages[0].createdAt, "2026-11-13T00:00:00Z")
        XCTAssertEqual(listing.nextOffset, 2)
        try await client.acknowledge(messageIds: ["a", "b", "a"])

        let requests = await transport.requests
        XCTAssertEqual(requests.map(\.path), ["/base/listMessages", "/base/listMessages", "/base/acknowledgeMessage"])
        XCTAssertEqual(try json(requests[0].body)["offset"] as? Int, 0)
        XCTAssertEqual(try json(requests[1].body)["offset"] as? Int, 1)
        XCTAssertEqual(try json(requests[0].body)["messageBox"] as? String, "transaction-delivery")
        XCTAssertEqual(try json(requests[2].body)["messageIds"] as? [String], ["a", "b"])
    }

    func test_anEmptyPageWithMoreToComeDoesNotStopTheListing() async throws {
        let sender = Hex.encode(try key(3).publicKey.compressedBytes)
        let transport = ScriptedTransport([
            #"{"status":"success","hasMore":true,"messages":[{"messageId":"a","body":"one","sender":"\#(sender)"}]}"#,
            #"{"status":"success","hasMore":true,"messages":[]}"#,
            #"{"status":"success","hasMore":false,"messages":[{"messageId":"c","body":"three","sender":"\#(sender)"}]}"#,
        ])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listing = try await client.listMessages(messageBox: "inbox", pageSize: 2)
        XCTAssertEqual(listing.messages.map(\.messageId), ["a", "c"])
        XCTAssertFalse(listing.truncated)
        let requests = await transport.requests
        let offsets = try requests.map { try json($0.body)["offset"] as? Int }
        XCTAssertEqual(offsets, [0, 1, 3])
    }

    func test_anAdvancingServerCursorIsFollowed() async throws {
        let sender = Hex.encode(try key(3).publicKey.compressedBytes)
        let transport = ScriptedTransport([
            #"{"status":"success","hasMore":true,"nextOffset":7,"messages":[{"messageId":"a","body":"one","sender":"\#(sender)"}]}"#,
            #"{"status":"success","hasMore":true,"nextOffset":7,"messages":[{"messageId":"b","body":"two","sender":"\#(sender)"}]}"#,
            #"{"status":"success","hasMore":true,"nextOffset":true,"messages":[{"messageId":"c","body":"three","sender":"\#(sender)"}]}"#,
            #"{"status":"success","messages":[]}"#,
        ])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listing = try await client.listMessages(messageBox: "inbox", pageSize: 5)
        XCTAssertEqual(listing.messages.map(\.messageId), ["a", "b", "c"])
        XCTAssertFalse(listing.truncated)
        XCTAssertEqual(listing.nextOffset, 9)
        // 7 is taken; a repeated 7 does not move forward, so the count is used; a boolean cursor is ignored.
        let requests = await transport.requests
        let offsets = try requests.map { try json($0.body)["offset"] as? Int }
        XCTAssertEqual(offsets, [0, 7, 8, 9])
    }

    func test_emptyPagesThatNeverEndStopAtTheCapAsTruncated() async throws {
        let transport = ScriptedTransport(Array(repeating: #"{"status":"success","hasMore":true,"messages":[]}"#, count: 3))
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listing = try await client.listMessages(messageBox: "inbox", pageSize: 4, maxPages: 3)
        // The next listing goes on from where this one would have asked next.
        XCTAssertEqual(listing, MessageBoxListing(messages: [], truncated: true, nextOffset: 12))
        XCTAssertFalse(listing.isComplete)
        let requests = await transport.requests
        let offsets = try requests.map { try json($0.body)["offset"] as? Int }
        XCTAssertEqual(offsets, [0, 4, 8])
    }

    func test_theLastAllowedPageWithMoreReturnsItsRowsAsTruncated() async throws {
        let sender = Hex.encode(try key(3).publicKey.compressedBytes)
        let transport = ScriptedTransport([
            #"{"status":"success","hasMore":true,"messages":[{"messageId":"a","body":"one","sender":"\#(sender)"}]}"#,
            #"{"status":"success","hasMore":true,"messages":[{"messageId":"b","body":"two","sender":"\#(sender)"}]}"#,
        ])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listing = try await client.listMessages(messageBox: "inbox", pageSize: 1, maxPages: 2)
        XCTAssertEqual(listing.messages.map(\.messageId), ["a", "b"])
        XCTAssertTrue(listing.truncated)
        XCTAssertEqual(listing.nextOffset, 2)
        // Exactly the allowed pages are asked for, never a third.
        let count = await transport.requests.count
        XCTAssertEqual(count, 2)
    }

    func test_aListingThatEndsUnderThePageCapIsNotTruncated() async throws {
        let sender = Hex.encode(try key(3).publicKey.compressedBytes)
        let transport = ScriptedTransport([
            #"{"status":"success","hasMore":true,"messages":[{"messageId":"a","body":"one","sender":"\#(sender)"}]}"#,
            #"{"status":"success","hasMore":false,"messages":[{"messageId":"b","body":"two","sender":"\#(sender)"}]}"#,
        ])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listing = try await client.listMessages(messageBox: "inbox", pageSize: 1, maxPages: 3)
        XCTAssertEqual(listing.messages.map(\.messageId), ["a", "b"])
        XCTAssertFalse(listing.truncated)
    }

    func test_aListingStartsAtTheGivenOffsetAndReportsWhereToGoOn() async throws {
        let sender = Hex.encode(try key(3).publicKey.compressedBytes)
        let transport = ScriptedTransport([
            #"{"status":"success","hasMore":true,"messages":[{"messageId":"f","body":"six","sender":"\#(sender)"}]}"#,
            #"{"status":"success","hasMore":true,"messages":[{"messageId":"g","body":"seven","sender":"\#(sender)"}]}"#,
        ])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listing = try await client.listMessages(messageBox: "inbox", pageSize: 1, maxPages: 2, offset: 5)
        XCTAssertEqual(listing.messages.map(\.messageId), ["f", "g"])
        XCTAssertTrue(listing.truncated)
        XCTAssertEqual(listing.nextOffset, 7)
        let requests = await transport.requests
        let offsets = try requests.map { try json($0.body)["offset"] as? Int }
        XCTAssertEqual(offsets, [5, 6])
    }

    func test_aNegativeOffsetIsRefusedBeforeAnyRequest() async throws {
        let transport = ScriptedTransport([])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        do { _ = try await client.listMessages(messageBox: "inbox", offset: -1); XCTFail("negative offset") }
        catch MessageBoxError.invalidMessage {}
        let count = await transport.requests.count
        XCTAssertEqual(count, 0)
    }

    func test_malformedListingsAreRefused() async throws {
        for body in [
            #"{"status":"success"}"#,
            #"{"status":"success","messages":[{"messageId":"a","body":"x","sender":"zz"}]}"#,
            #"{"status":"success","messages":[{"body":"x","sender":"02"}]}"#,
            #"{"status":"error","messages":[]}"#,
        ] {
            let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
                wallet: ProtoWallet(rootKey: key(1)), transport: ScriptedTransport([body]))
            do { _ = try await client.listMessages(messageBox: "inbox"); XCTFail("should refuse \(body)") }
            catch is MessageBoxError {}
        }
    }

    func test_aListingCanSkipRowsItCannotReadAndSaysItIsIncomplete() async throws {
        let sender = Hex.encode(try key(3).publicKey.compressedBytes)
        let first = #"{"status":"success","hasMore":true,"messages":[{"messageId":"a","body":"one","sender":"\#(sender)"},{"messageId":"b","body":"x","sender":"zz"},"junk"]}"#
        let second = #"{"status":"success","messages":[{"body":"x","sender":"\#(sender)"},{"messageId":"c","body":"three","sender":"\#(sender)"}]}"#

        // By default one such row fails the whole listing.
        let strict = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: ScriptedTransport([first]))
        do { _ = try await strict.listMessages(messageBox: "inbox", pageSize: 3); XCTFail("must refuse") }
        catch MessageBoxError.invalidResponse {}

        let transport = ScriptedTransport([first, second])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let listing = try await client.listMessages(messageBox: "inbox", pageSize: 3, skipMalformed: true)
        XCTAssertEqual(listing.messages.map(\.messageId), ["a", "c"])
        XCTAssertEqual(listing.skipped, 3)
        // Every page was read, but rows were left out: not truncated, and not complete either.
        XCTAssertFalse(listing.truncated)
        XCTAssertFalse(listing.isComplete)
        // Skipped rows are still on the server, so they count toward where to list on from.
        XCTAssertEqual(listing.nextOffset, 5)
        let requests = await transport.requests
        let offsets = try requests.map { try json($0.body)["offset"] as? Int }
        XCTAssertEqual(offsets, [0, 3])

        // A clean listing with skipping on is complete.
        let clean = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: ScriptedTransport([second.replacingOccurrences(
                of: #"{"body":"x","sender":"\#(sender)"},"#, with: "")]))
        let whole = try await clean.listMessages(messageBox: "inbox", skipMalformed: true)
        XCTAssertEqual(whole, MessageBoxListing(messages: whole.messages, truncated: false, nextOffset: 1, skipped: 0))
        XCTAssertEqual(whole.messages.map(\.messageId), ["c"])
        XCTAssertTrue(whole.isComplete)
    }

    func test_boxNamesAndAcknowledgementsAreChecked() async throws {
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: ScriptedTransport([]))
        for box in ["", "  ", String(repeating: "b", count: 65), "a\u{0007}b"] {
            do { _ = try await client.listMessages(messageBox: box); XCTFail("box \(box)") } catch is MessageBoxError {}
        }
        do { try await client.acknowledge(messageIds: []); XCTFail("empty ack") } catch is MessageBoxError {}
    }

    func test_binaryPostReturnsTheRawBodyAndRefusesErrors() async throws {
        let transport = ScriptedTransport(raw: [0xa1, 0x00], status: 200)
        let client = try MessageBoxClient(host: URL(string: "https://mb.example/x")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        let response = try await client.post("/sendMessage", contentType: "application/cbor", body: [0xa0])
        XCTAssertEqual(response, [0xa1, 0x00])
        let recorded = await transport.requests
        let request = try XCTUnwrap(recorded.first)
        XCTAssertEqual(request.path, "/x/sendMessage")
        XCTAssertEqual(request.headers["Content-Type"], "application/cbor")
        XCTAssertEqual(request.body, [0xa0])

        let failing = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: ScriptedTransport(raw: [], status: 500))
        do { _ = try await failing.post("listMessages", contentType: "application/cbor", body: []); XCTFail() }
        catch MessageBoxError.httpStatus(500) {}
        do { _ = try await failing.post("../x", contentType: "application/cbor", body: []); XCTFail() }
        catch MessageBoxError.invalidMessage {}
    }

    func test_storedEnvelopesForOtherBoxesDecode() throws {
        let envelope = MessageBoxEnvelope(recipient: "r", messageId: "m", body: "b", messageBox: "transaction-delivery")
        let data = try JSONEncoder().encode(envelope)
        XCTAssertEqual(try JSONDecoder().decode(MessageBoxEnvelope.self, from: data), envelope)
        let empty = #"{"recipient":"r","messageId":"m","body":"b","messageBox":""}"#
        XCTAssertThrowsError(try JSONDecoder().decode(MessageBoxEnvelope.self, from: Data(empty.utf8)))
    }

    func test_quoteAsksAboutTheNamedBox() async throws {
        let transport = ScriptedTransport([#"{"status":"success","quote":{"recipientFee":0,"deliveryFee":0}}"#])
        let client = try MessageBoxClient(host: URL(string: "https://mb.example")!,
            wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        try await client.requireFreeDelivery(to: key(2).publicKey, messageBox: "transaction-delivery")
        let path = await transport.requests.first?.path
        XCTAssertEqual(path, "/permissions/quote")
    }
}
