import XCTest
import Foundation
import BSVCore
import BSVKeys
import BSVWallet
import ToolboxAuth
@testable import ToolboxWallet

private actor MessageBoxTransport: AuthenticatedTransport {
    let response: AuthenticatedResponse
    var requests: [(String, String, String?, [UInt8]?)] = []
    init(_ json: String, status: Int = 200) {
        response = AuthenticatedResponse(statusCode: status, headers: [:], body: Array(json.utf8))
    }
    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        requests.append((method, path, query, body))
        return response
    }
}

final class MessageBoxTests: XCTestCase, @unchecked Sendable {
    private func key(_ value: UInt8) throws -> PrivateKey { try PrivateKey(Array(repeating: 0, count: 31) + [value]) }

    func test_paymentIsEncryptedAndRecipientCanDecryptPortableToken() async throws {
        let sender = try key(1), receiver = try key(2)
        let transport = MessageBoxTransport(#"{"status":"success"}"#)
        let client = try MessageBoxClient(host: URL(string: "https://messages.example/api")!,
            wallet: ProtoWallet(rootKey: sender), transport: transport)
        let token = MessageBoxPaymentToken(derivationPrefix: "cHJlZml4", derivationSuffix: "c3VmZml4",
            transaction: [1, 1, 1, 1, 255], amount: 123, outputIndex: 2)
        let envelope = try await client.preparePayment(to: receiver.publicKey, token: token)
        // Generated with the live ts-stack SDK ProtoWallet (sender=1, receiver=2),
        // using MessageBoxClient.generateMessageId's JSON-string input contract.
        XCTAssertEqual(envelope.messageId, "2c14b9ed5aa1df1f385b544e479d5a042d9cd5f7da8bbd208cb4b1e0f4fc87d1")
        let again = try await client.preparePayment(to: receiver.publicKey, token: token)
        XCTAssertEqual(envelope.messageId, again.messageId)
        XCTAssertNotEqual(envelope.body, again.body)
        let encrypted = try JSONDecoder().decode([String: String].self, from: Data(envelope.body.utf8))
        let ciphertext = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(encrypted["encryptedMessage"])))
        let plaintext = try await ProtoWallet(rootKey: receiver).decrypt(WalletDecryptRequest(
            protocolID: WalletProtocolID(securityLevel: .everyApp, name: "messagebox"),
            keyID: WalletKeyID("1"), counterparty: .publicKey(sender.publicKey), ciphertext: Array(ciphertext)))
        let decoded = try JSONDecoder().decode(MessageBoxPaymentToken.self, from: Data(plaintext.plaintext))
        XCTAssertEqual(decoded.transaction, token.transaction)
        XCTAssertEqual(decoded.outputIndex, 2)
        XCTAssertEqual(decoded.amount, 123)
        let typescriptCiphertext = "eTYnCmRnk+6vDbG+27aEpy13aqDjxWS6hs5gEgovF755J0gTPC4oVj5rscLHbtYWVWVc+8gSTndneQy26pimAMRsqOvm1Bh38rSMR+qjGpugrATaJEaaWNZBiJYffNQH08r4by9O22dWCeIe+kQ64gByqjVrREP+sQ9gpNJSQ+5KTvwPuce/py84+aIf5zNM6I9HI+dg8/YGRkCmMCDzgcSL0qkgSfqEr/XWtn/rDdTgGRh4zB2QB2eSMjd3"
        let crossLanguage = try await ProtoWallet(rootKey: receiver).decrypt(WalletDecryptRequest(
            protocolID: WalletProtocolID(securityLevel: .everyApp, name: "messagebox"),
            keyID: WalletKeyID("1"), counterparty: .publicKey(sender.publicKey),
            ciphertext: Array(XCTUnwrap(Data(base64Encoded: typescriptCiphertext)))))
        XCTAssertEqual(crossLanguage.plaintext, plaintext.plaintext)
        try await client.deliver(envelope)
        let requests = await transport.requests
        XCTAssertEqual(requests.first?.1, "/api/sendMessage")
        let request = try JSONSerialization.jsonObject(with: Data(XCTUnwrap(requests.first?.3))) as? [String: Any]
        let message = try XCTUnwrap(request?["message"] as? [String: Any])
        XCTAssertEqual(message["messageBox"] as? String, "payment_inbox")
        XCTAssertEqual(message["recipient"] as? String, Hex.encode(receiver.publicKey.compressedBytes))
        XCTAssertFalse(String(decoding: try XCTUnwrap(requests.first?.3), as: UTF8.self).contains("derivationPrefix"))
    }

    func test_quoteUsesConfiguredHostPathAndRecipient() async throws {
        let recipient = try key(2).publicKey
        let transport = MessageBoxTransport(#"{"status":"success","quote":{"recipientFee":0,"deliveryFee":0}}"#)
        let client = try MessageBoxClient(host: URL(string: "https://custom.example/mb/")!, wallet: ProtoWallet(rootKey: key(1)), transport: transport)
        try await client.requireFreeDelivery(to: recipient)
        let requests = await transport.requests
        XCTAssertEqual(requests.first?.0, "GET")
        XCTAssertEqual(requests.first?.1, "/mb/permissions/quote")
        XCTAssertTrue(requests.first?.2?.contains(Hex.encode(recipient.compressedBytes)) == true)
    }

    func test_blockedPaidAndMalformedQuotesAreRefused() async throws {
        for json in [
            #"{"quote":{"recipientFee":-1,"deliveryFee":0}}"#,
            #"{"quote":{"recipientFee":0,"deliveryFee":5}}"#,
            #"{"quote":{"recipientFee":-2,"deliveryFee":0}}"#,
            #"{"quote":{"recipientFee":false,"deliveryFee":0}}"#,
            #"{"quote":{"recipientFee":0.5,"deliveryFee":0}}"#,
            #"{"quote":{}}"#
        ] {
            let client = try MessageBoxClient(host: URL(string: "https://custom.example")!, wallet: ProtoWallet(rootKey: key(1)), transport: MessageBoxTransport(json))
            do { try await client.requireFreeDelivery(to: key(2).publicKey); XCTFail("Quote should fail") }
            catch is MessageBoxError {}
        }
    }

    func test_errorResponseCannotBeReportedAsDelivered() async throws {
        for json in [#"{"status":"error"}"#, #"{}"#] {
            let client = try MessageBoxClient(host: URL(string: "https://custom.example")!, wallet: ProtoWallet(rootKey: key(1)), transport: MessageBoxTransport(json))
            do { try await client.deliver(MessageBoxEnvelope(recipient: "recipient", messageId: "id", body: "encrypted")); XCTFail("Delivery should fail") }
            catch is MessageBoxError {}
        }
    }

    func test_unsafeServerURLsAreRefused() throws {
        for host in ["http://example.com", "https://user@example.com", "https://example.com?q=x", "https://example.com#x"] {
            XCTAssertThrowsError(try MessageBoxClient(host: URL(string: host)!, wallet: ProtoWallet(rootKey: key(1))))
        }
    }

    func test_liveReadOnlyAuthenticatedQuote() async throws {
        guard let host = ProcessInfo.processInfo.environment["TEST_RUNNER_LIVE_MESSAGEBOX_URL"] else {
            throw XCTSkip("Opt-in read-only MessageBox check")
        }
        let randomKey = try PrivateKey((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let client = try MessageBoxClient(host: XCTUnwrap(URL(string: host)), wallet: ProtoWallet(rootKey: randomKey))
        // No message, registration, transaction, or payment is submitted.
        try await client.requireFreeDelivery(to: randomKey.publicKey)
    }
}
