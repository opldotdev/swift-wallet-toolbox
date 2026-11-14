import XCTest
import Foundation
import BSVCore
import BSVKeys
import BSVWallet
import ToolboxAuth
@testable import ToolboxWallet

/// Answers every request with one fixed failure, as a gate in front of a server's auth does.
private struct RefusingTransport: AuthenticatedTransport {
    let error: AuthTransportError
    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        throw error
    }
}

/// Answers every request with one signed status and body.
private struct StatusTransport: AuthenticatedTransport {
    let status: Int
    let body: String
    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        AuthenticatedResponse(statusCode: status, headers: [:], body: Array(self.body.utf8))
    }
}

/// A refusal is reported by what the server said, not as a server that could not be verified.
final class MessageBoxRefusalTests: XCTestCase {
    private let host = URL(string: "https://messagebox.example")!
    private func wallet() throws -> ProtoWallet {
        ProtoWallet(rootKey: try PrivateKey(Array(repeating: 0, count: 31) + [1]))
    }
    private func envelope() -> MessageBoxEnvelope {
        MessageBoxEnvelope(recipient: String(repeating: "02", count: 33), messageId: "m", body: "{}")
    }
    private func gate(_ status: Int, _ body: String) -> RefusingTransport {
        RefusingTransport(error: .unauthenticatedReply(status: status, body: Array(body.utf8)))
    }

    func test_theAccountGateIsReportedAsTheRecipientHavingNoAccount() async throws {
        let client = try MessageBoxClient(host: host, wallet: wallet(), transport: gate(403,
            #"{"status":"error","code":"ERR_ACCOUNT_REQUIRED","description":"Recipient has no account on this host"}"#))
        do {
            try await client.deliver(envelope())
            XCTFail("a refused delivery must throw")
        } catch let error as MessageBoxError {
            XCTAssertEqual(error, .recipientAccountRequired)
            XCTAssertTrue(error.isRefusal)
            XCTAssertFalse(error.localizedDescription.contains("storage"))
        }
    }

    func test_anotherCodeKeepsItsStatusAndCode() async throws {
        let client = try MessageBoxClient(host: host, wallet: wallet(),
            transport: gate(400, #"{"status":"error","code":"ERR_INVALID_BODY"}"#))
        do {
            try await client.deliver(envelope())
            XCTFail("a refused delivery must throw")
        } catch let error as MessageBoxError {
            XCTAssertEqual(error, .refused(status: 400, code: "ERR_INVALID_BODY"))
            XCTAssertTrue(error.isRefusal)
        }
    }

    func test_aServerErrorDecidesNothing() async throws {
        let client = try MessageBoxClient(host: host, wallet: wallet(), transport: gate(502, "<html>bad gateway</html>"))
        do {
            try await client.deliver(envelope())
            XCTFail("a failed delivery must throw")
        } catch let error as MessageBoxError {
            XCTAssertEqual(error, .httpStatus(502))
            XCTAssertFalse(error.isRefusal, "a 5xx may have stored the message")
        }
    }

    func test_aSignedErrorReplyIsReadTheSameWay() async throws {
        let client = try MessageBoxClient(host: host, wallet: wallet(),
            transport: StatusTransport(status: 500, body: #"{"status":"error","code":"ERR_INTERNAL"}"#))
        do {
            _ = try await client.listMessages(messageBox: "payment_inbox")
            XCTFail("a failed listing must throw")
        } catch let error as MessageBoxError {
            XCTAssertEqual(error, .refused(status: 500, code: "ERR_INTERNAL"))
            XCTAssertFalse(error.isRefusal)
        }
    }

    func test_aCodeThatIsNotAnIdentifierIsNotShown() {
        XCTAssertEqual(MessageBoxClient.refusal(status: 403, body: Array(#"{"code":"see https://x.example now"}"#.utf8)),
            .httpStatus(403))
        XCTAssertEqual(MessageBoxClient.refusal(status: 403, body: []), .httpStatus(403))
        XCTAssertTrue(MessageBoxError.httpStatus(404).isRefusal)
        XCTAssertFalse(MessageBoxError.httpStatus(429).isRefusal)
        XCTAssertFalse(MessageBoxError.httpStatus(408).isRefusal)
    }

    func test_aBinaryPostStillReportsTheBareStatus() async throws {
        let client = try MessageBoxClient(host: host, wallet: wallet(),
            transport: gate(403, #"{"code":"ERR_ACCOUNT_REQUIRED"}"#))
        do {
            _ = try await client.post("sendMessage", contentType: "application/cbor", body: [0xa0])
            XCTFail("a refused post must throw")
        } catch MessageBoxError.httpStatus(403) {}
    }
}
