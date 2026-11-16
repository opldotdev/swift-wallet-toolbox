import XCTest
@testable import ToolboxAuth

/// An unsigned refusal says which server refused and why, in one short line, and the log gets the
/// whole call.
final class AuthTransportErrorTests: XCTestCase {
    private let request = AuthRequestContext(method: "POST", host: "wallet.1sat.app", path: "/")

    func test_aRefusalNamesTheHostAndTheServersReason() {
        let error = AuthTransportError.unauthenticatedReply(
            status: 400, body: Array(#"{"status":"error","message":"fee too low"}"#.utf8), request: request
        )
        XCTAssertEqual(
            error.localizedDescription,
            "The server at wallet.1sat.app refused the request (HTTP 400): fee too low"
        )
        XCTAssertEqual(error.serverReason, "fee too low")
    }

    func test_aServerErrorWithoutAReasonSaysToTryLater() {
        let error = AuthTransportError.unauthenticatedReply(
            status: 503, body: Array("<html>unavailable</html>".utf8), request: request
        )
        XCTAssertEqual(
            error.localizedDescription,
            "The server at wallet.1sat.app could not handle the request (HTTP 503). Try again later."
        )
    }

    func test_aRefusalWithoutContextStillGivesTheStatus() {
        let error = AuthTransportError.unauthenticatedReply(status: 403, body: [])
        XCTAssertEqual(error.localizedDescription, "The server refused the request (HTTP 403).")
    }

    func test_debugDescriptionCarriesTheCallStatusAndBody() {
        let error = AuthTransportError.unauthenticatedReply(
            status: 400, body: Array(#"{"message":"fee too low"}"#.utf8), request: request
        )
        let detail = String(reflecting: error)
        XCTAssertTrue(detail.contains("POST wallet.1sat.app/"), detail)
        XCTAssertTrue(detail.contains("HTTP 400"), detail)
        XCTAssertTrue(detail.contains(#"{"message":"fee too low"}"#), detail)
    }

    func test_theRequestContextDoesNotTakePartInEquality() {
        XCTAssertEqual(
            AuthTransportError.unauthenticatedReply(status: 400, body: [1], request: request),
            AuthTransportError.unauthenticatedReply(status: 400, body: [1])
        )
        XCTAssertNotEqual(
            AuthTransportError.unauthenticatedReply(status: 400, body: [1]),
            AuthTransportError.unauthenticatedReply(status: 401, body: [1])
        )
        XCTAssertNotEqual(AuthTransportError.sessionExpired, AuthTransportError.requestMismatch)
        XCTAssertEqual(AuthTransportError.handshakeFailed("x"), AuthTransportError.handshakeFailed("x"))
    }

    func test_aQueryIsNotLoggedVerbatim() {
        let detail = String(reflecting: AuthTransportError.invalidQuery("?token=secret%"))
        XCTAssertFalse(detail.contains("secret"), detail)
    }
}
