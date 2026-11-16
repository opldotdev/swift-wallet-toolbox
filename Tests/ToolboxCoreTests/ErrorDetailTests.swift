import XCTest
@testable import ToolboxCore

/// The server's own short reason is what a user is shown; everything else is for the log.
final class ErrorDetailTests: XCTestCase {

    func test_readsTheReasonFromCommonJSONShapes() {
        XCTAssertEqual(ErrorDetail.serverReason(Array(#"{"message":"fee too low"}"#.utf8)), "fee too low")
        XCTAssertEqual(
            ErrorDetail.serverReason(Array(#"{"code":"ERR_X","description":"paid enable is off"}"#.utf8)),
            "paid enable is off"
        )
        XCTAssertEqual(ErrorDetail.serverReason(Array(#"{"error":"Bad Request"}"#.utf8)), "Bad Request")
        XCTAssertEqual(
            ErrorDetail.serverReason(Array(#"{"error":{"message":"nested reason"}}"#.utf8)),
            "nested reason"
        )
        XCTAssertEqual(ErrorDetail.serverReason(Array(#"{"code":"ERR_ONLY_CODE"}"#.utf8)), "ERR_ONLY_CODE")
    }

    func test_readsShortPlainTextAndRefusesMarkupAndEmptyBodies() {
        XCTAssertEqual(ErrorDetail.serverReason(Array("  Payload too large\n".utf8)), "Payload too large")
        XCTAssertNil(ErrorDetail.serverReason(Array("<html><body>502</body></html>".utf8)))
        XCTAssertNil(ErrorDetail.serverReason([]))
        XCTAssertNil(ErrorDetail.serverReason(Array(#"{"status":"error"}"#.utf8)))
        XCTAssertNil(ErrorDetail.serverReason(Array(String(repeating: "x", count: 400).utf8)))
    }

    func test_aLongReasonIsCutToOneShortLine() {
        let long = String(repeating: "word ", count: 60)
        let reason = ErrorDetail.serverReason(Array("{\"message\":\"\(long)\\nsecond line\"}".utf8))
        XCTAssertNotNil(reason)
        XCTAssertLessThanOrEqual(reason?.count ?? .max, ErrorDetail.reasonLimit)
        XCTAssertFalse(reason?.contains("\n") ?? true)
        XCTAssertTrue(reason?.hasSuffix("…") ?? false)
    }

    func test_bodyPreviewIsBoundedAndNamesTheFullSize() {
        XCTAssertEqual(ErrorDetail.bodyPreview([]), "<empty>")
        XCTAssertEqual(ErrorDetail.bodyPreview(Array("short".utf8)), "short")
        let preview = ErrorDetail.bodyPreview(Array(repeating: UInt8(ascii: "a"), count: 2_500))
        XCTAssertTrue(preview.hasSuffix("… (2500 bytes)"))
        XCTAssertTrue(preview.hasPrefix(String(repeating: "a", count: 2_000)))
    }

    func test_hostPathDropsTheSchemeAndQuery() throws {
        let url = try XCTUnwrap(URL(string: "https://wallet.1sat.app:8443/api/x?token=secret"))
        XCTAssertEqual(ErrorDetail.hostPath(url), "wallet.1sat.app:8443/api/x")
        XCTAssertEqual(ErrorDetail.hostPath(host: "h", path: "/p?q=1"), "h/p")
        XCTAssertEqual(ErrorDetail.hostPath(host: "h", path: ""), "h/")
    }

    func test_wireErrorDebugDescriptionCarriesNameAndMessage() {
        XCTAssertEqual(
            String(reflecting: WireError.insufficientFunds("need 500 more")),
            "WireError WERR_INSUFFICIENT_FUNDS: need 500 more"
        )
        XCTAssertEqual(
            String(reflecting: WireError.invalidParameter(name: "satoshis", message: "bad")),
            "WireError WERR_INVALID_PARAMETER (parameter satoshis): bad"
        )
    }
}
