import Foundation
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

    func test_aURLErrorIsLoggedWithoutItsQuery() throws {
        let url = try XCTUnwrap(URL(string: "https://wallet.example/api/x?auth_token=SECRET#frag"))
        let error = URLError(.timedOut, userInfo: [
            "NSErrorFailingURLKey": url,
            "NSErrorFailingURLStringKey": url.absoluteString,
            NSLocalizedDescriptionKey: "The request to https://wallet.example/api/x?auth_token=SECRET timed out.",
        ])
        let logged = ErrorDetail.describe(error)
        XCTAssertFalse(logged.contains("SECRET"), logged)
        XCTAssertFalse(logged.contains("auth_token"), logged)
        XCTAssertTrue(logged.contains(NSURLErrorDomain), logged)
        XCTAssertTrue(logged.contains("\(URLError.Code.timedOut.rawValue)"), logged)
        XCTAssertTrue(logged.contains("wallet.example/api/x"), logged)
    }

    func test_anNSErrorAndItsUnderlyingErrorsAreLoggedWithoutQueries() {
        let inner = NSError(domain: "kCFErrorDomainCFNetwork", code: -1001, userInfo: [
            "NSErrorFailingURLStringKey": "https://wallet.example/inner?auth_token=SECRET",
        ])
        let middle = NSError(domain: NSCocoaErrorDomain, code: 1, userInfo: [NSUnderlyingErrorKey: inner])
        let outer = NSError(domain: NSURLErrorDomain, code: -1001, userInfo: [
            "NSErrorFailingURLStringKey": "https://wallet.example/outer?auth_token=SECRET",
            NSUnderlyingErrorKey: middle,
        ])
        let logged = ErrorDetail.describe(outer)
        XCTAssertFalse(logged.contains("SECRET"), logged)
        XCTAssertTrue(logged.contains("wallet.example/outer"), logged)
        XCTAssertTrue(logged.contains("wallet.example/inner"), logged)
        XCTAssertTrue(logged.contains("kCFErrorDomainCFNetwork -1001"), logged)
    }

    func test_otherErrorsAreLoggedAsTheyReflect() {
        XCTAssertEqual(
            ErrorDetail.describe(WireError.insufficientFunds("need 500 more")),
            "WireError WERR_INSUFFICIENT_FUNDS: need 500 more"
        )
        let plain = NSError(domain: "dev.opl.test", code: 7)
        XCTAssertEqual(ErrorDetail.describe(plain), String(reflecting: plain))
    }

    func test_anErrorWrappingAURLErrorIsLoggedWithoutItsQuery() throws {
        struct Wrapper: Error { let underlying: any Error }
        enum Wrapped: Error { case failed(any Error) }
        let url = try XCTUnwrap(URL(string: "https://wallet.example/api/x?auth_token=SECRET"))
        let urlError = URLError(.timedOut, userInfo: [
            "NSErrorFailingURLKey": url,
            "NSErrorFailingURLStringKey": url.absoluteString,
            NSLocalizedDescriptionKey: "The request to \(url.absoluteString) timed out.",
        ])
        let ns = NSError(domain: "dev.opl.test", code: 3, userInfo: [
            NSLocalizedDescriptionKey: "GET \(url.absoluteString) failed",
        ])
        for error in [Wrapper(underlying: urlError), Wrapped.failed(urlError), Wrapper(underlying: ns)] as [any Error] {
            let logged = ErrorDetail.describe(error)
            XCTAssertFalse(logged.contains("SECRET"), logged)
            XCTAssertFalse(logged.contains("auth_token"), logged)
        }
    }

    func test_anUnderlyingSwiftErrorIsLoggedWithoutItsQuery() {
        struct Inner: Error, CustomDebugStringConvertible {
            var debugDescription: String { "Inner: GET https://wallet.example/inner?auth_token=SECRET" }
        }
        let outer = NSError(domain: NSURLErrorDomain, code: -1001, userInfo: [NSUnderlyingErrorKey: Inner()])
        let logged = ErrorDetail.describe(outer)
        XCTAssertFalse(logged.contains("SECRET"), logged)
        XCTAssertTrue(logged.contains("underlying: Inner: GET https://wallet.example/inner"), logged)
    }

    func test_withoutQueriesCutsOnlyURLs() {
        XCTAssertEqual(
            ErrorDetail.withoutQueries("GET https://h.example/p?token=x failed? yes https://h.example/q#f h.example/r?a=b"),
            "GET https://h.example/p failed? yes https://h.example/q h.example/r"
        )
    }

    func test_withoutQueriesEndsTheCutWhereTheURLEnds() {
        XCTAssertEqual(
            ErrorDetail.withoutQueries(#"{"url":"https://h/p?x=1","txid":"abc"}"#),
            #"{"url":"https://h/p","txid":"abc"}"#
        )
        XCTAssertEqual(
            ErrorDetail.withoutQueries(#"{"a":"https://h/p?x=1","b":"https://h/q?y=2","n":"why?"}"#),
            #"{"a":"https://h/p","b":"https://h/q","n":"why?"}"#
        )
        XCTAssertEqual(ErrorDetail.withoutQueries("see https://h/p?ids=a,b&token=SECRET now"), "see https://h/p now")
        XCTAssertEqual(ErrorDetail.withoutQueries("(https://h/p?x=1), next"), "(https://h/p), next")
        XCTAssertEqual(
            ErrorDetail.withoutQueries("UserInfo={NSErrorFailingURLKey=https://w.example/x?auth_token=SECRET}"),
            "UserInfo={NSErrorFailingURLKey=https://w.example/x}"
        )
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
