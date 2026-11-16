import Foundation
import XCTest
@testable import ToolboxPaymail

/// A paymail failure names the provider and its own short reason; the status alone still decides
/// equality, so callers comparing by status are unaffected.
final class PaymailErrorTests: XCTestCase {

    func test_aFailedLookupNamesTheProviderAndItsReason() {
        let error = PaymailError.httpFailure(statusCode: 500, host: "paymail.example", reason: "database offline.")
        XCTAssertEqual(
            error.localizedDescription,
            "The paymail provider (paymail.example) could not complete the lookup (HTTP 500): database offline. Try again."
        )
    }

    func test_aLookupSaysTryAgainOnlyWhereRetryingCanHelp() {
        for status in [0, 408, 429, 500, 503] {
            XCTAssertTrue(
                PaymailError.httpFailure(statusCode: status).localizedDescription.hasSuffix(" Try again."), "\(status)"
            )
        }
        XCTAssertEqual(
            PaymailError.httpFailure(statusCode: 400, host: "paymail.example", reason: "bad alias").localizedDescription,
            "The paymail provider (paymail.example) could not complete the lookup (HTTP 400): bad alias."
        )
        for status in [401, 403, 410, 422] {
            XCTAssertFalse(
                PaymailError.httpFailure(statusCode: status).localizedDescription.contains("Try again"), "\(status)"
            )
        }
    }

    func test_aFailedDeliveryNamesTheProviderAndItsReason() {
        let error = PaymailError.deliveryFailed(statusCode: 400, host: "paymail.example", reason: "reference expired")
        XCTAssertEqual(
            error.localizedDescription,
            "The paymail provider (paymail.example) did not accept the transaction delivery (HTTP 400): reference expired."
        )
    }

    func test_withoutHostOrReasonTheTextIsUnchangedInShape() {
        XCTAssertEqual(
            PaymailError.deliveryFailed(statusCode: 503).localizedDescription,
            "The paymail provider did not accept the transaction delivery (HTTP 503)."
        )
        XCTAssertEqual(
            PaymailError.httpFailure(statusCode: 404, host: "paymail.example", reason: "nope").localizedDescription,
            "The paymail provider could not find that recipient or service. Check the address."
        )
    }

    func test_hostAndReasonDoNotTakePartInEquality() {
        XCTAssertEqual(
            PaymailError.httpFailure(statusCode: 502, host: "a.example", reason: "x"),
            PaymailError.httpFailure(statusCode: 502)
        )
        XCTAssertEqual(
            PaymailError.deliveryFailed(statusCode: 400, host: "a.example", reason: "x"),
            PaymailError.deliveryFailed(statusCode: 400)
        )
        XCTAssertNotEqual(PaymailError.httpFailure(statusCode: 502), PaymailError.deliveryFailed(statusCode: 502))
        XCTAssertNotEqual(PaymailError.httpFailure(statusCode: 502), PaymailError.httpFailure(statusCode: 503))
    }
}
