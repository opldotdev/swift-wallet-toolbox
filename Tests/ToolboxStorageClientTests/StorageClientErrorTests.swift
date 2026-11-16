import Foundation
import XCTest
@testable import ToolboxStorageClient

/// A storage failure says which call failed and whether trying again can help.
final class StorageClientErrorTests: XCTestCase {

    func test_theDescriptionNamesTheCall() {
        XCTAssertEqual(
            StorageClientError.httpFailure(method: "createAction", statusCode: 400).localizedDescription,
            "The wallet storage server refused createAction (HTTP 400)."
        )
        XCTAssertEqual(
            StorageClientError.httpFailure(method: "createAction", statusCode: 503).localizedDescription,
            "The wallet storage server could not handle createAction (HTTP 503). Try again later."
        )
        XCTAssertEqual(
            StorageClientError.httpFailure(method: "listOutputs", statusCode: 429).localizedDescription,
            "The wallet storage server could not handle listOutputs (HTTP 429). Try again later."
        )
        XCTAssertEqual(
            StorageClientError.unreadableResponse(method: "listActions").localizedDescription,
            "The wallet storage server sent a reply to listActions that could not be read."
        )
    }

    func test_theMethodIsReadable() {
        XCTAssertEqual(StorageClientError.unreadableResponse(method: "a").method, "a")
        XCTAssertEqual(StorageClientError.httpFailure(method: "b", statusCode: 500).method, "b")
    }
}
