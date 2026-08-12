import XCTest
import BSVWallet
import ToolboxCore
@testable import ToolboxStorageClient

/// Decoding history, and the shape of the housekeeping requests.
final class HistoryTests: XCTestCase {

    private func result(_ json: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
    }

    func test_actionsDecode() throws {
        let decoded = try StorageClient.decodeActions(try result("""
            {"totalActions": 1, "actions": [{
              "txid": "8ac7230489e80000000000000000000000000000000000000000000000000001",
              "satoshis": -4200, "status": "completed", "isOutgoing": true,
              "description": "coffee", "version": 1, "lockTime": 0
            }]}
            """))

        XCTAssertEqual(decoded.totalActions, 1)
        XCTAssertEqual(decoded.actions.count, 1)
        XCTAssertEqual(decoded.actions[0].satoshis, -4200)
        XCTAssertTrue(decoded.actions[0].isOutgoing)
        XCTAssertEqual(decoded.actions[0].status, .completed)
    }

    func test_anUnknownStatusIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeActions(try result("""
            {"totalActions": 1, "actions": [{
              "txid": "8ac7230489e80000000000000000000000000000000000000000000000000001",
              "satoshis": 1, "status": "levitating", "isOutgoing": false
            }]}
            """)))
    }

    func test_anEmptyHistoryDecodes() throws {
        let decoded = try StorageClient.decodeActions(
            try result(#"{"totalActions": 0, "actions": []}"#)
        )
        XCTAssertEqual(decoded.totalActions, 0)
        XCTAssertTrue(decoded.actions.isEmpty)
    }
}
