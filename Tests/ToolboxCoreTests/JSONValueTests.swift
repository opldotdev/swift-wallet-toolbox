import XCTest
@testable import ToolboxCore

/// Parsing bounds on untrusted numbers.
final class JSONValueTests: XCTestCase {

    private func decode(_ json: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
    }

    func test_anOrdinaryIntegerReads() throws {
        XCTAssertEqual(try decode("4200").intValue, 4200)
    }

    /// The trap the review found: 1e308 is integral, passes a rounding check, and crashes on
    /// `Int(_:)`. `Int(exactly:)` returns nil instead.
    func test_anEnormousIntegralNumberIsRejectedNotTrapped() throws {
        XCTAssertNil(try decode("1e308").intValue)
    }

    func test_aFractionalNumberIsNotAnInteger() throws {
        XCTAssertNil(try decode("4.2").intValue)
    }

    /// A document nested past the limit is a refusal, not a stack overflow.
    func test_deeplyNestedInputIsRefused() {
        let deep = String(repeating: "[", count: 200) + String(repeating: "]", count: 200)
        XCTAssertThrowsError(try decode(deep))
    }
}
