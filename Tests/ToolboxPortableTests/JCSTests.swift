import XCTest
import ToolboxCore
@testable import ToolboxPortable

final class JCSTests: XCTestCase {
    func test_rfc8785NumberFormattingBoundaries() throws {
        let values: [(Double, String)] = [
            (0, "0"),
            (-0.0, "0"),
            (Double(bitPattern: 1), "5e-324"),
            (Double(bitPattern: 0x8000_0000_0000_0001), "-5e-324"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (333_333_333.333_333_29, "333333333.3333333"),
            (Double.greatestFiniteMagnitude, "1.7976931348623157e+308"),
        ]

        for (value, expected) in values {
            XCTAssertEqual(try JCS.serialize(.number(value)), expected)
        }
    }

    func test_propertyNamesSortByUTF16CodeUnits() throws {
        let object: JSONValue = .object([
            "€": "Euro Sign",
            "\r": "Carriage Return",
            "דּ": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "😀": "Emoji",
            "": "Control",
            "ö": "Latin Small Letter O With Diaeresis",
        ])

        XCTAssertEqual(
            try JCS.serialize(object),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\":\"Control\","
                + "\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\","
                + "\"😀\":\"Emoji\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"
        )
    }
}
