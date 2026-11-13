import XCTest
@testable import ToolboxCore

/// The ordered JSON writer against `JSON.stringify`.
///
/// Storage recomputes an action-batch manifest digest over `JSON.stringify` of what it parsed, so
/// the client has to produce the same bytes for the same tree. The expected strings below are the
/// output of Node.js 22 `JSON.stringify` for the same inputs.
final class OrderedJSONTests: XCTestCase {

    func test_stringsAreEscapedAsJSONStringify() {
        let vectors: [(String, String)] = [
            ("", #""""#),
            ("plain", #""plain""#),
            ("q\"b\\s/", #""q\"b\\s/""#),
            ("\u{08}\u{0C}\n\r\t", #""\b\f\n\r\t""#),
            ("\r\n", #""\r\n""#),
            ("\u{00}\u{01}\u{1F}\u{7F}", "\"\\u0000\\u0001\\u001f\u{7F}\""),
            ("é☃😀", "\"é☃😀\""),
            ("\u{2028}\u{2029}", "\"\u{2028}\u{2029}\""),
            ("<>&'", #""<>&'""#),
        ]
        for (input, expected) in vectors {
            XCTAssertEqual(OrderedJSON.string(input).serialized(), expected, input.debugDescription)
        }
    }

    func test_numbersAreWrittenAsJavaScriptWritesThem() {
        let vectors: [(Double, String)] = [
            (0, "0"), (-0.0, "0"), (1, "1"), (-1, "-1"), (1.5, "1.5"), (0.1, "0.1"),
            (1e21, "1e+21"), (1e-7, "1e-7"), (123456789012, "123456789012"),
            (2.5e-5, "0.000025"), (9007199254740991, "9007199254740991"), (100.25, "100.25"),
            (-1.25e-9, "-1.25e-9"), (1.5e300, "1.5e+300"), (0.000001, "0.000001"),
        ]
        for (input, expected) in vectors {
            XCTAssertEqual(OrderedJSON.number(input).serialized(), expected, "\(input)")
        }
        XCTAssertEqual(OrderedJSON.integer(-42).serialized(), "-42")
    }

    func test_membersKeepTheirOrderAndAbsentValuesAreOmitted() {
        let value = OrderedJSON.record([
            "b": .integer(1),
            "a": .array([.bool(true), .null, .object([])]),
            "c": .record(["z": nil, "y": .string("y")]),
        ])
        XCTAssertEqual(value.serialized(), #"{"b":1,"a":[true,null,{}],"c":{"y":"y"}}"#)
    }

    func test_settingFollowsObjectSpread() {
        let value = OrderedJSON.record(["a": .integer(1), "b": .integer(2), "c": .integer(3)])
        // `{...value, b: 9}` keeps b where it was; `{...value, d: 4}` appends.
        XCTAssertEqual(value.setting("b", .integer(9)).serialized(), #"{"a":1,"b":9,"c":3}"#)
        XCTAssertEqual(value.setting("d", .integer(4)).serialized(), #"{"a":1,"b":2,"c":3,"d":4}"#)
        // `{...value, b: undefined}` is omitted by JSON.stringify.
        XCTAssertEqual(value.setting("b", nil).serialized(), #"{"a":1,"c":3}"#)
    }

    func test_parseKeepsDocumentOrderAndRoundTrips() throws {
        let text = #"{"z":[1,2.5,-3e-7,"é\n"],"a":{"y":null,"x":false},"m":"😀"}"#
        let parsed = try OrderedJSON.parse(text)
        XCTAssertEqual(parsed.members?.map(\.key), ["z", "a", "m"])
        XCTAssertEqual(parsed["a"]?.members?.map(\.key), ["y", "x"])
        XCTAssertEqual(parsed.serialized(), #"{"z":[1,2.5,-3e-7,"é\n"],"a":{"y":null,"x":false},"m":"😀"}"#)
    }

    func test_parseRejectsMalformedText() {
        for text in ["", "{", #"{"a":}"#, "[1,]", #""\x""#, "01", "-", "1.", ".5", "+1", "1e", "--1", "1 2", #"{"a" 1}"#] {
            XCTAssertThrowsError(try OrderedJSON.parse(text), text)
        }
        for text in ["0", "-0", "0.5e-3", "1E+2", "-12.25", "9223372036854775807"] {
            XCTAssertNoThrow(try OrderedJSON.parse(text), text)
        }
    }
}
