import XCTest
@testable import ToolboxCore

/// Reading a binary JSON response exactly as `parseJsonRpc(text, true)` reads it.
///
/// The vectors were written by `stringifyJsonRpc(payload, true)` and read back by
/// `parseJsonRpc(text, true)` from both `@bsv/wallet-toolbox` 2.16.0 and
/// `@bopen-io/wallet-toolbox` 2.15.2 (`out/src/storage/remoting/BinaryJson.js`), which gave the
/// same text; `Uint8Array` values are written below as the arrays of numbers this client reads.
final class BinaryJSONTests: XCTestCase {

    private func decode(_ json: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
    }

    /// Bytes, an empty byte value, and literal objects shaped like each marker, as storage wrote
    /// them and as the reference read them back.
    func test_aStorageReplyReadsBackAsTheReferenceReadsIt() throws {
        let wire = #"""
        {"jsonrpc":"2.0","id":3,"result":{"reference":"cmVm","inputBeef":{"$bsvBinary":"base64","data":"AQID+v8A"},"empty":{"$bsvBinary":"base64","data":""},"literalTagged":{"$bsvBinary":"escaped","entries":[["$bsvBinary","base64"],["data","AQID"]]},"literalEscaped":{"$bsvBinary":"escaped","entries":[["$bsvBinary","escaped"],["entries",[["a",1]]]]},"literalBuffer":{"$bsvBinary":"escaped","entries":[["type","Buffer"],["data",[9,8]]]},"nested":[{"rawTx":{"$bsvBinary":"base64","data":"Bwc="},"inner":{"$bsvBinary":"base64","data":{"$bsvBinary":"base64","data":"BQ=="}}}],"text":"type:text/plain"}}
        """#
        let decoded = #"""
        {"jsonrpc":"2.0","id":3,"result":{"reference":"cmVm","inputBeef":[1,2,3,250,255,0],"empty":[],"literalTagged":{"$bsvBinary":"base64","data":"AQID"},"literalEscaped":{"$bsvBinary":"escaped","entries":[["a",1]]},"literalBuffer":{"type":"Buffer","data":[9,8]},"nested":[{"rawTx":[7,7],"inner":{"$bsvBinary":"base64","data":[5]}}],"text":"type:text/plain"}}
        """#
        XCTAssertEqual(try decode(wire).decodingBinary(), try decode(decoded))
    }

    /// An escaped object is restored once and not read again, so a literal tagged value inside
    /// one stays a literal. Its values are read first, so real bytes inside one are bytes.
    func test_anEscapedObjectIsRestoredWithItsValuesRead() throws {
        XCTAssertEqual(
            try decode(#"{"v":{"$bsvBinary":"escaped","entries":[["k",{"$bsvBinary":"base64","data":"AQ=="}]]}}"#)
                .decodingBinary(),
            try decode(#"{"v":{"k":[1]}}"#)
        )
    }

    /// `Object.fromEntries` keeps the last of a repeated key.
    func test_aRepeatedEscapedKeyKeepsItsLastValue() throws {
        XCTAssertEqual(
            try decode(#"{"v":{"$bsvBinary":"escaped","entries":[["a",1],["a",2]]}}"#).decodingBinary(),
            try decode(#"{"v":{"a":2}}"#)
        )
    }

    /// Only the exact marker shapes are markers: a third member, or an entry that is not a
    /// `[string, value]` pair, leaves the object as it is.
    func test_anObjectNotExactlyAMarkerIsLeftAlone() throws {
        for text in [
            #"{"v":{"$bsvBinary":"base64","data":"AQ==","x":1}}"#,
            #"{"v":{"$bsvBinary":"escaped","entries":[["a",1],["b"]]}}"#,
            #"{"v":{"$bsvBinary":"escaped","entries":[[1,1]]}}"#,
        ] {
            XCTAssertEqual(try decode(text).decodingBinary(), try decode(text), text)
        }
    }

    func test_theWholeReplyMayItselfBeBytes() throws {
        XCTAssertEqual(try decode(#"{"$bsvBinary":"base64","data":"AQ=="}"#).decodingBinary(), .array([.number(1)]))
    }

    /// Every value the reference's `validateBase64` refuses: unpadded, non-zero unused bits, a
    /// character after padding, three `=`, and a character outside the alphabet.
    func test_dataThatIsNotCanonicalPaddedBase64IsRefused() throws {
        for data in ["AQI", "AQJ=", "AQ==x===", "A===", "AR==", "AQ*=", "AQ-_", "AQ== "] {
            XCTAssertThrowsError(
                try decode(#"{"v":{"$bsvBinary":"base64","data":"\#(data)"}}"#).decodingBinary(), data
            ) { error in
                XCTAssertEqual(error as? BinaryJSONError, .invalidBase64)
            }
        }
    }

    func test_canonicalBase64DecodesAtEveryPadding() throws {
        XCTAssertEqual(BinaryJSONBase64.decode(""), [])
        XCTAssertEqual(BinaryJSONBase64.decode("AQ=="), [1])
        XCTAssertEqual(BinaryJSONBase64.decode("AQI="), [1, 2])
        XCTAssertEqual(BinaryJSONBase64.decode("AQID"), [1, 2, 3])
        let bytes = (0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        XCTAssertEqual(BinaryJSONBase64.decode(Data(bytes).base64EncodedString()), bytes)
    }
}
