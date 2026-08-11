import XCTest
@testable import ToolboxCore

/// Decoding the errors a storage server sends.
///
/// The reason this matters: an application has to tell "you do not have enough money" from "the
/// server is broken", and only the name distinguishes them. A client that kept the message alone
/// would make both of them prose.
final class WireErrorTests: XCTestCase {

    func test_decodesEveryKnownName() {
        let expected: [String: WireError] = [
            "WERR_BAD_REQUEST": .badRequest("m"),
            "WERR_BROADCAST_UNAVAILABLE": .broadcastUnavailable("m"),
            "WERR_INSUFFICIENT_FUNDS": .insufficientFunds("m"),
            "WERR_INTERNAL": .internalFailure("m"),
            "WERR_INVALID_OPERATION": .invalidOperation("m"),
            "WERR_INVALID_PUBLIC_KEY": .invalidPublicKey("m"),
            "WERR_NETWORK_CHAIN": .networkChain("m"),
            "WERR_NOT_ACTIVE": .notActive("m"),
            "WERR_NOT_IMPLEMENTED": .notImplemented("m"),
            "WERR_REVIEW_ACTIONS": .reviewActions("m"),
            "WERR_UNAUTHORIZED": .unauthorized("m"),
        ]

        for (name, error) in expected {
            XCTAssertEqual(WireError.decode(["name": .string(name), "message": "m"]), error, name)
        }
    }

    /// Two codes carry which parameter was at fault. Dropping it would leave a caller guessing.
    func test_parameterCarryingErrorsKeepTheParameterName() {
        XCTAssertEqual(
            WireError.decode([
                "name": "WERR_INVALID_PARAMETER", "message": "bad", "parameter": "satoshis",
            ]),
            .invalidParameter(name: "satoshis", message: "bad")
        )
        XCTAssertEqual(
            WireError.decode([
                "name": "WERR_MISSING_PARAMETER", "message": "gone", "parameter": "reference",
            ]),
            .missingParameter(name: "reference", message: "gone")
        )
    }

    /// A server that gains a code before we do must still produce a report somebody can act on.
    func test_anUnknownNameIsKeptRatherThanFlattened() {
        let error = WireError.decode(["name": "WERR_FUTURE_THING", "message": "later"])

        XCTAssertEqual(error, .unrecognized(name: "WERR_FUTURE_THING", message: "later"))
        XCTAssertEqual(error.wireName, "WERR_FUTURE_THING")
    }

    /// This runs on a path that is already reporting a failure. Losing the failure to a parse
    /// error would be the worse outcome, so a malformed payload still decodes.
    func test_aMalformedPayloadStillProducesAnError() {
        XCTAssertEqual(WireError.decode([:]), .unrecognized(name: "", message: ""))
        XCTAssertEqual(
            WireError.decode(["name": 42, "message": .array(["nested"])]),
            .unrecognized(name: "", message: "")
        )
    }

    func test_everyCaseReportsItsWireName() {
        XCTAssertEqual(WireError.insufficientFunds("m").wireName, "WERR_INSUFFICIENT_FUNDS")
        XCTAssertEqual(WireError.internalFailure("m").wireName, "WERR_INTERNAL")
        XCTAssertEqual(WireError.invalidParameter(name: "p", message: "m").message, "m")
    }
}
