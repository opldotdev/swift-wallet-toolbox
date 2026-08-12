import XCTest
import BSVWallet
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// Building the request and reading the funded action.
///
/// Two things matter here. The request must carry every field the server reads, including the
/// empty ones. And the outputs storage echoes back must be kept exactly as sent, because the
/// signer compares them against the real request — merging the two would compare the request
/// with itself and the check would pass for anything.
final class CreateActionTests: XCTestCase {

    private func result(_ json: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
    }

    private func payment(satoshis: UInt64 = 1_000) throws -> WalletCreateActionRequest {
        try WalletCreateActionRequest(
            description: "a payment",
            outputs: [
                try WalletCreateActionOutput(
                    lockingScript: [0x76, 0xa9], satoshis: satoshis, outputDescription: "to someone"
                )
            ]
        )
    }

    // MARK: - The request

    /// The server reads several collections without checking they exist. An omitted empty array
    /// is a crash there, not a default here — `tags` on `listOutputs` proved it.
    func test_theRequestCarriesEveryCollectionEvenWhenEmpty() throws {
        let arguments = StorageClient.arguments(for: try payment())

        XCTAssertNotNil(arguments["inputs"]?.arrayValue)
        XCTAssertNotNil(arguments["labels"]?.arrayValue)
        let output = try XCTUnwrap(arguments["outputs"]?.arrayValue?.first)
        XCTAssertNotNil(output["tags"]?.arrayValue)
        let options = try XCTUnwrap(arguments["options"]?.objectValue)
        XCTAssertNotNil(options["sendWith"]?.arrayValue)
        XCTAssertNotNil(options["knownTxids"]?.arrayValue)
        XCTAssertNotNil(options["noSendChange"]?.arrayValue)
    }

    /// Storage must hand the action back rather than completing it. Anything else would mean
    /// storage holds keys, which it does not.
    func test_theRequestAsksStorageToStopBeforeSigning() throws {
        let arguments = StorageClient.arguments(for: try payment())

        XCTAssertEqual(arguments["isSignAction"]?.boolValue, true)
        XCTAssertEqual(arguments["options"]?["signAndProcess"]?.boolValue, false)
    }

    func test_anOutputIsSentAsHexWithItsAmount() throws {
        let arguments = StorageClient.arguments(for: try payment(satoshis: 4_200))

        let output = try XCTUnwrap(arguments["outputs"]?.arrayValue?.first)
        XCTAssertEqual(output["lockingScript"]?.stringValue, "76a9")
        XCTAssertEqual(output["satoshis"]?.intValue, 4_200)
    }

    // MARK: - The result

    func test_aFundedActionDecodes() throws {
        let decoded = try StorageClient.decodeCreateAction(try result("""
            {"reference": "abc123", "version": 1, "lockTime": 0,
             "inputs": [{
               "sourceTxid": "aa", "sourceVout": 1, "sourceSatoshis": 5000,
               "sourceLockingScript": "76a914", "unlockingScriptLength": 108,
               "derivationPrefix": "p", "derivationSuffix": "s"
             }],
             "outputs": [{"lockingScript": "76a9", "satoshis": 1000,
                          "outputDescription": "to someone"}]}
            """), requested: [])

        XCTAssertEqual(decoded.reference, "abc123")
        XCTAssertEqual(decoded.inputs.count, 1)
        XCTAssertEqual(decoded.inputs[0].sourceSatoshis, 5_000)
        XCTAssertEqual(decoded.inputs[0].unlockingScriptLength, 108)
        XCTAssertEqual(decoded.inputs[0].derivationPrefix, "p")
        XCTAssertEqual(decoded.outputs.count, 1)
    }

    /// The echoed outputs are whatever storage sent, not what we asked for. If this substituted
    /// our own request the signer's comparison would compare the request with itself and pass for
    /// anything storage returned.
    func test_theEchoedOutputsAreStoragesOwnAndNotOurs() throws {
        let ours = try WalletCreateActionOutput(
            lockingScript: [0xaa], satoshis: 1_000, outputDescription: "ours"
        )

        let decoded = try StorageClient.decodeCreateAction(try result("""
            {"reference": "r", "outputs": [{"lockingScript": "bb", "satoshis": 999,
                                            "outputDescription": "theirs"}]}
            """), requested: [ours])

        XCTAssertEqual(decoded.outputs.count, 1)
        XCTAssertEqual(decoded.outputs[0].lockingScript, [0xbb], "storage's script, not ours")
        XCTAssertEqual(decoded.outputs[0].satoshis, 999)
        XCTAssertNotEqual(decoded.outputs[0].lockingScript, ours.lockingScript)
    }

    /// A missing input amount is refused. Reading it as zero would let the signer sign an input
    /// whose value it does not know, which is how a transaction burns money to fees.
    func test_anInputWithNoAmountIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeCreateAction(try result("""
            {"reference": "r", "inputs": [{"sourceTxid": "aa", "sourceVout": 0,
              "sourceLockingScript": "76", "unlockingScriptLength": 108}]}
            """), requested: []))
    }

    func test_anActionWithNoReferenceIsRefused() throws {
        XCTAssertThrowsError(
            try StorageClient.decodeCreateAction(try result(#"{"inputs": []}"#), requested: [])
        )
    }

    func test_anInputWithAnUnreadableScriptIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeCreateAction(try result("""
            {"reference": "r", "inputs": [{"sourceTxid": "aa", "sourceVout": 0,
              "sourceSatoshis": 10, "sourceLockingScript": "zz",
              "unlockingScriptLength": 108}]}
            """), requested: []))
    }
}
