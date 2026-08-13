import XCTest
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// Turning the store's answer into outputs.
///
/// These records are what a balance is computed from and what the action layer selects inputs
/// out of, so a field this misreads becomes either money the wallet thinks it does not have or
/// money it thinks it does.
final class OutputDecodingTests: XCTestCase {

    private func result(_ json: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
    }

    func test_anOutputDecodes() throws {
        let payload = try result("""
            {"totalOutputs": 1, "outputs": [{
              "outpoint": "8ac7230489e80000000000000000000000000000000000000000000000000001.3",
              "satoshis": 4200, "spendable": true, "lockingScript": "76a914"
            }]}
            """)

        let decoded = try StorageClient.decodeOutputs(payload)

        XCTAssertEqual(decoded.totalOutputs, 1)
        XCTAssertEqual(decoded.outputs.count, 1)
        XCTAssertEqual(decoded.outputs[0].satoshis, 4200)
        XCTAssertTrue(decoded.outputs[0].spendable)
        XCTAssertEqual(decoded.outputs[0].outpoint.outputIndex, 3)
        XCTAssertEqual(decoded.outputs[0].lockingScript, [0x76, 0xa9, 0x14])
    }

    func test_anEmptyWalletDecodes() throws {
        let decoded = try StorageClient.decodeOutputs(
            try result(#"{"totalOutputs": 0, "outputs": []}"#)
        )

        XCTAssertEqual(decoded.totalOutputs, 0)
        XCTAssertTrue(decoded.outputs.isEmpty)
        XCTAssertNil(decoded.beef)
    }

    func test_entireTransactionBEEFIsDecoded() throws {
        let source = Transaction(
            version: 1,
            inputs: [],
            outputs: [
                TransactionOutput(
                    satoshis: 1,
                    lockingScript: try Script(bytes: [0x51], maximumByteCount: 10_000)
                ),
            ],
            lockTime: 0
        )
        let beef = try BEEF(
            merklePaths: [],
            transactions: [.raw(source)],
            limits: StorageLimits.beef
        )
        let bytes = try beef.serialized(limits: StorageLimits.beef)
        let array = bytes.map(String.init).joined(separator: ",")
        let decoded = try StorageClient.decodeOutputs(try result("""
            {"totalOutputs": 0, "outputs": [], "BEEF": [\(array)]}
            """))

        XCTAssertEqual(
            try decoded.beef?.serialized(limits: StorageLimits.beef),
            bytes
        )
    }

    /// An unspendable output still exists and still has to be reported. Dropping it would hide a
    /// coin the wallet owns but cannot move yet.
    func test_anUnspendableOutputIsKept() throws {
        let decoded = try StorageClient.decodeOutputs(try result("""
            {"totalOutputs": 1, "outputs": [{
              "outpoint": "8ac7230489e80000000000000000000000000000000000000000000000000001.0",
              "satoshis": 1, "spendable": false
            }]}
            """))

        XCTAssertEqual(decoded.outputs.count, 1)
        XCTAssertFalse(decoded.outputs[0].spendable)
    }

    // MARK: - Refusals

    /// A missing amount is refused rather than read as zero. A zero-satoshi output the wallet
    /// invented would be selected as an input and spend nothing.
    func test_anOutputWithNoAmountIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeOutputs(try result("""
            {"totalOutputs": 1, "outputs": [{
              "outpoint": "8ac7230489e80000000000000000000000000000000000000000000000000001.0",
              "spendable": true
            }]}
            """)))
    }

    /// Without an outpoint there is nothing to spend. Guessing one is not available.
    func test_anOutputWithNoOutpointIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeOutputs(try result("""
            {"totalOutputs": 1, "outputs": [{"satoshis": 10, "spendable": true}]}
            """)))
    }

    func test_anUnreadableOutpointIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeOutputs(try result("""
            {"totalOutputs": 1, "outputs": [{
              "outpoint": "not-an-outpoint", "satoshis": 10, "spendable": true
            }]}
            """)))
    }

    /// Spendability decides whether the action layer may select this coin. Defaulting it either
    /// way invents an answer the store did not give.
    func test_anOutputWithNoSpendableFlagIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeOutputs(try result("""
            {"totalOutputs": 1, "outputs": [{
              "outpoint": "8ac7230489e80000000000000000000000000000000000000000000000000001.0",
              "satoshis": 10
            }]}
            """)))
    }

    func test_aNegativeAmountIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeOutputs(try result("""
            {"totalOutputs": 1, "outputs": [{
              "outpoint": "8ac7230489e80000000000000000000000000000000000000000000000000001.0",
              "satoshis": -1, "spendable": true
            }]}
            """)))
    }

    func test_aResponseWithNoOutputsMemberIsRefused() throws {
        XCTAssertThrowsError(
            try StorageClient.decodeOutputs(try result(#"{"totalOutputs": 0}"#))
        )
    }
}
