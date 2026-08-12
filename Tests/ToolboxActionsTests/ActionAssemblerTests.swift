import XCTest
import BSVTransaction
import BSVWallet
import ToolboxStorage
@testable import ToolboxActions

/// Assembling a funded action into a transaction.
///
/// The property this file exists to pin: **verification happens before assembly**. A transaction
/// built from altered outputs and checked afterwards is a signable object whose only defence is
/// that nobody has signed it yet.
final class ActionAssemblerTests: XCTestCase {

    private let sourceTXID =
        "8ac7230489e80000000000000000000000000000000000000000000000000001"

    private func output(
        satoshis: UInt64, script: [UInt8] = [0x76, 0xa9]
    ) throws -> WalletCreateActionOutput {
        try WalletCreateActionOutput(
            lockingScript: script, satoshis: satoshis, outputDescription: "payment"
        )
    }

    private func input(satoshis: Int64) -> StorageActionInput {
        StorageActionInput(
            sourceTXID: sourceTXID, sourceVout: 0, sourceSatoshis: satoshis,
            sourceLockingScript: [0x76, 0xa9, 0x14], unlockingScriptLength: 108,
            derivationPrefix: "p", derivationSuffix: "s"
        )
    }

    private func funded(
        outputs: [WalletCreateActionOutput], inputs: [StorageActionInput]
    ) -> StorageCreateActionResult {
        StorageCreateActionResult(
            reference: "ref", version: 1, lockTime: 0, outputs: outputs, inputs: inputs,
            inputBEEF: nil, derivationPrefix: "p"
        )
    }

    // MARK: - Assembly

    func test_aFundedActionBecomesATransaction() throws {
        let requested = [try output(satoshis: 1_000)]
        let action = funded(outputs: requested, inputs: [input(satoshis: 5_000)])

        let transaction = try ActionAssembler.assemble(action, requested: requested)

        XCTAssertEqual(transaction.inputs.count, 1)
        XCTAssertEqual(transaction.outputs.count, 1)
        XCTAssertEqual(transaction.outputs[0].satoshis, 1_000)
        XCTAssertEqual(transaction.version, 1)
    }

    /// Inputs carry no unlocking script until they are signed, but they must carry the length the
    /// fee was computed from — otherwise the signed transaction weighs more than it was funded for.
    func test_inputsAreUnsignedButKeepTheirEstimatedLength() throws {
        let requested = [try output(satoshis: 1_000)]
        let action = funded(outputs: requested, inputs: [input(satoshis: 5_000)])

        let transaction = try ActionAssembler.assemble(action, requested: requested)

        XCTAssertTrue(transaction.inputs[0].unlockingScript.bytes.isEmpty)
        XCTAssertEqual(transaction.inputs[0].estimatedUnlockingScriptByteCount, 108)
    }

    /// The amount being spent has to travel with the input: a signature commits to it, and an
    /// input whose value is unknown cannot be signed correctly.
    func test_inputsCarryTheAmountBeingSpent() throws {
        let requested = [try output(satoshis: 1_000)]
        let action = funded(outputs: requested, inputs: [input(satoshis: 5_000)])

        let transaction = try ActionAssembler.assemble(action, requested: requested)

        XCTAssertEqual(transaction.inputs[0].sourceOutput?.satoshis, 5_000)
    }

    // MARK: - The check comes first

    /// The whole point. Storage returning a different output must stop assembly, not be caught
    /// somewhere later.
    func test_alteredOutputsStopAssembly() throws {
        let requested = [try output(satoshis: 1_000)]
        let tampered = [try output(satoshis: 1_000, script: [0xde, 0xad])]
        let action = funded(outputs: tampered, inputs: [input(satoshis: 5_000)])

        XCTAssertThrowsError(try ActionAssembler.assemble(action, requested: requested)) {
            XCTAssertEqual($0 as? ActionError,
                           .storageAlteredOutputs("storage altered output 0"))
        }
    }

    /// An extra output storage added on its own is a payment nobody asked for.
    func test_anAddedOutputStopsAssembly() throws {
        let requested = [try output(satoshis: 1_000)]
        let tampered = requested + [try output(satoshis: 9_000, script: [0xbe, 0xef])]
        let action = funded(outputs: tampered, inputs: [input(satoshis: 50_000)])

        XCTAssertThrowsError(try ActionAssembler.assemble(action, requested: requested))
    }

    func test_anUnreadableSourceTransactionIsRefused() throws {
        let requested = [try output(satoshis: 1_000)]
        var bad = input(satoshis: 5_000)
        bad = StorageActionInput(
            sourceTXID: "not-a-txid", sourceVout: bad.sourceVout,
            sourceSatoshis: bad.sourceSatoshis, sourceLockingScript: bad.sourceLockingScript,
            unlockingScriptLength: bad.unlockingScriptLength,
            derivationPrefix: bad.derivationPrefix, derivationSuffix: bad.derivationSuffix
        )
        let action = funded(outputs: requested, inputs: [bad])

        XCTAssertThrowsError(try ActionAssembler.assemble(action, requested: requested))
    }

    // MARK: - Fees

    func test_theFeeIsWhatIsLeftOver() throws {
        let action = funded(
            outputs: [try output(satoshis: 1_000)], inputs: [input(satoshis: 5_000)]
        )

        XCTAssertEqual(try ActionAssembler.fee(for: action), 4_000)
    }

    /// Outputs exceeding inputs is not a small fee, it is an impossible transaction. Reporting it
    /// as a negative number and carrying on would send it to a broadcaster to be rejected.
    func test_outputsExceedingInputsAreRefused() throws {
        let action = funded(
            outputs: [try output(satoshis: 9_000)], inputs: [input(satoshis: 1_000)]
        )

        XCTAssertThrowsError(try ActionAssembler.fee(for: action))
    }

    func test_aZeroFeeIsAllowed() throws {
        let action = funded(
            outputs: [try output(satoshis: 1_000)], inputs: [input(satoshis: 1_000)]
        )

        XCTAssertEqual(try ActionAssembler.fee(for: action), 0)
    }
}
