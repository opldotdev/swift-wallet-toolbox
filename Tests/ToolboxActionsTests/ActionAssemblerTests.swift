import XCTest
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage
@testable import ToolboxActions

/// Assembling a funded action into a transaction.
///
/// The property this file exists to pin: **verification happens before assembly**. A transaction
/// built from altered outputs and checked afterwards is a signable object whose only defence is
/// that nobody has signed it yet.
final class ActionAssemblerTests: XCTestCase {

    /// An output as storage returns it: the caller's own, echoed back.
    private func storageOutput(
        _ requested: WalletCreateActionOutput, vout: UInt32 = 0
    ) -> StorageActionOutput {
        StorageActionOutput(
            vout: vout, satoshis: requested.satoshis,
            lockingScript: requested.lockingScript, providedBy: .you,
            purpose: nil, derivationSuffix: nil
        )
    }

    /// A change output, which the assembler re-derives rather than trusts.
    private func changeOutput(
        satoshis: UInt64, vout: UInt32, suffix: String = "Su=="
    ) -> StorageActionOutput {
        StorageActionOutput(
            vout: vout, satoshis: satoshis, lockingScript: [0x00],
            providedBy: .storage, purpose: .change, derivationSuffix: suffix
        )
    }

    private func key(_ byte: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [byte])
    }

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
        outputs: [StorageActionOutput], inputs: [StorageActionInput]
    ) -> StorageCreateActionResult {
        StorageCreateActionResult(
            reference: "ref", version: 1, lockTime: 0, outputs: outputs, inputs: inputs,
            inputBEEF: nil, derivationPrefix: "p"
        )
    }

    // MARK: - Assembly

    func test_aFundedActionBecomesATransaction() throws {
        let requested = [try output(satoshis: 1_000)]
        let action = funded(outputs: requested.map { storageOutput($0) }, inputs: [input(satoshis: 5_000)])

        let transaction = try ActionAssembler.assemble(action, requested: requested, changeKey: try key(1))

        XCTAssertEqual(transaction.inputs.count, 1)
        XCTAssertEqual(transaction.outputs.count, 1)
        XCTAssertEqual(transaction.outputs[0].satoshis, 1_000)
        XCTAssertEqual(transaction.version, 1)
    }

    /// Inputs carry no unlocking script until they are signed, but they must carry the length the
    /// fee was computed from — otherwise the signed transaction weighs more than it was funded for.
    func test_inputsAreUnsignedButKeepTheirEstimatedLength() throws {
        let requested = [try output(satoshis: 1_000)]
        let action = funded(outputs: requested.map { storageOutput($0) }, inputs: [input(satoshis: 5_000)])

        let transaction = try ActionAssembler.assemble(action, requested: requested, changeKey: try key(1))

        XCTAssertTrue(transaction.inputs[0].unlockingScript.bytes.isEmpty)
        XCTAssertEqual(transaction.inputs[0].estimatedUnlockingScriptByteCount, 108)
    }

    /// The amount being spent has to travel with the input: a signature commits to it, and an
    /// input whose value is unknown cannot be signed correctly.
    func test_inputsCarryTheAmountBeingSpent() throws {
        let requested = [try output(satoshis: 1_000)]
        let action = funded(outputs: requested.map { storageOutput($0) }, inputs: [input(satoshis: 5_000)])

        let transaction = try ActionAssembler.assemble(action, requested: requested, changeKey: try key(1))

        XCTAssertEqual(transaction.inputs[0].sourceOutput?.satoshis, 5_000)
    }

    // MARK: - The check comes first

    /// The whole point. Storage returning a different output must stop assembly, not be caught
    /// somewhere later.
    func test_alteredOutputsStopAssembly() throws {
        let requested = [try output(satoshis: 1_000)]
        let tampered = [try output(satoshis: 1_000, script: [0xde, 0xad])]
        let action = funded(outputs: tampered.map { storageOutput($0) }, inputs: [input(satoshis: 5_000)])

        XCTAssertThrowsError(try ActionAssembler.assemble(action, requested: requested, changeKey: try key(1))) {
            XCTAssertEqual($0 as? ActionError,
                           .storageAlteredOutputs("storage altered output 0"))
        }
    }

    /// An extra output storage added on its own is a payment nobody asked for.
    func test_anAddedOutputStopsAssembly() throws {
        let requested = [try output(satoshis: 1_000)]
        let tampered = requested + [try output(satoshis: 9_000, script: [0xbe, 0xef])]
        let action = funded(outputs: tampered.map { storageOutput($0) }, inputs: [input(satoshis: 50_000)])

        XCTAssertThrowsError(try ActionAssembler.assemble(action, requested: requested, changeKey: try key(1)))
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
        let action = funded(outputs: requested.map { storageOutput($0) }, inputs: [bad])

        XCTAssertThrowsError(try ActionAssembler.assemble(action, requested: requested, changeKey: try key(1)))
    }

    // MARK: - Fees

    func test_theFeeIsWhatIsLeftOver() throws {
        let action = funded(
            outputs: [storageOutput(try output(satoshis: 1_000))], inputs: [input(satoshis: 5_000)]
        )

        XCTAssertEqual(try ActionAssembler.fee(for: action), 4_000)
    }

    /// Outputs exceeding inputs is not a small fee, it is an impossible transaction. Reporting it
    /// as a negative number and carrying on would send it to a broadcaster to be rejected.
    func test_outputsExceedingInputsAreRefused() throws {
        let action = funded(
            outputs: [storageOutput(try output(satoshis: 9_000))], inputs: [input(satoshis: 1_000)]
        )

        XCTAssertThrowsError(try ActionAssembler.fee(for: action))
    }

    func test_aZeroFeeIsAllowed() throws {
        let action = funded(
            outputs: [storageOutput(try output(satoshis: 1_000))], inputs: [input(satoshis: 1_000)]
        )

        XCTAssertEqual(try ActionAssembler.fee(for: action), 0)
    }
}

/// The fee ceiling, and change the wallet re-derives rather than trusts.
///
/// Both come from the adversarial review of 2026-08-11. The fee case is the one no output check
/// can find: every output is exactly what was asked for, and the money leaves as a fee.
final class FeeAndChangeTests: XCTestCase {

    private func key(_ byte: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [byte])
    }

    private func requested() throws -> WalletCreateActionOutput {
        try WalletCreateActionOutput(
            lockingScript: [0x76, 0xa9], satoshis: 1_000, outputDescription: "payment"
        )
    }

    private func action(
        inputSatoshis: Int64, outputs: [StorageActionOutput]
    ) -> StorageCreateActionResult {
        StorageCreateActionResult(
            reference: "ref", version: 1, lockTime: 0, outputs: outputs,
            inputs: [
                StorageActionInput(
                    sourceTXID:
                        "8ac7230489e80000000000000000000000000000000000000000000000000001",
                    sourceVout: 0, sourceSatoshis: inputSatoshis,
                    sourceLockingScript: [0x76, 0xa9, 0x14], unlockingScriptLength: 108,
                    derivationPrefix: "Pr==", derivationSuffix: "Su=="
                )
            ],
            inputBEEF: nil, derivationPrefix: "Pr=="
        )
    }

    private func echoed(_ output: WalletCreateActionOutput) -> StorageActionOutput {
        StorageActionOutput(
            vout: 0, satoshis: output.satoshis, lockingScript: output.lockingScript,
            providedBy: .you, purpose: nil, derivationSuffix: nil
        )
    }

    /// The critical case: the requested output is exactly right, a whole coin is spent, and no
    /// change comes back. Every output check passes and the wallet is emptied into a fee.
    func test_ahugeFeeWithCorrectOutputsIsRefused() throws {
        let payment = try requested()
        let funded = action(inputSatoshis: 100_000_000, outputs: [echoed(payment)])

        XCTAssertEqual(try ActionAssembler.fee(for: funded), 99_999_000)
        XCTAssertThrowsError(try ActionAssembler.requireFeeWithin(5_000, for: funded)) {
            XCTAssertEqual($0 as? ActionError, .feeTooHigh(paid: 99_999_000, maximum: 5_000))
        }
    }

    func test_afeeWithinTheCeilingIsAllowed() throws {
        let payment = try requested()
        let funded = action(inputSatoshis: 1_500, outputs: [echoed(payment)])

        XCTAssertNoThrow(try ActionAssembler.requireFeeWithin(5_000, for: funded))
    }

    /// Storage's script for a change output is discarded. The assembled output must pay a key this
    /// wallet derives, whatever storage attached to it.
    func test_changeIsRederivedRatherThanTrusted() throws {
        let payment = try requested()
        let identity = try key(1)
        let storageScript: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
        let funded = action(inputSatoshis: 5_000, outputs: [
            echoed(payment),
            StorageActionOutput(
                vout: 1, satoshis: 3_900, lockingScript: storageScript,
                providedBy: .storage, purpose: .change, derivationSuffix: "Su=="
            ),
        ])

        let transaction = try ActionAssembler.assemble(
            funded, requested: [payment], changeKey: identity
        )

        XCTAssertEqual(transaction.outputs.count, 2)
        XCTAssertNotEqual(
            transaction.outputs[1].lockingScript.bytes, storageScript,
            "storage's change script must never be used"
        )
        let mine = try BRC29.receivingPrivateKey(
            recipient: identity, sender: identity.publicKey, prefix: "Pr==", suffix: "Su=="
        )
        XCTAssertEqual(
            transaction.outputs[1].lockingScript.bytes,
            try BRC29.lockingScript(for: mine.publicKey).bytes,
            "change must pay a key this wallet derives"
        )
    }

    /// Without a derivation there is nothing safe to fall back to, because storage's copy is never
    /// used. Refusing beats paying an address we cannot prove is ours.
    func test_changeWithNoDerivationIsRefused() throws {
        let payment = try requested()
        let funded = action(inputSatoshis: 5_000, outputs: [
            echoed(payment),
            StorageActionOutput(
                vout: 1, satoshis: 3_900, lockingScript: [0xaa],
                providedBy: .storage, purpose: .change, derivationSuffix: nil
            ),
        ])

        XCTAssertThrowsError(
            try ActionAssembler.assemble(funded, requested: [payment], changeKey: try key(1))
        )
    }
}
