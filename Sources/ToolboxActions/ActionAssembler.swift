import Foundation
import BSVCore
import BSVKeys
import ToolboxBRC29
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxStorage

/// Turns a funded action into a transaction ready to sign.
///
/// Storage decided which outputs to spend and what change to make; this puts those decisions into
/// a real transaction. It is the last step before keys are used, which is why the output check
/// happens here rather than anywhere a caller could skip it.
///
/// The order is deliberate: verify first, build second. Building a transaction from outputs that
/// were altered and *then* checking would leave a signable object lying around whose only defence
/// is that nobody signed it yet.
public enum ActionAssembler {

    /// Verifies storage's answer and assembles the unsigned transaction.
    ///
    /// - Parameters:
    ///   - funded: what storage returned.
    ///   - requested: the outputs the caller actually asked for, from their own request rather
    ///     than from anything storage sent back.
    public static func assemble(
        _ funded: StorageCreateActionResult,
        requested: [WalletCreateActionOutput],
        changeKey: PrivateKey,
        limits: TransactionLimits = WalletTransactionLimits.standard
    ) throws -> Transaction {
        // Before anything else. See `OutputVerification` for why.
        try OutputVerification.verify(requested: requested, returned: funded.outputs)

        let inputs = try funded.inputs.map { input -> TransactionInput in
            let txid: TransactionID
            do {
                txid = try TransactionID(displayHex: input.sourceTXID)
            } catch {
                throw ActionError.unusableInput(
                    "input names a transaction that cannot be read: \(input.sourceTXID)"
                )
            }
            guard input.sourceSatoshis >= 0 else {
                throw ActionError.unusableInput("input has a negative amount")
            }
            return TransactionInput(
                previousOutput: Outpoint(
                    transactionID: txid, outputIndex: input.sourceVout
                ),
                // Empty until signed. The length storage reported is kept so the fee the
                // transaction was funded for still matches what it will weigh once signed.
                unlockingScript: try script([], limits: limits),
                sequence: 0xffff_ffff,
                sourceOutput: TransactionOutput(
                    satoshis: UInt64(input.sourceSatoshis),
                    lockingScript: try script(input.sourceLockingScript, limits: limits)
                ),
                estimatedUnlockingScriptByteCount: Int(input.unlockingScriptLength)
            )
        }

        // A change output's script is re-derived from our own key and storage's copy is
        // discarded. That is what makes the label safe to accept: an output calling itself change
        // can then only pay this wallet, whatever script storage attached to it.
        let outputs = try funded.outputs.map { output -> TransactionOutput in
            guard output.isChange else {
                return TransactionOutput(
                    satoshis: output.satoshis,
                    lockingScript: try script(output.lockingScript, limits: limits)
                )
            }
            guard let prefix = funded.derivationPrefix, let suffix = output.derivationSuffix else {
                throw ActionError.unresolvableChange(
                    "change at index \(output.vout) has no derivation, so its script cannot be "
                        + "rebuilt and storage's copy cannot be trusted"
                )
            }
            let mine = try BRC29.receivingPrivateKey(
                recipient: changeKey, sender: changeKey.publicKey,
                prefix: prefix, suffix: suffix
            )
            return TransactionOutput(
                satoshis: output.satoshis,
                lockingScript: try BRC29.lockingScript(for: mine.publicKey),
                isChange: true
            )
        }

        return Transaction(
            version: funded.version,
            inputs: inputs,
            // A transaction with no outputs is rejected by processors. When an action genuinely
            // has none, the reference adds one zero-satoshi `OP_FALSE OP_RETURN` output so the
            // transaction is well formed, and so does this.
            outputs: outputs.isEmpty
                ? [try TransactionOutput(satoshis: 0, lockingScript: emptyDataOutput(limits: limits))]
                : outputs,
            lockTime: funded.lockTime
        )
    }

    /// A provably unspendable zero-value output, for an action that would otherwise have none.
    private static func emptyDataOutput(limits: TransactionLimits) throws -> Script {
        try Script.falseReturn(
            [],
            maximumByteCount: Int(limits.maximumScriptByteCount),
            maximumPartByteCount: Int(limits.maximumScriptByteCount)
        )
    }

    /// A script, refused rather than truncated when it exceeds what a transaction may carry.
    private static func script(_ bytes: [UInt8], limits: TransactionLimits) throws -> Script {
        do {
            return try Script(
                bytes: bytes, maximumByteCount: Int(limits.maximumScriptByteCount)
            )
        } catch {
            throw ActionError.unusableInput("a script exceeds the transaction limits")
        }
    }

    /// Refuses a fee above what the caller allows.
    ///
    /// Storage chooses the inputs, so nothing else stops it selecting a large one and returning no
    /// change: the requested output is untouched, every other check passes, and the difference —
    /// which can be the whole wallet — goes to miners as a fee. Verifying outputs does not catch
    /// this, because no output is wrong.
    public static func requireFeeWithin(
        _ maximum: Int64, for funded: StorageCreateActionResult
    ) throws {
        let paid = try fee(for: funded)
        guard paid <= maximum else {
            throw ActionError.feeTooHigh(paid: paid, maximum: maximum)
        }
    }

    /// What the transaction pays in fees, from the amounts storage reported.
    ///
    /// Computed rather than taken on trust: storage chose the inputs and the change, and this is
    /// the number that says whether those choices were sane. A negative result means the outputs
    /// exceed the inputs, which is not a fee but an impossible transaction.
    public static func fee(for funded: StorageCreateActionResult) throws -> Int64 {
        // Reporting overflow rather than trapping: these amounts come from a remote server.
        var inputTotal = Int64(0)
        for input in funded.inputs {
            let (sum, overflow) = inputTotal.addingReportingOverflow(input.sourceSatoshis)
            guard !overflow else { throw ActionError.unusableInput("input amounts overflow") }
            inputTotal = sum
        }
        var outputTotal = Int64(0)
        for output in funded.outputs {
            guard let amount = Int64(exactly: output.satoshis) else {
                throw ActionError.unusableInput("an output amount is out of range")
            }
            let (sum, overflow) = outputTotal.addingReportingOverflow(amount)
            guard !overflow else { throw ActionError.unusableInput("output amounts overflow") }
            outputTotal = sum
        }
        let (fee, feeOverflow) = inputTotal.subtractingReportingOverflow(outputTotal)
        guard !feeOverflow else { throw ActionError.unusableInput("amounts overflow") }
        guard fee >= 0 else {
            throw ActionError.unusableInput(
                "outputs exceed inputs by \(-fee) satoshis"
            )
        }
        return fee
    }
}
