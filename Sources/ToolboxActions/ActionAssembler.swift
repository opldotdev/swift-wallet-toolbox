import Foundation
import BSVCore
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

        let outputs = try funded.outputs.map { output in
            TransactionOutput(
                satoshis: output.satoshis,
                lockingScript: try script(output.lockingScript, limits: limits)
            )
        }

        return Transaction(
            version: funded.version,
            inputs: inputs,
            outputs: outputs,
            lockTime: funded.lockTime
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

    /// What the transaction pays in fees, from the amounts storage reported.
    ///
    /// Computed rather than taken on trust: storage chose the inputs and the change, and this is
    /// the number that says whether those choices were sane. A negative result means the outputs
    /// exceed the inputs, which is not a fee but an impossible transaction.
    public static func fee(for funded: StorageCreateActionResult) throws -> Int64 {
        let inputTotal = funded.inputs.reduce(Int64(0)) { $0 + $1.sourceSatoshis }
        let outputTotal = funded.outputs.reduce(Int64(0)) { $0 + Int64($1.satoshis) }
        let fee = inputTotal - outputTotal
        guard fee >= 0 else {
            throw ActionError.unusableInput(
                "outputs exceed inputs by \(-fee) satoshis"
            )
        }
        return fee
    }
}
