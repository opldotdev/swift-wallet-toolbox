import Foundation
import BSVWallet
import ToolboxStorage

/// Checks that storage did not change where the money goes.
///
/// Storage chooses inputs and returns a funded action, and a remote store is run by somebody else.
/// Two separate things can go wrong, and each needs its own check — the first without the second
/// is close to useless.
///
/// **The caller's outputs must come back unchanged.** Otherwise the operator alters a recipient
/// script, the wallet signs it, and the application goes on displaying the recipient that was
/// asked for. This is advisory GHSA-36f9-7rg5-cpf8.
///
/// **Every output beyond the caller's must be change or a bounded commission.** Otherwise the
/// operator leaves the requested outputs alone and simply *adds* one paying itself, funded by
/// shrinking the change. The first check passes and the money still goes.
///
/// Change is the subtle one. An output labelled `change` is not trusted either: its script is
/// re-derived from the wallet's own keys during assembly and storage's copy is discarded, so an
/// attacker output wearing that label pays the wallet rather than the attacker.
///
/// These live inside the signing path rather than being offered to callers. A check a caller can
/// forget is not a control.
public enum OutputVerification {

    /// The most a commission may be, in satoshis.
    ///
    /// This is `MAX_STORAGE_COMMISSION_SATOSHIS` from the TypeScript toolbox, matched exactly. A
    /// lower ceiling would look safer but would reject a legitimate commission an honest server is
    /// entitled to charge, breaking the payment. The bound exists so "commission" cannot become an
    /// unlimited payment to the operator, not to second-guess the reference's number.
    public static let maximumCommission: UInt64 = 500_000

    /// Throws unless storage's outputs are the requested ones followed only by change and at most
    /// one bounded commission.
    ///
    /// Order matters. The requested outputs occupy the first positions, in the order they were
    /// asked for, which is what lets everything after them be judged by a different rule.
    public static func verify(
        requested: [WalletCreateActionOutput],
        returned: [StorageActionOutput],
        maximumCommission: UInt64 = maximumCommission
    ) throws {
        try verifyRequestedUnchanged(requested: requested, returned: returned)
        try verifyExtrasAreChangeOrCommission(
            requestedCount: requested.count, returned: returned,
            maximumCommission: maximumCommission
        )
    }

    /// Every output the caller asked for, echoed back exactly, in position.
    static func verifyRequestedUnchanged(
        requested: [WalletCreateActionOutput],
        returned: [StorageActionOutput]
    ) throws {
        guard returned.count >= requested.count else {
            throw ActionError.storageAlteredOutputs(
                "storage returned \(returned.count) outputs for \(requested.count) requested"
            )
        }
        for (index, output) in requested.enumerated() {
            let echoed = returned[index]
            guard echoed.satoshis == output.satoshis,
                  echoed.lockingScript == output.lockingScript else {
                throw ActionError.storageAlteredOutputs("storage altered output \(index)")
            }
        }
    }

    /// Anything storage added on its own.
    static func verifyExtrasAreChangeOrCommission(
        requestedCount: Int,
        returned: [StorageActionOutput],
        maximumCommission: UInt64
    ) throws {
        var commissions = 0
        for index in requestedCount..<returned.count {
            let output = returned[index]
            if output.isChange { continue }
            if output.isCommission {
                commissions += 1
                guard commissions == 1 else {
                    throw ActionError.storageAlteredOutputs(
                        "storage returned more than one commission output, at index \(index)"
                    )
                }
                guard output.satoshis <= maximumCommission else {
                    throw ActionError.storageAlteredOutputs(
                        "storage returned a commission of \(output.satoshis) at index \(index), "
                            + "above the limit of \(maximumCommission)"
                    )
                }
                continue
            }
            throw ActionError.storageAlteredOutputs(
                "storage added an output at index \(index) that is neither change nor commission"
            )
        }
    }
}

public enum ActionError: Error, Equatable, Sendable {
    case notImplemented(String)
    /// Storage returned outputs that differ from the ones requested, or added one of its own that
    /// is not change or a bounded commission. Never recoverable: the only safe response is to sign
    /// nothing.
    case storageAlteredOutputs(String)
    case insufficientFunds(required: Int64, available: Int64)
    /// An input storage chose cannot be used as described.
    case unusableInput(String)
    /// A change output arrived without what is needed to re-derive its script. Storage's own copy
    /// is never used, so there is nothing safe to fall back to.
    case unresolvableChange(String)
    /// The transaction would pay more in fees than the caller allowed.
    case feeTooHigh(paid: Int64, maximum: Int64)
}
