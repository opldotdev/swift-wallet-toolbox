import Foundation
import BSVWallet
import ToolboxStorage

/// Checks that storage did not change what the caller asked to send.
///
/// Storage chooses inputs and returns a funded action, and a remote store is run by somebody else.
/// Nothing stops that operator from returning an action whose outputs pay a different script than
/// the one requested — and a wallet that signed what it was handed would sign that too. This is
/// advisory GHSA-36f9-7rg5-cpf8 in the TypeScript toolbox, where the same check is made before any
/// signature is produced.
///
/// It lives here, inside the signing path, rather than being offered to callers. A check a caller
/// can forget is not a control.
public enum OutputVerification {

    /// Throws unless every requested output appears unchanged in what storage returned.
    ///
    /// Order and count must match as well as content. An extra output is as much a change as an
    /// altered one, and comparing sets would let one through.
    public static func verify(
        requested: [WalletCreateActionOutput],
        returned: [WalletCreateActionOutput]
    ) throws {
        guard requested.count == returned.count else {
            throw ActionError.storageAlteredOutputs(
                "storage returned \(returned.count) outputs for \(requested.count) requested"
            )
        }
        for (index, output) in requested.enumerated() where output != returned[index] {
            throw ActionError.storageAlteredOutputs("storage altered output \(index)")
        }
    }
}

public enum ActionError: Error, Equatable, Sendable {
    case notImplemented(String)
    /// Storage returned outputs that differ from the ones requested. Never recoverable: the only
    /// safe response is to sign nothing.
    case storageAlteredOutputs(String)
    case insufficientFunds(required: Int64, available: Int64)
}
