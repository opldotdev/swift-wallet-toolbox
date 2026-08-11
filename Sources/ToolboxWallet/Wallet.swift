import Foundation
import BSVWallet
import ToolboxActions
import ToolboxServices
import ToolboxStorage

/// The concrete BRC-100 wallet.
///
/// It composes rather than implements: key operations come from the SDK's offline kernel, records
/// from storage, chain access from services, and transaction assembly from actions. What this type
/// adds is the order those happen in.
///
/// Construction is two-phase because the parts depend on each other in a cycle: storage
/// authenticates using the wallet's identity, and the wallet needs storage. Key operations are
/// built first, from the identity key alone; the authenticated transport and storage come next;
/// the wallet closes over both. See `docs/DESIGN.md` §8.
public struct Wallet: Sendable {
    public let storage: any WalletStorageProvider
    public let chain: Chain

    public init(storage: any WalletStorageProvider, chain: Chain) {
        self.storage = storage
        self.chain = chain
    }
}

public enum WalletError: Error, Equatable, Sendable {
    /// Raised by the certificate, key-linkage and identity-discovery methods, which v1 does not
    /// provide. Go's toolbox leaves the same eight methods unbuilt; it panics, and this throws.
    case notImplemented(String)
    case identityMismatch
}
