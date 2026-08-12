import Foundation
import BSVWallet
import ToolboxCore

/// Types that exist only at the storage boundary.
///
/// Everything the wallet's caller sees is a `BSVWallet` type. These are the shapes in between:
/// what storage returns when it has funded an action but nobody has signed it yet, and what it
/// needs back once somebody has.

/// A funded, unsigned action.
///
/// `inputs` is the reason the signer cannot trust this blindly. Storage chose which outputs to
/// spend, and it also echoes back the outputs the caller asked for — which the signer re-checks
/// against its own request before signing anything. See `docs/DESIGN.md` §6.
public struct StorageCreateActionResult: Equatable, Sendable {
    public let reference: String
    public let version: UInt32
    public let lockTime: UInt32
    /// Every output storage put in the transaction: the caller's first, then at most one
    /// commission, then change. None of it is taken as fact — see `OutputVerification`.
    public let outputs: [StorageActionOutput]
    public let inputs: [StorageActionInput]
    /// Present when the caller supplied inputs whose source transactions storage already holds.
    public let inputBEEF: [UInt8]?
    public let derivationPrefix: String?

    public init(reference: String, version: UInt32, lockTime: UInt32,
                outputs: [StorageActionOutput], inputs: [StorageActionInput],
                inputBEEF: [UInt8]?, derivationPrefix: String?) {
        self.reference = reference
        self.version = version
        self.lockTime = lockTime
        self.outputs = outputs
        self.inputs = inputs
        self.inputBEEF = inputBEEF
        self.derivationPrefix = derivationPrefix
    }
}

/// An output storage allocated for spending, with what the signer needs to unlock it.
public struct StorageActionInput: Equatable, Sendable {
    public let sourceTXID: String
    public let sourceVout: UInt32
    public let sourceSatoshis: Int64
    public let sourceLockingScript: [UInt8]
    public let unlockingScriptLength: UInt32
    /// BRC-29 derivation for a change output the wallet owns. Absent for an input the caller
    /// supplied and will unlock itself.
    public let derivationPrefix: String?
    public let derivationSuffix: String?

    public init(sourceTXID: String, sourceVout: UInt32, sourceSatoshis: Int64,
                sourceLockingScript: [UInt8], unlockingScriptLength: UInt32,
                derivationPrefix: String?, derivationSuffix: String?) {
        self.sourceTXID = sourceTXID
        self.sourceVout = sourceVout
        self.sourceSatoshis = sourceSatoshis
        self.sourceLockingScript = sourceLockingScript
        self.unlockingScriptLength = unlockingScriptLength
        self.derivationPrefix = derivationPrefix
        self.derivationSuffix = derivationSuffix
    }
}

/// A signed action handed back for finalisation and broadcast.
public struct StorageProcessActionRequest: Equatable, Sendable {
    public let reference: String
    public let isNewTx: Bool
    public let isSendWith: Bool
    /// Atomic BEEF, per BRC-95.
    public let rawTX: [UInt8]?
    public let sendWith: [String]

    public init(reference: String, isNewTx: Bool, isSendWith: Bool, rawTX: [UInt8]?,
                sendWith: [String]) {
        self.reference = reference
        self.isNewTx = isNewTx
        self.isSendWith = isSendWith
        self.rawTX = rawTX
        self.sendWith = sendWith
    }
}

public struct StorageProcessActionResult: Equatable, Sendable {
    public let sendWithResults: [SendWithResult]

    public init(sendWithResults: [SendWithResult]) {
        self.sendWithResults = sendWithResults
    }
}

public struct SendWithResult: Equatable, Sendable {
    public enum Status: String, Equatable, Sendable {
        case unproven
        case sending
        case failed
    }

    public let txid: String
    public let status: Status

    public init(txid: String, status: Status) {
        self.txid = txid
        self.status = status
    }
}

// MARK: - Sync

/// Where a reader has reached in each table it is catching up on.
///
/// Declared for v1 but not exercised: one store has nothing to reconcile with. See
/// `docs/DESIGN.md` §4.
public struct SyncChunkRequest: Equatable, Sendable {
    public let identityKey: String
    public let maxRoughSize: Int
    public let maxItems: Int
    public let offsets: [String: Int]

    public init(identityKey: String, maxRoughSize: Int, maxItems: Int, offsets: [String: Int]) {
        self.identityKey = identityKey
        self.maxRoughSize = maxRoughSize
        self.maxItems = maxItems
        self.offsets = offsets
    }
}

public struct SyncChunk: Equatable, Sendable {
    public let fromStorageIdentityKey: String
    public let toStorageIdentityKey: String
    public let outputs: [StorageOutput]
    public let baskets: [StorageOutputBasket]

    public init(fromStorageIdentityKey: String, toStorageIdentityKey: String,
                outputs: [StorageOutput], baskets: [StorageOutputBasket]) {
        self.fromStorageIdentityKey = fromStorageIdentityKey
        self.toStorageIdentityKey = toStorageIdentityKey
        self.outputs = outputs
        self.baskets = baskets
    }
}

public struct SyncChunkResult: Equatable, Sendable {
    public let inserts: Int
    public let updates: Int
    /// True once a chunk comes back with nothing in it, which is how the catch-up loop ends.
    public let done: Bool

    public init(inserts: Int, updates: Int, done: Bool) {
        self.inserts = inserts
        self.updates = updates
        self.done = done
    }
}

/// Raised by a conforming type for a capability it does not provide.
///
/// Go's toolbox uses `panic("implement me")` for the eight BRC-100 methods it has not built. That
/// is a language habit, not a design decision worth copying into a wallet on somebody's phone.
public enum StorageError: Error, Equatable, Sendable {
    case notImplemented(String)
    case notAvailable
}
