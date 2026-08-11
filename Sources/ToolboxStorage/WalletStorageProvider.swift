import Foundation
import BSVWallet
import ToolboxCore

/// What a wallet needs from wherever its records live.
///
/// The wallet-facing request and result types come from `BSVWallet` — the SDK already defines the
/// BRC-100 ABI, and a parallel set of near-identical types here would guarantee the two drift.
/// Only genuinely storage-shaped types are declared in this module: the ones with no meaning above
/// the storage boundary, such as a funded-but-unsigned action.
///
/// One protocol, satisfied today by a remote server and later by an on-device engine. Splitting it
/// into read, write and sync halves follows the TypeScript layering, and the reason is not
/// tidiness: a remote client can serve every method here, while an engine additionally implements
/// the business logic underneath. `isStorageProvider` is how a caller tells those apart.
///
/// Every method is `async throws`. Storage is a network hop until proven otherwise, and a protocol
/// that pretended it was local would force every implementation to lie.
public protocol WalletStorageReader: Sendable {
    func makeAvailable() async throws -> StorageSettings
    func findOutputs(_ query: FindOutputsQuery) async throws -> [StorageOutput]
    func findOutputBaskets(_ query: FindBasketsQuery) async throws -> [StorageOutputBasket]
    func listActions(
        _ auth: AuthID, _ request: WalletListActionsRequest
    ) async throws -> WalletListActionsResult
    func listOutputs(
        _ auth: AuthID, _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult
}

public protocol WalletStorageWriter: WalletStorageReader {
    /// Reserves inputs and creates the records for an action that is not yet signed.
    ///
    /// The result is the storage layer's view — funded, with change decided — and is not a
    /// transaction. Signing happens above this boundary, where the keys are.
    func createAction(
        _ auth: AuthID, _ request: WalletCreateActionRequest
    ) async throws -> StorageCreateActionResult

    /// Finalises an action's records and hands it on for broadcast.
    func processAction(
        _ auth: AuthID, _ request: StorageProcessActionRequest
    ) async throws -> StorageProcessActionResult

    func internalizeAction(
        _ auth: AuthID, _ request: WalletInternalizeActionRequest
    ) async throws -> WalletInternalizeActionResult
    func abortAction(
        _ auth: AuthID, _ request: WalletAbortActionRequest
    ) async throws -> WalletAbortActionResult
    func relinquishOutput(
        _ auth: AuthID, _ request: WalletRelinquishOutputRequest
    ) async throws -> WalletRelinquishOutputResult
}

/// Reconciliation between two stores holding the same user's records.
///
/// Not used in v1 — there is one store and nothing to reconcile with. It is declared now because
/// the chunk cursor shape constrains the record types, and discovering that later would mean
/// changing them after they are in use.
public protocol WalletStorageSync: WalletStorageWriter {
    func getSyncChunk(_ request: SyncChunkRequest) async throws -> SyncChunk
    func processSyncChunk(_ chunk: SyncChunk) async throws -> SyncChunkResult
}

public protocol WalletStorageProvider: WalletStorageSync {
    /// True for an engine that owns the records, false for a client that forwards to one.
    ///
    /// The distinction is load-bearing rather than informational: a caller holding only a client
    /// must not assume it can perform operations that require the records themselves.
    var isStorageProvider: Bool { get }
}

/// Identifies the authenticated user on every call.
///
/// The remote protocol passes this as the first parameter of every method. It is a parameter and
/// not connection state because one authenticated transport may act for one identity while the
/// records belong to a user row the server resolves separately.
public struct AuthID: Equatable, Sendable {
    public let identityKey: String
    public let userID: Int?

    public init(identityKey: String, userID: Int? = nil) {
        self.identityKey = identityKey
        self.userID = userID
    }
}
