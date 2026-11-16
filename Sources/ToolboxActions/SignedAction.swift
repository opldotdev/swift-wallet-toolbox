import BSVCore
import BSVTransaction
import BSVWallet
import ToolboxStorage

/// A signed transaction, packaged for storage to broadcast.
///
/// Wallet callers receive BRC-95 Atomic BEEF: the subject transaction with exactly the proof graph
/// needed to verify it, and nothing else. "Exactly" is the part that matters — an envelope
/// carrying unrelated transactions is refused by a conforming reader — so the funded graph is cut
/// to the subject's ancestry rather than passed through whole.
/// Storage finalization separately receives raw transaction bytes and the transaction ID.
///
/// Only the BEEF accessors depend on that graph. `processRequest` needs the reference and the raw
/// transaction alone, as the TypeScript client's `processAction` does, so a funded graph that
/// cannot prove the subject never stops the action from being processed; it fails only when
/// Atomic BEEF or BEEF is asked for.
public struct SignedAction: Sendable {
    /// The storage reference the funded action was created under. `processAction` matches the
    /// signed transaction to its reserved inputs by this, so it travels with it.
    public let reference: String
    public let transaction: Transaction
    public let transactionID: TransactionID
    /// The BRC-95 envelope, or why it cannot be built. The funded graph's BUMPs, BRC-96
    /// transaction-ID anchors and BEEF version are kept as storage supplied them.
    private let envelope: Result<AtomicBEEF, any Error>
    private let beefLimits: BEEFLimits

    /// Packages a signed transaction using the proof graph from the action that funded it.
    ///
    /// `funded.inputBEEF` is the graph storage returned. `@bsv/sdk` writes BEEF with every proven
    /// transaction in the order it was merged, then each unproven one, so a proven child can sit
    /// ahead of its proven parent and an unproven transaction ahead of its own parents. It is read
    /// in any order and reordered parents-first, as that SDK's reader accepts it.
    ///
    /// The graph is then cut to what the subject spends: its inputs' transactions and, below any
    /// without a merkle path, their parents. Records outside that ancestry are dropped, as
    /// `Beef.toBinaryAtomic` in `@bsv/sdk` leaves them out of what it verifies. The subject is
    /// appended and the envelope checked against BRC-95. A graph that is missing an ancestor or
    /// carries conflicting BUMPs is kept as the reason `atomicBEEF()` and `beef()` throw.
    ///
    /// This throws only when the funded bytes cannot be read, or when they already hold a
    /// transaction with the subject's ID.
    public init(
        funded: StorageCreateActionResult,
        transaction: Transaction,
        transactionLimits: TransactionLimits = WalletTransactionLimits.standard,
        beefLimits: BEEFLimits = WalletBEEFLimits.standard
    ) throws {
        self.reference = funded.reference
        self.transaction = transaction
        let transactionID = try transaction.transactionID(limits: transactionLimits)
        self.transactionID = transactionID
        self.beefLimits = beefLimits

        let sourceGraph: BEEF
        if let graph = funded.inputBEEF {
            sourceGraph = try BEEF(bytes: graph, limits: beefLimits, transactionOrder: .any)
        } else {
            sourceGraph = try BEEF(
                version: .v2,
                merklePaths: [],
                transactions: [],
                limits: beefLimits
            )
        }
        if try sourceGraph.transactions.contains(where: {
            try $0.transactionID(limits: beefLimits.transactionLimits) == transactionID
        }) {
            throw BEEFError.duplicateTransactionID(transactionID)
        }
        self.envelope = Result {
            let ancestry = try ActionBatchBEEF.subgraph(
                sourceGraph,
                txids: transaction.inputs.map(\.previousOutput.transactionID),
                limits: beefLimits
            )
            let completeGraph = try BEEF(
                version: ancestry.version,
                merklePaths: ancestry.merklePaths,
                transactions: ancestry.transactions + [.raw(transaction)],
                limits: beefLimits
            )
            // Atomic BEEF requires an exact ancestry graph, while this additional check rejects
            // two otherwise well-formed BUMPs that claim different roots for one block height.
            _ = try completeGraph.merkleRootsByBlockHeight()
            let envelope = try AtomicBEEF(
                subjectTransactionID: transactionID,
                beef: completeGraph,
                limits: beefLimits
            )
            _ = try envelope.serialized(limits: beefLimits)
            return envelope
        }
    }

    /// The BRC-95 envelope to hand back.
    ///
    /// Atomic BEEF must carry the whole proof graph: every transaction this one spends has to be
    /// inside it or the envelope is invalid. This throws the `BEEFError` that stopped the
    /// envelope being built (a missing ancestor, conflicting BUMPs, or a size bound) rather than
    /// producing bytes that fail at the far end.
    public func atomicBEEF() throws -> [UInt8] {
        try envelope.get().serialized(limits: beefLimits)
    }

    /// BRC-62 BEEF for paymail receive-BEEF (`5c55a7fdb7bb`).
    ///
    /// BRC-70 and `Transaction.toBEEF()` in `@bsv/sdk` emit version
    /// `4022206465` (`0100BEEF`). Storage's funded graph is often BRC-96 v2
    /// (`0200BEEF`). HandCash's receive-beef parser is the BRC-62 reader:
    /// v2 bytes are rejected after the payment is already on chain.
    /// Atomic BEEF (`0x01010101`) is still `atomicBEEF()`.
    public func beef() throws -> [UInt8] {
        let graph = try envelope.get().beef
        if graph.version == .v1 {
            return try graph.serialized(limits: beefLimits)
        }
        return try BEEF(
            version: .v1,
            merklePaths: graph.merklePaths,
            transactions: graph.transactions,
            limits: beefLimits
        ).serialized(limits: beefLimits)
    }

    /// What storage needs to finalise and send this: the reference and raw signed transaction.
    /// Without the transaction storage cannot commit or broadcast it, and the inputs
    /// it reserved stay reserved.
    ///
    /// `isNoSend` and `isDelayed` decide what storage does with it. A `noSend` action must say so
    /// here as well as at createAction: storage reads these flags, not the ones it was funded
    /// under, so a `false` broadcasts a transaction the caller meant to hold for a later batch.
    public func processRequest(
        sendWith: [String] = [], isNoSend: Bool = false, isDelayed: Bool = false
    ) throws -> StorageProcessActionRequest {
        StorageProcessActionRequest(
            reference: reference,
            isNewTx: true,
            isSendWith: !sendWith.isEmpty,
            rawTX: try transaction.serialized(limits: beefLimits.transactionLimits),
            sendWith: sendWith,
            isNoSend: isNoSend,
            isDelayed: isDelayed
        )
    }

    /// The process request for an action funded with these createAction options, with the
    /// reference client's defaults: `noSend` false, `acceptDelayedBroadcast` true, `sendWith` empty.
    public func processRequest(options: WalletCreateActionOptions?) throws -> StorageProcessActionRequest {
        try processRequest(
            sendWith: (options?.sendWith ?? []).map(\.displayHex),
            isNoSend: options?.noSend ?? false,
            isDelayed: options?.acceptDelayedBroadcast ?? true
        )
    }
}

/// The bounds this library reads and writes BEEF within, aliased to the shared `StorageLimits`.
public enum WalletBEEFLimits {
    public static let standard: BEEFLimits = StorageLimits.beef
}
