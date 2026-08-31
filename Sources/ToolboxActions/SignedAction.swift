import BSVCore
import BSVTransaction
import ToolboxStorage

/// A signed transaction, packaged for storage to broadcast.
///
/// Storage takes BRC-95 Atomic BEEF: the subject transaction together with exactly the proof graph
/// needed to verify it, and nothing else. "Exactly" is the part that matters — an envelope
/// carrying unrelated transactions is refused by a conforming reader, so this builds the graph
/// from what the action actually spends rather than from whatever happens to be at hand.
public struct SignedAction: Sendable {
    /// The storage reference the funded action was created under. `processAction` matches the
    /// signed transaction to its reserved inputs by this, so it travels with it.
    public let reference: String
    public let transaction: Transaction
    public let transactionID: TransactionID
    /// The validated BRC-95 envelope, including the funded graph exactly as storage supplied it.
    /// Keeping the envelope rather than flattening it to raw transactions preserves BUMPs,
    /// BRC-96 transaction-ID anchors, and the original BEEF version.
    private let envelope: AtomicBEEF
    private let beefLimits: BEEFLimits

    /// Packages a signed transaction using the proof graph from the action that funded it.
    ///
    /// `funded.inputBEEF` is the graph storage returned. The signed subject is appended without
    /// changing that graph's version, entries, or BUMPs, then BRC-95 validation proves that every
    /// retained record belongs to the subject's ancestry and that no ancestor is missing. A funded
    /// graph that is unrelated, incomplete, internally conflicting, or collides with the subject is
    /// rejected here, before a process request can be produced.
    public init(
        funded: StorageCreateActionResult,
        transaction: Transaction,
        transactionLimits: TransactionLimits = WalletTransactionLimits.standard,
        beefLimits: BEEFLimits = WalletBEEFLimits.standard
    ) throws {
        self.reference = funded.reference
        self.transaction = transaction
        self.transactionID = try transaction.transactionID(limits: transactionLimits)
        self.beefLimits = beefLimits

        let sourceGraph: BEEF
        if let graph = funded.inputBEEF {
            sourceGraph = try BEEF(bytes: graph, limits: beefLimits)
        } else {
            sourceGraph = try BEEF(
                version: .v2,
                merklePaths: [],
                transactions: [],
                limits: beefLimits
            )
        }
        let completeGraph = try BEEF(
            version: sourceGraph.version,
            merklePaths: sourceGraph.merklePaths,
            transactions: sourceGraph.transactions + [.raw(transaction)],
            limits: beefLimits
        )
        // Atomic BEEF requires an exact ancestry graph, while this additional check rejects two
        // otherwise well-formed BUMPs that claim different roots for the same block height.
        _ = try completeGraph.merkleRootsByBlockHeight()
        let envelope = try AtomicBEEF(
            subjectTransactionID: transactionID,
            beef: completeGraph,
            limits: beefLimits
        )
        // Validate the final outer-envelope byte bound now, not after storage has been called.
        _ = try envelope.serialized(limits: beefLimits)
        self.envelope = envelope
    }

    /// The BRC-95 envelope to hand back.
    ///
    /// Atomic BEEF must carry the whole proof graph: every transaction this one spends has to be
    /// inside it or the envelope is invalid. The SDK refuses to build one with a missing ancestor
    /// rather than producing bytes that fail at the far end.
    public func atomicBEEF() throws -> [UInt8] {
        try envelope.serialized(limits: beefLimits)
    }

    /// What storage needs to finalise and send this: the reference, and the signed transaction as
    /// Atomic BEEF. Without the transaction storage cannot commit or broadcast it, and the inputs
    /// it reserved stay reserved.
    public func processRequest(sendWith: [String] = []) throws -> StorageProcessActionRequest {
        StorageProcessActionRequest(
            reference: reference,
            isNewTx: true,
            isSendWith: !sendWith.isEmpty,
            rawTX: try atomicBEEF(),
            sendWith: sendWith
        )
    }
}

/// The bounds this library reads and writes BEEF within, aliased to the shared `StorageLimits`.
public enum WalletBEEFLimits {
    public static let standard: BEEFLimits = StorageLimits.beef
}
