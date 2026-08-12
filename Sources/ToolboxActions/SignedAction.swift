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

    public init(
        reference: String,
        transaction: Transaction,
        limits: TransactionLimits = WalletTransactionLimits.standard
    ) throws {
        self.reference = reference
        self.transaction = transaction
        self.transactionID = try transaction.transactionID(limits: limits)
    }

    /// The BRC-95 envelope to hand back.
    ///
    /// `sourceTransactions` is required, not optional, because an Atomic BEEF must carry the whole
    /// proof graph: every transaction this one spends has to be inside it or the envelope is
    /// invalid. A verifier cannot check an input it cannot see, and the SDK refuses to build one
    /// with a missing ancestor rather than producing bytes that fail at the far end.
    ///
    /// Storage supplies these as `inputBEEF` on the funded action.
    public func atomicBEEF(
        sourceTransactions: [Transaction],
        limits: BEEFLimits = WalletBEEFLimits.standard
    ) throws -> [UInt8] {
        let beef = try BEEF(
            merklePaths: [],
            transactions: sourceTransactions.map { .raw($0) } + [.raw(transaction)],
            limits: limits
        )
        return try AtomicBEEF(
            subjectTransactionID: transactionID,
            beef: beef,
            limits: limits
        ).serialized(limits: limits)
    }

    /// What storage needs to finalise and send this.
    public func processRequest(sendWith: [String] = []) -> StorageProcessActionRequest {
        StorageProcessActionRequest(
            reference: reference,
            isNewTx: true,
            isSendWith: !sendWith.isEmpty,
            rawTX: nil,
            sendWith: sendWith
        )
    }
}

/// The bounds this library reads and writes BEEF within.
///
/// As with `WalletTransactionLimits`, the SDK offers no default on purpose. A wallet does have an
/// opinion: an envelope for one payment is small, and one large enough to exhaust memory is not a
/// payment.
public enum WalletBEEFLimits {
    /// A megabyte of merkle path, with leaf counts a real proof never approaches.
    public static let merklePath: MerklePathLimits = {
        try! MerklePathLimits(
            maximumByteCount: 1 << 20,
            maximumLeavesPerLevel: 100_000,
            maximumTotalLeaves: 1_000_000
        )
    }()

    /// Eight megabytes of envelope holding at most ten thousand transactions and proofs.
    public static let standard: BEEFLimits = {
        // Constants that satisfy every check the initialiser makes.
        try! BEEFLimits(
            maximumByteCount: 8 << 20,
            maximumMerklePathCount: 10_000,
            maximumTransactionCount: 10_000,
            transactionLimits: WalletTransactionLimits.standard,
            merklePathLimits: merklePath
        )
    }()
}
