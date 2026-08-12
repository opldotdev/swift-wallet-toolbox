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
    /// The ancestor transactions this one spends, taken from the funded action's proof graph. The
    /// envelope must carry them, because a verifier cannot check an input it cannot see.
    let sourceTransactions: [Transaction]
    private let beefLimits: BEEFLimits
    private let transactionLimits: TransactionLimits

    /// Packages a signed transaction using the proof graph from the action that funded it.
    ///
    /// `funded.inputBEEF` is the graph storage returned. It is parsed here and its transactions
    /// become the ancestors of the outgoing envelope. When storage returned none, the envelope
    /// carries the subject transaction alone — valid only when the transaction has no inputs, which
    /// is why the graph is normally present.
    public init(
        funded: StorageCreateActionResult,
        transaction: Transaction,
        transactionLimits: TransactionLimits = WalletTransactionLimits.standard,
        beefLimits: BEEFLimits = WalletBEEFLimits.standard
    ) throws {
        self.reference = funded.reference
        self.transaction = transaction
        self.transactionID = try transaction.transactionID(limits: transactionLimits)
        self.transactionLimits = transactionLimits
        self.beefLimits = beefLimits
        if let graph = funded.inputBEEF {
            let parsed = try BEEF(bytes: graph, limits: beefLimits)
            self.sourceTransactions = parsed.transactions.compactMap { $0.transaction }
        } else {
            self.sourceTransactions = []
        }
    }

    /// The BRC-95 envelope to hand back.
    ///
    /// Atomic BEEF must carry the whole proof graph: every transaction this one spends has to be
    /// inside it or the envelope is invalid. The SDK refuses to build one with a missing ancestor
    /// rather than producing bytes that fail at the far end.
    public func atomicBEEF() throws -> [UInt8] {
        let beef = try BEEF(
            merklePaths: [],
            transactions: sourceTransactions.map { .raw($0) } + [.raw(transaction)],
            limits: beefLimits
        )
        return try AtomicBEEF(
            subjectTransactionID: transactionID,
            beef: beef,
            limits: beefLimits
        ).serialized(limits: beefLimits)
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
