import BSVTransaction

/// The decode and encode bounds this library applies to transactions and BEEF.
///
/// `swift-sdk` offers no defaults on purpose: it has no unbounded path and no opinion about what an
/// application should accept. A wallet does have an opinion, and it belongs low in the stack so
/// every layer that touches storage shares one set of bounds rather than each inventing its own.
///
/// These are not consensus rules. They are what a wallet talking to a remote store is willing to
/// assemble or read — generous for real payments and data, far below a memory problem.
public enum StorageLimits {

    public static let transaction: TransactionLimits = {
        // Constants that satisfy every check the initialiser makes.
        try! TransactionLimits(
            maximumTransactionByteCount: 4 << 20,
            maximumInputCount: 100_000,
            maximumOutputCount: 100_000,
            maximumScriptByteCount: 1 << 20
        )
    }()

    public static let merklePath: MerklePathLimits = {
        try! MerklePathLimits(
            maximumByteCount: 1 << 20,
            maximumLeavesPerLevel: 100_000,
            maximumTotalLeaves: 1_000_000
        )
    }()

    public static let beef: BEEFLimits = {
        try! BEEFLimits(
            maximumByteCount: 8 << 20,
            maximumMerklePathCount: 10_000,
            maximumTransactionCount: 10_000,
            transactionLimits: transaction,
            merklePathLimits: merklePath
        )
    }()
}
