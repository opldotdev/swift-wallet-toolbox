import BSVTransaction

/// The bounds this library builds wallet transactions within.
///
/// `swift-sdk` offers no default, on purpose: it has no unbounded decode path and no opinion about
/// what any particular application should accept. A wallet does have an opinion, so it is stated
/// here, once, rather than guessed at each call site.
///
/// These are not consensus rules. They are what a wallet talking to a remote store should be
/// willing to assemble, chosen to be generous enough for ordinary payments and data outputs while
/// still refusing a response large enough to be a denial of service. A caller that genuinely needs
/// more passes its own.
public enum WalletTransactionLimits {

    /// Four megabytes of transaction, a hundred thousand inputs or outputs, and a megabyte of
    /// script. A payment reaches none of these; a hostile server reaches all of them.
    public static let standard: TransactionLimits = {
        // The values are constants and satisfy every check the initialiser makes, so this cannot
        // fail. A wallet that could not describe its own limits has nothing to fall back to.
        try! TransactionLimits(
            maximumTransactionByteCount: 4 << 20,
            maximumInputCount: 100_000,
            maximumOutputCount: 100_000,
            maximumScriptByteCount: 1 << 20
        )
    }()
}
