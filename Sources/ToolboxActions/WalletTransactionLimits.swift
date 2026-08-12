import BSVTransaction
import ToolboxStorage

/// The bounds this library builds wallet transactions within.
///
/// A thin alias over `StorageLimits.transaction`, which is the single source shared by every layer
/// that touches storage. Kept as a name here so the action layer reads naturally.
public enum WalletTransactionLimits {
    public static let standard: TransactionLimits = StorageLimits.transaction
}
