import Foundation

/// Failures the wallet raises directly.
///
/// The concrete wallet is `RemoteWallet`. This type is only the small set of errors that belong to
/// the wallet layer rather than to storage, actions, or auth beneath it.
public enum WalletError: Error, Equatable, Sendable {
    /// Raised by the certificate, key-linkage and identity-discovery methods, which v1 does not
    /// provide. Go's toolbox leaves the same eight methods unbuilt; it panics, and this throws.
    case notImplemented(String)
    case identityMismatch
    /// A storage reference that is not valid base64, so it cannot be sent back.
    case invalidReference
    /// The payment broadcast, but the recipient paymail host could not be notified. The money is
    /// on chain under this txid.
    case paymailDeliveryFailed(txid: String)
}
