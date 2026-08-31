import BSVWallet

/// The narrow wallet surface needed to read canonical BRC-116 permission tokens.
///
/// This deliberately does not inherit `WalletInterface`: an adapter can expose only
/// account-bound token queries plus the cryptographic operations used by the codec.
public protocol PermissionTokenWallet:
    WalletPublicKeyProviding,
    WalletCipherOperations,
    WalletSignatureOperations,
    Sendable
{
    var permissionAccountID: PermissionAccountID { get }

    func listPermissionTokenOutputs(
        _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult
}
