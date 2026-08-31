import BSVWallet
import ToolboxPermissions

public enum RemoteWalletPermissionTokenAdapterError: Error, Equatable, Sendable {
    case invalidListRequest
}

/// Narrow, account-bound BRC-116 adapter over the exact `RemoteWallet` session and identity.
public struct RemoteWalletPermissionTokenAdapter: PermissionTokenWallet, Sendable {
    private let wallet: RemoteWallet
    public let permissionAccountID: PermissionAccountID

    public init(wallet: RemoteWallet) throws {
        self.wallet = wallet
        self.permissionAccountID = try wallet._permissionAccountID()
    }

    public func listPermissionTokenOutputs(
        _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult {
        guard PermissionTokenBasket.allCases.map(\.rawValue).contains(request.basket),
              request.include == .entireTransactions,
              request.seekPermission == false,
              request.tagQueryMode == .all,
              request.includeTags == true,
              request.pagination.limit == 100,
              Self.hasCanonicalTagShape(request) else {
            throw RemoteWalletPermissionTokenAdapterError.invalidListRequest
        }
        return try await wallet._listPermissionTokenOutputs(request)
    }

    private static func hasCanonicalTagShape(_ request: WalletListOutputsRequest) -> Bool {
        let tags = request.tags
        switch PermissionTokenBasket(rawValue: request.basket) {
        case .protocolPermission:
            return (tags.count == 4 || tags.count == 5)
                && tags[0].hasPrefix("originator ")
                && tags[1].hasPrefix("privileged ")
                && tags[2].hasPrefix("protocolName ")
                && tags[3].hasPrefix("protocolSecurityLevel ")
                && (tags.count == 4 || tags[4].hasPrefix("counterparty "))
        case .basketAccess:
            return tags.count == 2
                && tags[0].hasPrefix("originator ")
                && tags[1].hasPrefix("basket ")
        case .certificateAccess:
            return tags.count == 4
                && tags[0].hasPrefix("originator ")
                && tags[1].hasPrefix("privileged ")
                && tags[2].hasPrefix("type ")
                && tags[3].hasPrefix("verifier ")
        case .spendingAuthorization:
            return tags.count == 1 && tags[0].hasPrefix("originator ")
        case nil:
            return false
        }
    }

    public func commitPermissionTokenMutation(
        _ request: PermissionTokenMutationRequest
    ) async throws -> PermissionTokenMutationResult {
        try await wallet._commitPermissionTokenMutation(request, using: self)
    }

    public func getPublicKey(
        _ request: WalletGetPublicKeyRequest
    ) async throws -> WalletGetPublicKeyResult {
        try await wallet.getPublicKey(request)
    }

    public func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult {
        try await wallet.encrypt(request)
    }

    public func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult {
        try await wallet.decrypt(request)
    }

    public func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        try await wallet.createSignature(request)
    }

    public func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        try await wallet.verifySignature(request)
    }
}
