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
              request.includeCustomInstructions == nil,
              request.includeTags == true,
              request.includeLabels == nil,
              request.pagination.limit == 100,
              Self.hasCanonicalTagShape(request) else {
            throw RemoteWalletPermissionTokenAdapterError.invalidListRequest
        }
        return try await wallet._listPermissionTokenOutputs(request)
    }

    private static func hasCanonicalTagShape(_ request: WalletListOutputsRequest) -> Bool {
        let tags = request.tags
        func hasValue(_ tag: String, prefix: String) -> Bool {
            tag.hasPrefix(prefix) && tag.count > prefix.count
        }
        func isBoolean(_ tag: String, prefix: String) -> Bool {
            tag == "\(prefix)true" || tag == "\(prefix)false"
        }
        switch PermissionTokenBasket(rawValue: request.basket) {
        case .protocolPermission:
            let levelOne = tags.count == 4 && tags[3] == "protocolSecurityLevel 1"
            let levelTwo = tags.count == 5 && tags[3] == "protocolSecurityLevel 2"
                && hasValue(tags[4], prefix: "counterparty ")
            return (levelOne || levelTwo)
                && hasValue(tags[0], prefix: "originator ")
                && isBoolean(tags[1], prefix: "privileged ")
                && hasValue(tags[2], prefix: "protocolName ")
        case .basketAccess:
            return tags.count == 2
                && hasValue(tags[0], prefix: "originator ")
                && hasValue(tags[1], prefix: "basket ")
        case .certificateAccess:
            return tags.count == 4
                && hasValue(tags[0], prefix: "originator ")
                && isBoolean(tags[1], prefix: "privileged ")
                && hasValue(tags[2], prefix: "type ")
                && hasValue(tags[3], prefix: "verifier ")
        case .spendingAuthorization:
            return tags.count == 1 && hasValue(tags[0], prefix: "originator ")
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
