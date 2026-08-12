import BSVWallet

extension RemoteWallet {
    /// The SDK kernel derives public keys from the same identity used by remote storage.
    public func getPublicKey(
        _ request: WalletGetPublicKeyRequest
    ) async throws -> WalletGetPublicKeyResult {
        try await protoWallet.getPublicKey(request)
    }

    /// The SDK kernel signs with keys derived from the wallet's identity.
    public func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        try await protoWallet.createSignature(request)
    }

    /// The SDK kernel verifies signatures under the same BRC-100 derivation rules.
    public func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        try await protoWallet.verifySignature(request)
    }

    /// The SDK kernel encrypts with keys derived from the wallet's identity.
    public func encrypt(
        _ request: WalletEncryptRequest
    ) async throws -> WalletEncryptResult {
        try await protoWallet.encrypt(request)
    }

    /// The SDK kernel decrypts with keys derived from the wallet's identity.
    public func decrypt(
        _ request: WalletDecryptRequest
    ) async throws -> WalletDecryptResult {
        try await protoWallet.decrypt(request)
    }

    /// The SDK kernel authenticates data with keys derived from the wallet's identity.
    public func createHMAC(
        _ request: WalletCreateHMACRequest
    ) async throws -> WalletCreateHMACResult {
        try await protoWallet.createHMAC(request)
    }

    /// The SDK kernel verifies authentication codes under the same BRC-100 derivation rules.
    public func verifyHMAC(
        _ request: WalletVerifyHMACRequest
    ) async throws -> WalletVerifyHMACResult {
        try await protoWallet.verifyHMAC(request)
    }
}
