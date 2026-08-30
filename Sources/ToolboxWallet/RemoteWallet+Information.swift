import BSVWallet

/// Authentication and implementation information that a BRC-100 client can query without
/// spending. A `RemoteWallet` is already set up with the user's identity key when it is created,
/// matching the live TypeScript and Go wallets' authentication semantics.
extension RemoteWallet {
    public func isAuthenticated(
        _ request: WalletIsAuthenticatedRequest
    ) async throws -> WalletAuthenticatedResult {
        WalletAuthenticatedResult(authenticated: true)
    }

    public func waitForAuthentication(
        _ request: WalletWaitForAuthenticationRequest
    ) async throws -> WalletAuthenticatedResult {
        WalletAuthenticatedResult(authenticated: true)
    }

    /// Reads the configured chain from the storage settings. This intentionally makes storage
    /// available instead of assuming that every application build uses mainnet.
    public func getNetwork(
        _ request: WalletGetNetworkRequest
    ) async throws -> WalletGetNetworkResult {
        let settings = try await storage.makeAvailable(auth)
        switch settings.chain {
        case .main:
            return WalletGetNetworkResult(network: .mainnet)
        case .test:
            return WalletGetNetworkResult(network: .testnet)
        }
    }

    /// The interoperable BRC-100 implementation identifier returned by the live TypeScript wallet
    /// and BSV Desktop vector. It is deliberately not this Swift package's release version.
    public func getVersion(
        _ request: WalletGetVersionRequest
    ) async throws -> WalletGetVersionResult {
        try WalletGetVersionResult(version: "wallet-brc100-1.0.0")
    }
}

extension RemoteWallet: WalletAuthenticationOperations {}
