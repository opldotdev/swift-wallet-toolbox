import BSVWallet

extension RemoteWallet {
    /// Reveals the BRC-69 counterparty linkage through the offline SDK kernel.
    ///
    /// `ProtoWallet` owns the BRC-72 encryption, BRC-94 proof generation, self-linkage rejection,
    /// and privileged-request policy. Keeping this as a direct delegation prevents the composed
    /// wallet from weakening or duplicating those security-sensitive semantics.
    public func revealCounterpartyKeyLinkage(
        _ request: WalletRevealCounterpartyKeyLinkageRequest
    ) async throws -> WalletRevealCounterpartyKeyLinkageResult {
        try await protoWallet.revealCounterpartyKeyLinkage(request)
    }

    /// Reveals one BRC-69 derived-key linkage through the offline SDK kernel.
    public func revealSpecificKeyLinkage(
        _ request: WalletRevealSpecificKeyLinkageRequest
    ) async throws -> WalletRevealSpecificKeyLinkageResult {
        try await protoWallet.revealSpecificKeyLinkage(request)
    }
}

extension RemoteWallet: WalletLinkageOperations {}
