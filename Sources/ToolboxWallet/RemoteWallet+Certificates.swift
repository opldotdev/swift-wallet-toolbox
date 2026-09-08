import BSVWallet

extension RemoteWallet {
    /// Lists certificates owned by this wallet, filtered and paginated by storage.
    public func listCertificates(
        _ request: WalletListCertificatesRequest
    ) async throws -> WalletListCertificatesResult {
        try await storage.listCertificates(auth, request)
    }
}
