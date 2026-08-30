import BSVWallet

/// The BRC-100 operations whose state is owned entirely by storage.
extension RemoteWallet {
    /// Abandons an unfinished action and returns storage's actual decision. A signed `noSend`
    /// action may already be known to the network, in which case current reference storage
    /// deliberately returns `aborted: false` rather than pretending it was released.
    public func abortAction(
        _ request: WalletAbortActionRequest
    ) async throws -> WalletAbortActionResult {
        try await storage.abortAction(auth, request)
    }

    /// Lists the outputs in the requested application basket without applying any 1Sat-specific
    /// basket aliases or naming conventions.
    public func listOutputs(
        _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult {
        try await storage.listOutputs(auth, request)
    }

    /// Stops tracking an output in a basket without spending it.
    public func relinquishOutput(
        _ request: WalletRelinquishOutputRequest
    ) async throws -> WalletRelinquishOutputResult {
        try await storage.relinquishOutput(auth, request)
    }
}

extension RemoteWallet: WalletOutputOperations {}
