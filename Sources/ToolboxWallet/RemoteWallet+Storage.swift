import BSVWallet

/// The BRC-100 operations whose state is owned entirely by storage.
extension RemoteWallet {
    /// Lists matching actions. Storage's private `customInstructions` are deliberately removed at
    /// the wallet boundary, matching the live TypeScript wallet's security policy.
    public func listActions(
        _ request: WalletListActionsRequest
    ) async throws -> WalletListActionsResult {
        let result = try await storage.listActions(auth, request)
        let actions = try result.actions.map { action in
            let outputs = try action.outputs?.map { output in
                try WalletActionOutput(
                    satoshis: output.satoshis,
                    lockingScript: output.lockingScript,
                    spendable: output.spendable,
                    customInstructions: nil,
                    tags: output.tags,
                    outputIndex: output.outputIndex,
                    outputDescription: output.outputDescription,
                    basket: output.basket
                )
            }
            return try WalletAction(
                transactionID: action.transactionID,
                satoshis: action.satoshis,
                status: action.status,
                isOutgoing: action.isOutgoing,
                description: action.description,
                labels: action.labels,
                version: action.version,
                lockTime: action.lockTime,
                inputs: action.inputs,
                outputs: outputs
            )
        }
        return try WalletListActionsResult(totalActions: result.totalActions, actions: actions)
    }

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
