import BSVWallet
import ToolboxCore
import ToolboxStorage

/// The BRC-100 operations whose state is owned entirely by storage.
extension RemoteWallet {
    /// Lists matching actions. Storage's private `customInstructions` are deliberately removed at
    /// the wallet boundary, matching the live TypeScript wallet's security policy.
    public func listActions(
        _ request: WalletListActionsRequest
    ) async throws -> WalletListActionsResult {
        let result = try await storage.listActions(auth, request)
        // A row the BRC-100 types refuse is left out of the listing, and the reason is logged.
        let actions: [WalletAction] = result.actions.compactMap { action -> WalletAction? in
            let outputs = action.outputs.map { rows in
                rows.compactMap { output -> WalletActionOutput? in
                    do {
                        return try WalletActionOutput(
                            satoshis: output.satoshis,
                            lockingScript: output.lockingScript,
                            spendable: output.spendable,
                            customInstructions: nil,
                            tags: output.tags,
                            outputIndex: output.outputIndex,
                            outputDescription: output.outputDescription,
                            basket: output.basket
                        )
                    } catch {
                        Self.logDroppedRow("an output of action \(action.transactionID)", error)
                        return nil
                    }
                }
            }
            do {
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
            } catch {
                Self.logDroppedRow("action \(action.transactionID)", error)
                return nil
            }
        }
        do {
            return try WalletListActionsResult(totalActions: result.totalActions, actions: actions)
        } catch {
            ToolboxLog.error("ToolboxWallet", "listActions: the result was refused with inputs and "
                + "outputs, so they are left out: \(ErrorDetail.describe(error))")
            // Each row was accepted above with more fields; one refused with fewer is a row the
            // result could not hold either way, and the failure above is already logged.
            let stripped = actions.compactMap { action in
                try? WalletAction(
                    transactionID: action.transactionID,
                    satoshis: action.satoshis,
                    status: action.status,
                    isOutgoing: action.isOutgoing,
                    description: action.description,
                    labels: action.labels,
                    version: action.version,
                    lockTime: action.lockTime
                )
            }
            return try WalletListActionsResult(totalActions: result.totalActions, actions: stripped)
        }
    }

    private static func logDroppedRow(_ what: String, _ error: any Error) {
        ToolboxLog.error("ToolboxWallet", "listActions left out \(what): \(ErrorDetail.describe(error))")
    }

    /// Abandons an unfinished action and returns storage's actual decision. A signed `noSend`
    /// action may already be known to the network, in which case current reference storage
    /// deliberately returns `aborted: false` rather than pretending it was released.
    public func abortAction(
        _ request: WalletAbortActionRequest
    ) async throws -> WalletAbortActionResult {
        await pendingActions.remove(request.reference.base64)
        return try await storage.abortAction(auth, request)
    }

    /// Lists the outputs in the requested application basket without applying any 1Sat-specific
    /// basket aliases or naming conventions.
    ///
    /// A BRC-112 balance request, basket `balance <basket>`, asks storage for the balance of
    /// `<basket>` instead: `totalOutputs` is the sum of its satoshis and `outputs` is empty. Only
    /// this method reads the prefix; the wallet's own `balance(basket:)` and permission-token
    /// reads call storage directly with baskets that never carry it.
    public func listOutputs(
        _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult {
        try await storage.listOutputs(auth, try Self.balanceBasketRequest(request))
    }

    /// TS `Wallet.ts` `validateListOutputsArgs` (BRC-112).
    ///
    /// The basket is read as the SDK validates it, trimmed and lowercased, within 1...300 bytes.
    /// `balance <basket>` becomes `<basket>` with the wallet-balance special-operation tag appended
    /// after the caller's tags, which storage answers with the sum of that basket's satoshis.
    /// `balance p <module> <basket>` is refused: a BRC-99 module that offers a balance does so as
    /// `p <module> balance <basket>`, which the module handles. A basket without the prefix goes to
    /// storage as the caller wrote it, and storage normalizes it as it does any basket.
    ///
    /// Stricter than TS on purpose: the remainder after `balance ` is normalized again before the
    /// `p ` check, because storage trims the basket it receives. TS leaves the remainder as cut and
    /// its storage looks the name up literally, so `balance  default` (two spaces) is the default
    /// basket's balance here but 0 in TS, and `balance  p color abc` is refused here but 0 in TS.
    /// Checking the untrimmed remainder would let that spelling reach storage as `p color abc`.
    static func balanceBasketRequest(_ request: WalletListOutputsRequest) throws -> WalletListOutputsRequest {
        let basket = try ActionBatchWire.identifier(request.basket, name: "basket")
        // Prefixes are matched on UTF-8 bytes, as TS `startsWith` matches code units: `balance `
        // followed by a combining mark is still a balance request, which `hasPrefix` would miss
        // because it compares whole characters. Both prefixes are ASCII, so cutting their bytes
        // leaves valid UTF-8.
        let balancePrefix = ListOutputsSpecOp.balanceBasketPrefix.utf8
        guard basket.utf8.starts(with: balancePrefix) else { return request }
        let target = try ActionBatchWire.identifier(
            String(decoding: basket.utf8.dropFirst(balancePrefix.count), as: UTF8.self), name: "basket"
        )
        if target.utf8.starts(with: ListOutputsSpecOp.moduleBasketPrefix.utf8) {
            throw WireError.invalidParameter(name: "basket", message: balanceOfModuleBasketRefusal)
        }
        // TS appends the tag after validation and never counts again, so a caller's legal maximum
        // of tags plus the balance tag must still build.
        let standard = WalletABILimits.standard
        let limits = try WalletABILimits(
            maximumTextUTF8ByteCount: standard.maximumTextUTF8ByteCount,
            maximumCollectionCount: standard.maximumCollectionCount,
            maximumTagCount: standard.maximumTagCount + 1,
            maximumLabelCount: standard.maximumLabelCount,
            maximumBytePayloadCount: standard.maximumBytePayloadCount,
            maximumAggregatePayloadByteCount: standard.maximumAggregatePayloadByteCount
        )
        return try WalletListOutputsRequest(
            basket: target, tags: request.tags + [ListOutputsSpecOp.walletBalance],
            tagQueryMode: request.tagQueryMode, include: request.include,
            includeCustomInstructions: request.includeCustomInstructions, includeTags: request.includeTags,
            includeLabels: request.includeLabels, pagination: request.pagination,
            seekPermission: request.seekPermission, limits: limits
        )
    }

    /// TS `Wallet.ts:1657-1661`, word for word.
    static let balanceOfModuleBasketRefusal = "not a BRC-99 module basket: BRC-112 rejects "
        + "`balance p <module> <basket>`; use `p <module> balance <basket>` if the module offers it."

    /// Stops tracking an output in a basket without spending it.
    public func relinquishOutput(
        _ request: WalletRelinquishOutputRequest
    ) async throws -> WalletRelinquishOutputResult {
        try await storage.relinquishOutput(auth, request)
    }
}

extension RemoteWallet: WalletOutputOperations {}
