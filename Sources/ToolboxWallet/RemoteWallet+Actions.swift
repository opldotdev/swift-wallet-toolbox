import BSVCore
import Foundation
import BSVInterpreter
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxActions
import ToolboxBRC29
import ToolboxPermissions
import ToolboxStorage

/// Per-wallet, ephemeral create/sign state. No private key is retained here.
/// Removal precedes signing, so concurrent/replayed sign requests cannot both run.
actor PendingWalletActions {
    struct Entry: Sendable {
        let request: WalletCreateActionRequest
        let funded: StorageCreateActionResult
        let transaction: Transaction
        let sources: BEEF
    }
    private var entries: [String: Entry] = [:]

    func insert(_ entry: Entry) throws {
        guard entries.count < 128, entries[entry.funded.reference] == nil else {
            throw WalletActionLifecycleError.pendingActionLimit
        }
        entries[entry.funded.reference] = entry
    }

    func take(_ reference: String) throws -> Entry {
        guard let entry = entries.removeValue(forKey: reference) else {
            throw WalletActionLifecycleError.unknownReference
        }
        return entry
    }

    func remove(_ reference: String) { entries.removeValue(forKey: reference) }

    func review(_ reference: String) throws -> SpendingReview {
        guard let entry = entries[reference] else { throw WalletActionLifecycleError.unknownReference }
        let commission = entry.funded.outputs.filter(\.isCommission).reduce(UInt64(0)) { $0 + $1.satoshis }
        let sources = Dictionary(uniqueKeysWithValues: entry.transaction.inputs.map { ($0.previousOutput, $0.sourceOutput!) })
        return try SpendingReview(
            request: entry.request, transaction: entry.transaction, sourceOutputs: sources,
            storageCommissionSatoshis: commission
        )
    }
}

public enum WalletActionLifecycleError: Error, Equatable, Sendable {
    case unknownReference
    case pendingActionLimit
    case invalidFunding
    case invalidSpend
    case unsupportedBatch
}

extension RemoteWallet {
    public var storageEndpoint: URL { storage.endpoint }

    /// Numeric review of the validated pending transaction, including any bounded storage fee.
    public func reviewAction(reference: WalletBase64Data) async throws -> SpendingReview {
        try await pendingActions.review(reference.base64)
    }
    /// BRC-100 create/sign lifecycle. Permission-aware hosts force `signAndProcess: false`,
    /// review the returned unsigned transaction, then call signAction only after consent.
    public func createAction(_ request: WalletCreateActionRequest) async throws -> WalletCreateActionResult {
        // Batch-only processing needs an originator-owned sent-action ledger. Do not quietly
        // broadcast arbitrary pre-existing transactions as a side effect of a new approval.
        guard !(request.inputs ?? []).isEmpty || !(request.outputs ?? []).isEmpty,
              (request.options?.sendWith ?? []).isEmpty else {
            throw WalletActionLifecycleError.unsupportedBatch
        }
        let funded = try await storage.createAction(auth, request, includeAllSourceTransactions: true)
        do {
            _ = try WalletBase64Data(base64: funded.reference)
            try Task.checkCancellation()
            let ordered = try Self.orderActionInputs(funded)
            guard ordered.version == (request.version ?? 1),
                  ordered.lockTime == (request.lockTime ?? 0) else {
                throw WalletActionLifecycleError.invalidFunding
            }
            try ActionAssembler.requireFeeWithin(maximumFee, for: ordered)
            var transaction = try ActionAssembler.assemble(
                ordered, requested: request.outputs ?? [], changeKey: identityKey
            )
            let requested = request.inputs ?? []
            guard requested.count <= transaction.inputs.count,
                  Set(transaction.inputs.map(\.previousOutput)).count == transaction.inputs.count else {
                throw WalletActionLifecycleError.invalidFunding
            }
            for (index, input) in requested.enumerated() {
                // BRC-100 reserves the first vins for caller inputs in request order.
                guard transaction.inputs[index].previousOutput == input.outpoint else {
                    throw WalletActionLifecycleError.invalidFunding
                }
                transaction.inputs[index].sequence = input.sequenceNumber ?? 0xffff_ffff
                if case .script(let bytes) = input.unlocking {
                    transaction.inputs[index].unlockingScript = try Script(
                        bytes: bytes, maximumByteCount: Int(StorageLimits.transaction.maximumScriptByteCount)
                    )
                }
            }
            let sources = try Self.validatedFundedSourceGraph(
                ordered, subject: transaction, expectedSourceGraph: request.inputBEEF
            )
            // Resolve and validate every wallet input before presenting a signable transaction.
            // The actual signing keys exist only inside this operation, never in pending state.
            _ = try actionInputKeys(ordered, callerInputCount: requested.count)
            let entry = PendingWalletActions.Entry(
                request: request, funded: ordered, transaction: transaction, sources: sources
            )
            let deferred = request.options?.signAndProcess == false || requested.contains {
                if case .scriptLength = $0.unlocking { return true }; return false
            }
            if deferred {
                let atomic = try Self.atomicBEEF(
                    subject: transaction,
                    transactionID: transaction.transactionID(limits: StorageLimits.transaction),
                    sourceGraph: sources
                )
                let result = try WalletCreateActionResult(
                    noSendChange: Self.noSendChange(entry, transactionID: atomic.subjectTransactionID),
                    signableTransaction: .init(transaction: atomic, reference: WalletBase64Data(base64: ordered.reference))
                )
                try await pendingActions.insert(entry)
                return result
            }
            let signed = try await finishAction(entry, spends: [:], options: nil)
            return try WalletCreateActionResult(
                transactionID: signed.transactionID, transaction: signed.transaction,
                noSendChange: try Self.noSendChange(entry, transactionID: signed.transactionID),
                sendWithResults: signed.sendWithResults
            )
        } catch {
            _ = try? await storage.abortAction(auth, WalletAbortActionRequest(
                reference: WalletBase64Data(base64: funded.reference)
            ))
            throw error
        }
    }

    public func signAction(_ request: WalletSignActionRequest) async throws -> WalletSignActionResult {
        let entry = try await pendingActions.take(request.reference.base64)
        do {
            return try await finishAction(entry, spends: request.spends, options: request.options)
        } catch {
            // Do not reinsert after an ambiguous process response. A retry must never sign again.
            _ = try? await storage.abortAction(auth, WalletAbortActionRequest(reference: request.reference))
            throw error
        }
    }

    private func finishAction(
        _ entry: PendingWalletActions.Entry,
        spends: [UInt32: WalletSignActionSpend],
        options: WalletSignActionOptions?
    ) async throws -> WalletSignActionResult {
        let prior = entry.request.options
        guard (options?.sendWith ?? prior?.sendWith ?? []).isEmpty else {
            throw WalletActionLifecycleError.unsupportedBatch
        }
        let callerInputs = entry.request.inputs ?? []
        var transaction = entry.transaction
        for (vin, spend) in spends {
            guard let index = Int(exactly: vin), callerInputs.indices.contains(index),
                  case .scriptLength(let maximum) = callerInputs[index].unlocking,
                  spend.unlockingScript.count <= Int(maximum) else {
                throw WalletActionLifecycleError.invalidSpend
            }
            transaction.inputs[index].unlockingScript = try Script(
                bytes: spend.unlockingScript,
                maximumByteCount: Int(StorageLimits.transaction.maximumScriptByteCount)
            )
            if let sequence = spend.sequenceNumber { transaction.inputs[index].sequence = sequence }
        }
        for (index, input) in callerInputs.enumerated() {
            if case .scriptLength = input.unlocking, spends[UInt32(index)] == nil {
                throw WalletActionLifecycleError.invalidSpend
            }
        }
        let keys = try actionInputKeys(entry.funded, callerInputCount: callerInputs.count)
        try Task.checkCancellation()
        for (index, key) in keys {
            try transaction.signPayToPublicKeyHashInput(at: index, with: key, limits: StorageLimits.transaction)
        }
        let configuration = try ScriptExecutionConfiguration(
            era: .afterGenesis, flags: [.enableForkID], resourceLimits: .standard
        )
        for (index, input) in transaction.inputs.enumerated() {
            guard let source = input.sourceOutput else { throw WalletActionLifecycleError.invalidFunding }
            try Task.checkCancellation()
            _ = try ScriptInterpreter.execute(
                unlockingScript: input.unlockingScript, lockingScript: source.lockingScript,
                configuration: configuration,
                context: ScriptExecutionContext(
                    transaction: transaction, inputIndex: index, spentOutput: source,
                    transactionLimits: StorageLimits.transaction
                )
            )
        }
        let txid = try transaction.transactionID(limits: StorageLimits.transaction)
        let atomic = try Self.atomicBEEF(subject: transaction, transactionID: txid, sourceGraph: entry.sources)
        _ = try atomic.serialized(limits: StorageLimits.beef)
        let noSend = options?.noSend ?? prior?.noSend ?? false
        let process = StorageProcessActionRequest(
            reference: entry.funded.reference, isNewTx: true, isSendWith: false,
            rawTX: try transaction.serialized(limits: StorageLimits.transaction), sendWith: [], isNoSend: noSend,
            isDelayed: options?.acceptDelayedBroadcast ?? prior?.acceptDelayedBroadcast ?? true
        )
        try Task.checkCancellation()
        let result = try await storage.processAction(auth, process)
        return try WalletSignActionResult(
            transactionID: txid,
            transaction: (options?.returnTransactionIDOnly ?? prior?.returnTransactionIDOnly ?? false) ? nil : atomic,
            sendWithResults: result.sendWithResults.map {
                WalletSendWithResult(
                    transactionID: try TransactionID(displayHex: $0.txid),
                    status: WalletActionResultStatus(rawValue: $0.status.rawValue)!
                )
            }
        )
    }

    private func actionInputKeys(
        _ funded: StorageCreateActionResult, callerInputCount: Int
    ) throws -> [(Int, PrivateKey)] {
        try funded.inputs.enumerated().dropFirst(callerInputCount).map { index, input in
            guard let prefix = input.derivationPrefix, let suffix = input.derivationSuffix else {
                throw WalletActionLifecycleError.invalidFunding
            }
            let sender: PublicKey
            if let text = input.senderIdentityKey {
                guard let bytes = Self.hexBytes(text) else { throw WalletActionLifecycleError.invalidFunding }
                sender = try PublicKey(bytes)
            } else {
                sender = identityKey.publicKey
            }
            let key = try BRC29.receivingPrivateKey(
                recipient: identityKey, sender: sender, prefix: prefix, suffix: suffix
            )
            guard try BRC29.lockingScript(for: key.publicKey).bytes == input.sourceLockingScript else {
                throw WalletActionLifecycleError.invalidFunding
            }
            return (index, key)
        }
    }

    private static func orderActionInputs(_ funded: StorageCreateActionResult) throws -> StorageCreateActionResult {
        var inputs = funded.inputs
        if inputs.contains(where: { $0.vin != nil }) {
            guard inputs.allSatisfy({ $0.vin != nil }),
                  Set(inputs.compactMap(\.vin)) == Set((0..<inputs.count).map(UInt32.init)) else {
                throw WalletActionLifecycleError.invalidFunding
            }
            inputs.sort { $0.vin! < $1.vin! }
        }
        return StorageCreateActionResult(
            reference: funded.reference, version: funded.version, lockTime: funded.lockTime,
            outputs: funded.outputs, inputs: inputs, inputBEEF: funded.inputBEEF,
            derivationPrefix: funded.derivationPrefix
        )
    }

    private static func noSendChange(
        _ entry: PendingWalletActions.Entry, transactionID: TransactionID?
    ) throws -> [Outpoint]? {
        guard entry.request.options?.noSend == true, let transactionID else { return nil }
        return entry.funded.outputs.filter(\.isChange).map {
            Outpoint(transactionID: transactionID, outputIndex: $0.vout)
        }
    }
}
