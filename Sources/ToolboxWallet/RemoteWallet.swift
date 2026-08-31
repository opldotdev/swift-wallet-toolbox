import Foundation
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxActions
import ToolboxPermissions
import ToolboxPaymail
import ToolboxBRC29
import ToolboxStorage
import ToolboxStorageClient

/// A wallet backed by remote storage.
///
/// This is where the pieces compose. A payment is four calls in a fixed order — fund, verify,
/// sign, send — and getting that order right is the whole reason the pieces are separate. The
/// wallet holds the identity key and the fee policy; storage holds the coins; the action layer
/// holds the safety checks. None of them trusts the others by default.
///
/// It is a `struct` around an actor `StorageClient`: the mutable state lives in the client, and
/// concurrent payments serialize there.
public struct RemoteWallet: Sendable {
    private let storage: StorageClient
    private let identityKey: PrivateKey
    private let auth: AuthID
    /// The most this wallet will pay to miners on any single payment, in satoshis. A payment whose
    /// funding would exceed it is refused before signing rather than silently overpaid.
    public let maximumFee: Int64

    public init(
        storage: StorageClient,
        identityKey: PrivateKey,
        auth: AuthID,
        maximumFee: Int64 = 100_000
    ) {
        self.storage = storage
        self.identityKey = identityKey
        self.auth = auth
        self.maximumFee = maximumFee
    }

    /// The offline BRC-100 kernel shares this wallet's identity key for every crypto operation.
    public var protoWallet: ProtoWallet { ProtoWallet(rootKey: identityKey) }

    /// Restores a wallet from its recovery phrase, using the BSV Association reference scheme
    /// (`MnemonicRestore`, matching `bsv-desktop`).
    ///
    /// The phrase is the whole backup: it produces the identity key, which both authenticates to
    /// storage and signs. A phrase written down in `bsv-desktop` restores the same wallet here.
    ///
    /// Nothing reaches the network; the handshake waits for the first call.
    public static func restore(
        fromPhrase phrase: String,
        endpoint: URL = RemoteStorage.defaultEndpoint,
        maximumFee: Int64 = 100_000
    ) throws -> RemoteWallet {
        let identityKey = try MnemonicRestore.identityKey(fromPhrase: phrase)
        let identityHex = identityKey.publicKey.compressedBytes
            .map { String(format: "%02x", $0) }.joined()
        let storage = try RemoteStorage.client(
            at: endpoint, wallet: ProtoWallet(rootKey: identityKey)
        )
        return RemoteWallet(
            storage: storage,
            identityKey: identityKey,
            auth: AuthID(identityKey: identityHex),
            maximumFee: maximumFee
        )
    }

    /// Reachable once storage has described itself.
    @discardableResult
    public func connect() async throws -> StorageSettings {
        try await storage.makeAvailable(auth)
    }

    /// The spendable balance of a basket, in satoshis.
    public func balance(basket: String = "default") async throws -> Int64 {
        let outputs = try await storage.listOutputs(
            auth, try WalletListOutputsRequest(basket: basket)
        )
        return outputs.outputs.reduce(0) { $0 + Int64($1.satoshis) }
    }

    /// The wallet's transaction history, most work left to the caller's request.
    public func history(
        _ request: WalletListActionsRequest? = nil
    ) async throws -> WalletListActionsResult {
        try await storage.listActions(auth, request ?? (try WalletListActionsRequest(labels: [])))
    }

    // MARK: - Receiving

    /// A receiving address, derived at the given index under the 1Sat deposit convention.
    ///
    /// The protocol owner is `DepositAddresses` in `swift-1sat-sdk` (`@1sat/actions`
    /// `deriveDepositAddresses`). This method uses `OneSatDeposit`, the toolbox's byte-identical
    /// copy of that derivation for the default prefix `"1sat"`. Any wallet that binds this
    /// identity key derives the same default addresses. Index 0 is the primary address a wallet
    /// usually displays.
    public func receiveAddress(
        index: Int = 0, network: BitcoinNetwork = .mainnet
    ) throws -> String {
        try OneSatDeposit.address(identity: identityKey, index: index, network: network)
            .description
    }

    /// A run of receiving addresses, for scanning the chain or handing out fresh ones.
    ///
    /// Each index is `receiveAddress(index:network:)` — the same `DepositAddresses` derivation
    /// via the local `OneSatDeposit` copy.
    public func receiveAddresses(
        startIndex: Int, count: Int, network: BitcoinNetwork = .mainnet
    ) throws -> [String] {
        try (startIndex..<startIndex + count).map {
            try receiveAddress(index: $0, network: network)
        }
    }

    /// Claims an incoming transaction's outputs into this wallet, verifying ownership first.
    ///
    /// This is the receive side of BRC-29. For every output tagged `wallet payment`, the wallet
    /// re-derives the key it would hold for that output — from its own identity key, the sender's
    /// identity key, and the payment's prefix and suffix — and refuses unless the output's locking
    /// script is exactly the P2PKH that key unlocks. A `basket insertion` output carries no such
    /// claim and is passed through for storage to track.
    ///
    /// Every output is checked before storage is called, so a later bad output cannot follow an
    /// earlier one that already changed state. Storage does the actual tracking, proof validation
    /// and any rebroadcast; the wallet's job is only to prove each claimed output is really its own.
    @discardableResult
    public func internalizeAction(
        _ request: WalletInternalizeActionRequest
    ) async throws -> WalletInternalizeActionResult {
        let limits = WalletTransactionLimits.standard
        guard let subject = try request.transaction.beef.transaction(
            for: request.transaction.subjectTransactionID, limits: limits
        ) else {
            throw WalletError.internalizeSubjectMissing
        }

        for output in request.outputs {
            let index = Int(output.outputIndex)
            guard index < subject.outputs.count else {
                throw WalletError.internalizeOutputOutOfRange(outputIndex: output.outputIndex)
            }

            switch output.remittance {
            case .basketInsertion:
                // No BRC-29 claim to check; storage tracks it as instructed.
                continue
            case .walletPayment(let payment):
                // The prefix and suffix are the canonical base64 strings the sender derived with, so
                // they are rebuilt from the remittance bytes, never used as raw bytes.
                let prefix = Base64Encoding.encode(payment.derivationPrefix.bytes)
                let suffix = Base64Encoding.encode(payment.derivationSuffix.bytes)
                let receivingKey = try BRC29.receivingPrivateKey(
                    recipient: identityKey,
                    sender: payment.senderIdentityKey,
                    prefix: prefix,
                    suffix: suffix
                )
                let expected = try BRC29.lockingScript(for: receivingKey.publicKey)
                guard subject.outputs[index].lockingScript == expected else {
                    throw WalletError.outputIsNotBRC29Payment(outputIndex: output.outputIndex)
                }
            }
        }

        return try await storage.internalizeAction(auth, request)
    }

    /// Pays the given outputs and broadcasts.
    ///
    /// The order is the point. Storage funds the action and returns it; the signer re-checks the
    /// outputs and the fee before any key is used, re-derives change from this wallet's own key,
    /// and signs; the signed transaction goes back as Atomic BEEF for storage to record and send.
    /// A failure at any step leaves the reserved inputs to be released by `abort`, never a
    /// half-sent payment.
    @discardableResult
    public func pay(
        _ outputs: [WalletCreateActionOutput],
        description: String,
        labels: [String] = []
    ) async throws -> SentPayment {
        try await sign(outputs, description: description, labels: labels).sent
    }

    /// Pays a recipient — a native address or a paymail — for an amount.
    ///
    /// Resolution is the whole point of this method: whatever the user typed becomes output
    /// scripts, and from there the payment is the ordinary one. A native address is one P2PKH
    /// output. A paymail is resolved through its host, which returns the outputs to pay and a
    /// reference; after the transaction is signed and broadcast, the signed BEEF is delivered back
    /// to that host so the recipient recognises the payment.
    ///
    /// A paymail whose delivery fails after the money has moved throws `paymailDeliveryFailed`
    /// carrying the txid — the payment is on chain, but the recipient's host was not told, and the
    /// caller must know both facts.
    @discardableResult
    public func pay(
        to recipient: String,
        satoshis: UInt64,
        description: String,
        labels: [String] = [],
        paymail resolver: Paymail = Paymail()
    ) async throws -> SentPayment {
        if Paymail.isPaymail(recipient) {
            let destination = try await resolver.paymentDestination(
                paymail: recipient, satoshis: satoshis
            )
            let outputs = try destination.outputs.map { output in
                try WalletCreateActionOutput(
                    lockingScript: output.lockingScript,
                    satoshis: output.satoshis,
                    outputDescription: description
                )
            }
            let result = try await sign(outputs, description: description, labels: labels)
            do {
                try await resolver.deliver(
                    beef: try result.signed.atomicBEEF(),
                    to: recipient,
                    reference: destination.reference
                )
            } catch {
                throw WalletError.paymailDeliveryFailed(
                    txid: result.sent.transactionID.displayHex
                )
            }
            return result.sent
        }

        // A native address: one P2PKH output for the whole amount.
        let script = try Script.payToPublicKeyHash(
            try Address(recipient).publicKeyHash, maximumByteCount: 1 << 20
        )
        let output = try WalletCreateActionOutput(
            lockingScript: script.bytes, satoshis: satoshis, outputDescription: description
        )
        return try await pay([output], description: description, labels: labels)
    }

    /// Pays a counterparty's identity key with a BRC-29 payment, returning everything the recipient
    /// needs to internalize and spend the output.
    ///
    /// The wallet is the sender. It derives the recipient's paying key with BRC-42 against this
    /// wallet's identity key under the BRC-29 protocol, using the caller-supplied `prefix` and
    /// `suffix`, and locks a plain P2PKH to it (`BRC29`). Only the recipient, holding the same
    /// `prefix`, `suffix`, and this wallet's identity key, can derive the private key that spends it
    /// — so the caller MUST keep `prefix` and `suffix`, or the money becomes unspendable.
    ///
    /// The output index is confirmed against the signed transaction **before** the broadcast. A
    /// derivation that does not appear exactly once throws and nothing is sent, because telling the
    /// recipient a wrong index points it at an output it cannot spend.
    public func payToCounterparty(
        recipient recipientIdentityKey: PublicKey,
        satoshis: UInt64,
        derivationPrefix prefix: String,
        derivationSuffix suffix: String,
        description: String,
        labels: [String] = []
    ) async throws -> CounterpartyPayment {
        let payingPublicKey = try BRC29.payingPublicKey(
            recipient: recipientIdentityKey, sender: identityKey, prefix: prefix, suffix: suffix
        )
        let script = try BRC29.lockingScript(for: payingPublicKey)
        let output = try WalletCreateActionOutput(
            lockingScript: script.bytes, satoshis: satoshis, outputDescription: description
        )

        let request = try WalletCreateActionRequest(
            description: description, outputs: [output], labels: labels
        )
        let funded = try await storage.createAction(auth, request)
        let transaction = try ActionSigner.sign(
            funded,
            requested: [output],
            identityKey: identityKey,
            senderPublicKey: identityKey.publicKey,
            maximumFee: maximumFee
        )
        let signed = try SignedAction(funded: funded, transaction: transaction)

        // The paid output is located by its locking script, not assumed at an index, because storage
        // may add change and may reorder. Zero or several matches means the derivation is wrong or
        // collided; the funded inputs are released and nothing is broadcast.
        let scriptBytes = script.bytes
        let matches = signed.transaction.outputs.enumerated().filter {
            $0.element.lockingScript.bytes == scriptBytes
        }
        guard matches.count == 1, let index = matches.first?.offset else {
            _ = try? await abort(reference: funded.reference)
            throw BRC29PaymentError.outputNotUniquelyIdentified(matches: matches.count)
        }

        let processed = try await storage.processAction(auth, try signed.processRequest())
        return CounterpartyPayment(
            transactionID: signed.transactionID,
            outputIndex: index,
            atomicBEEF: try signed.atomicBEEF(),
            reference: funded.reference,
            results: processed.sendWithResults
        )
    }

    /// Funds, signs and broadcasts the outputs, returning both the signed action (for a paymail
    /// BEEF delivery) and the receipt.
    private func sign(
        _ outputs: [WalletCreateActionOutput],
        description: String,
        labels: [String]
    ) async throws -> (signed: SignedAction, sent: SentPayment) {
        let request = try WalletCreateActionRequest(
            description: description, outputs: outputs, labels: labels
        )
        let funded = try await storage.createAction(auth, request)

        let transaction = try ActionSigner.sign(
            funded,
            requested: outputs,
            identityKey: identityKey,
            senderPublicKey: identityKey.publicKey,
            maximumFee: maximumFee
        )

        let signed = try SignedAction(funded: funded, transaction: transaction)
        let result = try await storage.processAction(auth, try signed.processRequest())

        return (
            signed,
            SentPayment(
                transactionID: signed.transactionID,
                reference: funded.reference,
                results: result.sendWithResults
            )
        )
    }

    /// Abandons a funded action, releasing its reserved inputs.
    ///
    /// `reference` is the opaque base64 string storage returned on the funded action. It is decoded
    /// back to bytes here so the request re-encodes to exactly that string.
    @discardableResult
    public func abort(reference: String) async throws -> Bool {
        guard let bytes = Data(base64Encoded: reference) else {
            throw WalletError.invalidReference
        }
        let request = WalletAbortActionRequest(reference: try WalletBase64Data(Array(bytes)))
        return try await storage.abortAction(auth, request).aborted
    }

    package func _permissionAccountID() throws -> PermissionAccountID {
        guard Self.hexBytes(auth.identityKey) == identityKey.publicKey.compressedBytes else {
            throw PermissionTokenMutationError.accountMismatch
        }
        let identityComponent = Base64Encoding.encode(identityKey.publicKey.compressedBytes)
        let userComponent = auth.userID.map { "some:\($0)" } ?? "none"
        return try PermissionAccountID("auth-v1|\(identityComponent)|\(userComponent)")
    }

    package func _listPermissionTokenOutputs(
        _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult {
        _ = try _permissionAccountID()
        return try await storage.listOutputs(auth, request)
    }

    package func _commitPermissionTokenMutation(
        _ mutation: PermissionTokenMutationRequest,
        using tokenWallet: any PermissionTokenWallet
    ) async throws -> PermissionTokenMutationResult {
        try Task.checkCancellation()
        let accountID = try _permissionAccountID()
        guard mutation.accountID == accountID,
              tokenWallet.permissionAccountID == accountID else {
            throw PermissionTokenMutationError.accountMismatch
        }

        // Finish all codec work and source validation before storage reserves any inputs.
        var requestedOutputs = [WalletCreateActionOutput]()
        requestedOutputs.reserveCapacity(mutation.created.count)
        for token in mutation.created {
            try Task.checkCancellation()
            let script = try await PermissionTokenCodec.encode(token, using: tokenWallet)
            requestedOutputs.append(try WalletCreateActionOutput(
                lockingScript: script.bytes,
                satoshis: 1,
                outputDescription: "\(token.basket.rawValue) permission token",
                basket: token.basket.rawValue,
                tags: token.indexTags
            ))
        }

        for match in mutation.consumed {
            try Task.checkCancellation()
            try Self.validatePermissionTokenSource(match)
        }
        try Task.checkCancellation()
        let inputBEEF = try Self.mergePermissionTokenSources(mutation.consumed)
        try Task.checkCancellation()
        let requestedInputs = try mutation.consumed.map { match in
            try WalletCreateActionInput(
                outpoint: match.outpoint,
                inputDescription: "Consume \(match.token.basket.rawValue) permission token",
                unlockingScriptLength: UInt32(TransactionInput.pushDropUnlockingScriptByteCount)
            )
        }
        let options = try WalletCreateActionOptions(
            signAndProcess: false,
            acceptDelayedBroadcast: true,
            randomizeOutputs: false
        )
        let createRequest = try WalletCreateActionRequest(
            description: "Update wallet permission token",
            inputBEEF: inputBEEF,
            inputs: requestedInputs,
            outputs: requestedOutputs,
            options: options
        )
        try Task.checkCancellation()
        let funded = try await storage.createAction(auth, createRequest)

        do {
            guard !funded.reference.isEmpty,
                  (try? WalletBase64Data(base64: funded.reference)) != nil else {
                throw PermissionTokenMutationError.invalidStorageReference
            }
            try Task.checkCancellation()
            try ActionAssembler.requireFeeWithin(maximumFee, for: funded)
            let unsigned = try ActionAssembler.assemble(
                funded, requested: requestedOutputs, changeKey: identityKey
            )
            let fundedSourceGraph = try Self.validatedFundedSourceGraph(
                funded, subject: unsigned, expectedSourceGraph: inputBEEF
            )
            try Task.checkCancellation()
            let declarations = try mutation.consumed.map { match in
                guard let satoshis = Int64(exactly: match.satoshis) else {
                    throw PermissionTokenMutationError.invalidConsumedValue(
                        outpoint: match.outpoint, satoshis: match.satoshis
                    )
                }
                return ActionSigner.BRC116PermissionTokenSpend(
                    outpoint: match.outpoint,
                    satoshis: satoshis,
                    lockingScript: match.lockingScript,
                    signer: tokenWallet
                )
            }
            let transaction = try await ActionSigner.signBRC116PermissionTokenAction(
                funded,
                requested: requestedOutputs,
                identityKey: identityKey,
                senderPublicKey: identityKey.publicKey,
                permissionTokenSpends: declarations,
                maximumFee: maximumFee
            )
            try Task.checkCancellation()
            let transactionID = try transaction.transactionID(
                limits: StorageLimits.transaction
            )
            let atomic = try Self.atomicBEEF(
                subject: transaction,
                transactionID: transactionID,
                sourceGraph: fundedSourceGraph
            )
            let processRequest = StorageProcessActionRequest(
                reference: funded.reference,
                isNewTx: true,
                isSendWith: false,
                rawTX: try atomic.serialized(limits: StorageLimits.beef),
                sendWith: []
            )
            try Task.checkCancellation()
            _ = try await storage.processAction(auth, processRequest)
            // No cancellation or epoch check belongs after process success: the mutation committed.
            return PermissionTokenMutationResult(
                transactionID: transactionID,
                reference: funded.reference
            )
        } catch {
            let primaryError = error
            await Task.detached { [storage, auth] in
                guard let reference = try? WalletBase64Data(base64: funded.reference) else {
                    return
                }
                _ = try? await storage.abortAction(
                    auth, WalletAbortActionRequest(reference: reference)
                )
            }.value
            throw primaryError
        }
    }

    private static func mergePermissionTokenSources(
        _ matches: [PermissionTokenMatch]
    ) throws -> BEEF? {
        guard var merged = matches.first?.sourceBEEF else { return nil }
        for match in matches.dropFirst() {
            merged = try merged.merging(match.sourceBEEF, limits: StorageLimits.beef)
        }
        _ = try merged.merkleRootsByBlockHeight()
        return merged
    }

    /// Checks storage's complete input graph against every funded source before any signer runs.
    private static func validatedFundedSourceGraph(
        _ funded: StorageCreateActionResult,
        subject: Transaction,
        expectedSourceGraph: BEEF?
    ) throws -> BEEF {
        let graph: BEEF
        if let bytes = funded.inputBEEF {
            do {
                graph = try BEEF(bytes: bytes, limits: StorageLimits.beef)
            } catch {
                throw PermissionTokenMutationError.untrustworthyFundedBEEF
            }
        } else {
            guard funded.inputs.isEmpty else {
                throw PermissionTokenMutationError.untrustworthyFundedBEEF
            }
            graph = try BEEF(
                merklePaths: [], transactions: [], limits: StorageLimits.beef
            )
        }

        for input in funded.inputs {
            guard let transactionID = try? TransactionID(displayHex: input.sourceTXID),
                  let transaction = try graph.transaction(
                    for: transactionID,
                    limits: StorageLimits.transaction
                  ),
                  let index = Int(exactly: input.sourceVout),
                  transaction.outputs.indices.contains(index),
                  input.sourceSatoshis >= 0 else {
                throw PermissionTokenMutationError.untrustworthyFundedBEEF
            }
            let source = transaction.outputs[index]
            guard source.satoshis == UInt64(input.sourceSatoshis),
                  source.lockingScript.bytes == input.sourceLockingScript else {
                throw PermissionTokenMutationError.untrustworthyFundedBEEF
            }
        }

        // The unsigned subject connects every legitimate input root. Atomic validation rejects
        // omitted ancestors and any unrelated transaction/path before a token signature is asked.
        let candidate = try BEEF(
            version: graph.version,
            merklePaths: graph.merklePaths,
            transactions: graph.transactions + [.raw(subject)],
            limits: StorageLimits.beef
        )
        let subjectID = try subject.transactionID(limits: StorageLimits.transaction)
        do {
            // Storage cannot supply two different claimed roots for one block height. Atomic BEEF
            // checks exact ancestry, while this cross-path consistency check is deliberately
            // separate in the SDK.
            _ = try candidate.merkleRootsByBlockHeight()
            if let expectedSourceGraph {
                // Storage may add funding ancestry, but it may not strip or replace proof metadata
                // from the exact source graph supplied with the request. Normalize both sides via
                // the graph merger so BUMP leaf unions and raw/raw-with-path spelling compare by
                // their semantic graph rather than their original wire order.
                let empty = try BEEF(
                    version: graph.version,
                    merklePaths: [],
                    transactions: [],
                    limits: StorageLimits.beef
                )
                let normalizedReturned = try graph.merging(
                    empty, limits: StorageLimits.beef
                )
                let returnedWithExpected = try graph.merging(
                    expectedSourceGraph, limits: StorageLimits.beef
                )
                guard returnedWithExpected == normalizedReturned else {
                    throw PermissionTokenMutationError.untrustworthyFundedBEEF
                }
            }
            _ = try AtomicBEEF(
                subjectTransactionID: subjectID,
                beef: candidate,
                limits: StorageLimits.beef
            )
        } catch {
            throw PermissionTokenMutationError.untrustworthyFundedBEEF
        }
        return graph
    }

    private static func atomicBEEF(
        subject: Transaction,
        transactionID: TransactionID,
        sourceGraph: BEEF
    ) throws -> AtomicBEEF {
        let beef = try BEEF(
            version: sourceGraph.version,
            merklePaths: sourceGraph.merklePaths,
            transactions: sourceGraph.transactions + [.raw(subject)],
            limits: StorageLimits.beef
        )
        return try AtomicBEEF(
            subjectTransactionID: transactionID,
            beef: beef,
            limits: StorageLimits.beef
        )
    }

    private static func validatePermissionTokenSource(_ match: PermissionTokenMatch) throws {
        guard match.satoshis == 1,
              let transaction = try match.sourceBEEF.transaction(
                for: match.outpoint.transactionID,
                limits: StorageLimits.beef.transactionLimits
              ),
              let index = Int(exactly: match.outpoint.outputIndex),
              transaction.outputs.indices.contains(index) else {
            throw PermissionTokenMutationError.invalidConsumedValue(
                outpoint: match.outpoint, satoshis: match.satoshis
            )
        }
        let source = transaction.outputs[index]
        guard source.satoshis == 1, source.lockingScript.bytes == match.lockingScript else {
            throw PermissionTokenMutationError.invalidConsumedValue(
                outpoint: match.outpoint, satoshis: match.satoshis
            )
        }
    }

    private static func hexBytes(_ text: String) -> [UInt8]? {
        guard text.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}

/// The receipt of a BRC-29 payment to a counterparty.
///
/// It carries the three things the recipient needs to internalize the output, beyond the derivation
/// prefix and suffix the caller already holds: the transaction id, the index of the paid output,
/// and the Atomic BEEF (BRC-95). With these plus the sender's identity key the recipient derives the
/// spending key and validates the transaction without trusting anyone.
public struct CounterpartyPayment: Sendable {
    public let transactionID: TransactionID
    public let outputIndex: Int
    public let atomicBEEF: [UInt8]
    public let reference: String
    public let results: [SendWithResult]

    public init(
        transactionID: TransactionID,
        outputIndex: Int,
        atomicBEEF: [UInt8],
        reference: String,
        results: [SendWithResult]
    ) {
        self.transactionID = transactionID
        self.outputIndex = outputIndex
        self.atomicBEEF = atomicBEEF
        self.reference = reference
        self.results = results
    }
}

/// Failures of a BRC-29 counterparty payment.
public enum BRC29PaymentError: Error, Equatable, Sendable {
    /// The derived output did not appear exactly once in the signed transaction. The payment was
    /// not broadcast. `matches` is how many outputs carried the derived locking script.
    case outputNotUniquelyIdentified(matches: Int)
}

/// The outcome of a payment that reached storage.
public struct SentPayment: Sendable {
    public let transactionID: TransactionID
    public let reference: String
    public let results: [SendWithResult]

    public init(transactionID: TransactionID, reference: String, results: [SendWithResult]) {
        self.transactionID = transactionID
        self.reference = reference
        self.results = results
    }
}
