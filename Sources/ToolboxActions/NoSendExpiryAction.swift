import Foundation
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage

/// Creates a BRC-177 protected `noSend` action, the way the reference client's
/// `createNoSendExpiryAction` does.
///
/// 1. Storage prepares a funding action for a dedicated anchor output. It is signed and
///    broadcast here.
/// 2. Storage activates the protected action, funded by that anchor alone.
/// 3. A reclaim of the anchor is built, signed, and handed to storage, which arms the action. From
///    then on storage can revoke it at the deadline by broadcasting the reclaim.
/// 4. The protected action is signed and processed as `noSend`. Storage refuses to release it
///    unless it was armed.
///
/// Any failure after storage reserved something aborts that reservation.
public enum NoSendExpiryAction {

    public struct Result: Sendable {
        public let signed: SignedAction
        public let funded: StorageCreateActionResult
        public let anchorTxid: String
        public let anchorVout: UInt32
        public let deadline: UInt64?
    }

    /// - Parameters:
    ///   - request: the protected action. Must carry exactly one `p nosend expiry …` label and
    ///     `noSend: true`.
    ///   - signCallerInputs: unlocking scripts for the caller's own inputs, by input index in the
    ///     funded transaction. Storage-managed inputs (the anchor) are signed here.
    public static func run(
        storage: any NoSendExpiryStorage,
        auth: AuthID,
        identity: PrivateKey,
        request: WalletCreateActionRequest,
        maximumFee: Int64,
        signCallerInputs: @Sendable (Transaction, StorageCreateActionResult) throws -> [Int: Script]
    ) async throws -> Result {
        guard let expiry = try NoSendExpiry.parse(labels: request.labels ?? []) else {
            throw NoSendExpiryError.invalidRequest("no BRC-177 expiry label")
        }
        guard try await storage.supportsNoSendExpiry() else {
            throw NoSendExpiryError.unsupported
        }

        let prepared = try await storage.prepareNoSendExpiry(auth, request)

        // The anchor funding: storage's own action, paying the anchor to this wallet as change.
        let fundingTransaction: Transaction
        let fundingTxid: String
        do {
            fundingTransaction = try await fund(
                prepared, storage: storage, auth: auth, identity: identity, maximumFee: maximumFee
            )
            fundingTxid = try fundingTransaction
                .transactionID(limits: WalletTransactionLimits.standard).displayHex
        } catch {
            await abort(prepared.funding.reference, storage: storage, auth: auth)
            throw error
        }

        let activated = try await storage.activateNoSendExpiry(
            auth, target: request, fundingReference: prepared.funding.reference,
            fundingTxid: fundingTxid, anchorVout: prepared.anchorVout
        )
        let target = activated.action

        do {
            let anchorIndex = try anchorInput(
                of: target, txid: activated.anchorTxid, vout: activated.anchorVout,
                fundingTxid: fundingTxid
            )
            guard activated.mode == expiry.mode else {
                throw NoSendExpiryError.unexpectedAction(
                    "storage armed \(activated.mode), the label asked for \(expiry.mode)"
                )
            }

            if activated.mode != "never" {
                let reclaim = try makeReclaim(
                    anchor: target.inputs[anchorIndex],
                    fundingTransaction: fundingTransaction,
                    anchorVout: activated.anchorVout,
                    reclaimSatoshis: prepared.reclaimSatoshis,
                    identity: identity
                )
                try await storage.armNoSendExpiry(auth, NoSendExpiryArm(
                    reference: target.reference,
                    reclaimTxid: reclaim.txid,
                    reclaimRawTx: reclaim.rawTx,
                    reclaimDerivationPrefix: reclaim.prefix,
                    reclaimDerivationSuffix: reclaim.suffix,
                    reclaimSatoshis: prepared.reclaimSatoshis
                ))
            }

            try ActionAssembler.requireFeeWithin(maximumFee, for: target)
            var transaction = try ActionAssembler.assemble(
                target, requested: request.outputs ?? [], changeKey: identity
            )
            applySequences(request.inputs ?? [], onto: &transaction, funded: target)
            let spends = try signCallerInputs(transaction, target)
            for (index, script) in spends {
                guard transaction.inputs.indices.contains(index), index != anchorIndex else {
                    throw NoSendExpiryError.invalidRequest("caller signed input \(index)")
                }
                transaction.inputs[index].unlockingScript = script
            }
            try signManaged(
                &transaction, input: target.inputs[anchorIndex], at: anchorIndex,
                identity: identity
            )

            let signed = try SignedAction(funded: target, transaction: transaction)
            let process = StorageProcessActionRequest(
                reference: target.reference,
                isNewTx: true,
                isSendWith: false,
                rawTX: try transaction.serialized(limits: WalletTransactionLimits.standard),
                sendWith: [],
                isNoSend: true,
                isDelayed: false
            )
            _ = try await storage.processAction(auth, process)
            return Result(
                signed: signed, funded: target, anchorTxid: activated.anchorTxid,
                anchorVout: activated.anchorVout, deadline: activated.deadline
            )
        } catch {
            await abort(target.reference, storage: storage, auth: auth)
            throw error
        }
    }

    // MARK: - Funding

    static func fund(
        _ prepared: NoSendExpiryPrepared,
        storage: any NoSendExpiryStorage,
        auth: AuthID,
        identity: PrivateKey,
        maximumFee: Int64
    ) async throws -> Transaction {
        let funding = prepared.funding
        guard let anchor = funding.outputs.first(where: { $0.vout == prepared.anchorVout }),
              anchor.isChange, anchor.satoshis == prepared.anchorSatoshis else {
            throw NoSendExpiryError.unexpectedAction(
                "the funding action does not pay the anchor to this wallet"
            )
        }
        // Storage built this action, so nothing was requested; every output must be change.
        try ActionAssembler.requireFeeWithin(maximumFee, for: funding)
        var transaction = try ActionAssembler.assemble(
            funding, requested: [], changeKey: identity
        )
        for (index, input) in funding.inputs.enumerated() {
            try signManaged(&transaction, input: input, at: index, identity: identity)
        }
        let processed = try await storage.processAction(auth, StorageProcessActionRequest(
            reference: funding.reference,
            isNewTx: true,
            isSendWith: false,
            rawTX: try transaction.serialized(limits: WalletTransactionLimits.standard),
            sendWith: [],
            isNoSend: false,
            isDelayed: false
        ))
        if let failed = processed.sendWithResults.first(where: { $0.status != .unproven }) {
            throw NoSendExpiryError.fundingFailed("broadcast \(failed.status.rawValue)")
        }
        return transaction
    }

    // MARK: - Reclaim

    struct Reclaim {
        let txid: String
        let rawTx: [UInt8]
        let prefix: String
        let suffix: String
    }

    /// One input, the anchor at sequence 0xffffffff; one output, the reclaim amount back to this
    /// wallet under a fresh BRC-29 derivation; lock time 0; SIGHASH_ALL|FORKID. Storage refuses
    /// any other shape.
    static func makeReclaim(
        anchor: StorageActionInput,
        fundingTransaction: Transaction,
        anchorVout: UInt32,
        reclaimSatoshis: UInt64,
        identity: PrivateKey,
        prefix: String = randomDerivation(),
        suffix: String = randomDerivation()
    ) throws -> Reclaim {
        let limits = WalletTransactionLimits.standard
        guard fundingTransaction.outputs.indices.contains(Int(anchorVout)) else {
            throw NoSendExpiryError.unexpectedAction("the anchor is not in the funding transaction")
        }
        let source = fundingTransaction.outputs[Int(anchorVout)]
        let fundingID = try fundingTransaction.transactionID(limits: limits)
        let ownKey = try BRC29.receivingPrivateKey(
            recipient: identity, sender: identity.publicKey, prefix: prefix, suffix: suffix
        )
        var reclaim = Transaction(
            version: 1,
            inputs: [TransactionInput(
                previousOutput: Outpoint(transactionID: fundingID, outputIndex: anchorVout),
                unlockingScript: try Script(bytes: [], maximumByteCount: 1 << 20),
                sequence: 0xffff_ffff,
                sourceOutput: source
            )],
            outputs: [TransactionOutput(
                satoshis: reclaimSatoshis,
                lockingScript: try BRC29.lockingScript(for: ownKey.publicKey)
            )],
            lockTime: 0
        )
        try signManaged(&reclaim, input: anchor, at: 0, identity: identity)
        let rawTx = try reclaim.serialized(limits: limits)
        guard rawTx.count <= 1000 else {
            throw NoSendExpiryError.unexpectedAction("the reclaim exceeds 1000 bytes")
        }
        return Reclaim(
            txid: try reclaim.transactionID(limits: limits).displayHex,
            rawTx: rawTx, prefix: prefix, suffix: suffix
        )
    }

    /// Sixteen random bytes in base64, the derivation shape storage requires for a reclaim.
    public static func randomDerivation() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        for index in bytes.indices { bytes[index] = UInt8.random(in: 0...255) }
        return Data(bytes).base64EncodedString()
    }

    // MARK: - Helpers

    /// The index of the anchor in the activated action, which must be its only managed input.
    static func anchorInput(
        of target: StorageCreateActionResult, txid: String, vout: UInt32, fundingTxid: String
    ) throws -> Int {
        guard txid.lowercased() == fundingTxid.lowercased() else {
            throw NoSendExpiryError.unexpectedAction("the anchor is not the funded output")
        }
        let managed = target.inputs.enumerated().filter { $0.element.derivationPrefix != nil }
        guard managed.count == 1, let only = managed.first,
              only.element.sourceTXID.lowercased() == txid.lowercased(),
              only.element.sourceVout == vout else {
            throw NoSendExpiryError.unexpectedAction(
                "the protected action does not have exactly one managed anchor input"
            )
        }
        guard !target.outputs.contains(where: \.isChange) else {
            throw NoSendExpiryError.unexpectedAction("the protected action carries change")
        }
        return only.offset
    }

    static func signManaged(
        _ transaction: inout Transaction, input: StorageActionInput, at index: Int,
        identity: PrivateKey
    ) throws {
        guard let prefix = input.derivationPrefix, let suffix = input.derivationSuffix else {
            throw ActionError.unusableInput("input \(index) is missing its derivation")
        }
        let sender: PublicKey
        if let senderHex = input.senderIdentityKey {
            guard let bytes = try? Hex.decode(senderHex, maximumDecodedByteCount: 33),
                  let key = try? PublicKey(bytes) else {
                throw ActionError.unusableInput("input \(index) names a sender key that cannot be read")
            }
            sender = key
        } else {
            sender = identity.publicKey
        }
        let key = try BRC29.receivingPrivateKey(
            recipient: identity, sender: sender, prefix: prefix, suffix: suffix
        )
        try transaction.signPayToPublicKeyHashInput(
            at: index, with: key, limits: WalletTransactionLimits.standard
        )
    }

    static func applySequences(
        _ requested: [WalletCreateActionInput],
        onto transaction: inout Transaction,
        funded: StorageCreateActionResult
    ) {
        for input in requested {
            guard let sequence = input.sequenceNumber,
                  let index = funded.inputs.firstIndex(where: {
                      $0.sourceTXID.lowercased() == input.outpoint.transactionID.displayHex
                          && $0.sourceVout == input.outpoint.outputIndex
                  }),
                  transaction.inputs.indices.contains(index) else { continue }
            transaction.inputs[index].sequence = sequence
        }
    }

    static func abort(_ reference: String, storage: any NoSendExpiryStorage, auth: AuthID) async {
        guard let bytes = Data(base64Encoded: reference),
              let encoded = try? WalletBase64Data(Array(bytes)) else { return }
        _ = try? await storage.abortAction(auth, WalletAbortActionRequest(reference: encoded))
    }
}
