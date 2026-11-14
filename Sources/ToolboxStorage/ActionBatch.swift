import Foundation
import BSVTransaction
import BSVWallet
import ToolboxCore

/// Action batches: several actions planned on the client and committed to storage together.
///
/// This is the storage half of the TypeScript toolbox's `ActionBatchController`
/// (`@bsv/wallet-toolbox` 2.15.3, `sdk/ActionBatch.interfaces.d.ts`). Storage reserves the wallet
/// outputs a batch may spend when it begins; the client plans and signs each member action
/// against those reservations and against the outputs of the members before it; and one commit
/// hands storage every signed member, which it validates and persists atomically before
/// broadcasting.
///
/// The point is a chain that ordinary `createAction` cannot fund. Storage funds a new action only
/// from change whose transaction is completed, unproven or sending, so a `noSend` action's change
/// cannot pay for the action that broadcasts it. Inside a batch it can: the client plans the
/// second action from the first one's change before storage has seen either.

/// What `getCapabilities` advertises under `actionBatch`. Only version 1 is spoken.
public struct ActionBatchCapabilities: Equatable, Sendable {
    public let version: Int
    public let maxInlineBytes: Int
    public let maxBlobBytes: Int
    public let maxConcurrentUploads: Int
    /// How long a reservation lives without renewal, in milliseconds.
    public let leaseMs: Int
    /// How long a batch may live in total, renewals included, in milliseconds.
    public let hardLifetimeMs: Int
    /// The first action may be sent without its scripts and proof bytes.
    public let compactBegin: Bool
    /// 2 when storage accepts the compact manifest, which derives scripts from the transactions.
    public let manifestVersion: Int?
    public let commitByDigest: Bool
    public let resume: Bool
    public let maxReservedOutputs: Int?

    public init(
        version: Int, maxInlineBytes: Int, maxBlobBytes: Int, maxConcurrentUploads: Int,
        leaseMs: Int, hardLifetimeMs: Int, compactBegin: Bool = false,
        manifestVersion: Int? = nil, commitByDigest: Bool = false, resume: Bool = false,
        maxReservedOutputs: Int? = nil
    ) {
        self.version = version
        self.maxInlineBytes = maxInlineBytes
        self.maxBlobBytes = maxBlobBytes
        self.maxConcurrentUploads = maxConcurrentUploads
        self.leaseMs = leaseMs
        self.hardLifetimeMs = hardLifetimeMs
        self.compactBegin = compactBegin
        self.manifestVersion = manifestVersion
        self.commitByDigest = commitByDigest
        self.resume = resume
        self.maxReservedOutputs = maxReservedOutputs
    }
}

/// The basket storage funds change from and pays change into (`TableOutputBasket`).
public struct ActionBatchChangeBasket: Equatable, Sendable {
    public let basketId: Int
    public let name: String
    public let numberOfDesiredUTXOs: Int
    public let minimumDesiredUTXOValue: Int

    public init(basketId: Int, name: String, numberOfDesiredUTXOs: Int, minimumDesiredUTXOValue: Int) {
        self.basketId = basketId
        self.name = name
        self.numberOfDesiredUTXOs = numberOfDesiredUTXOs
        self.minimumDesiredUTXOValue = minimumDesiredUTXOValue
    }
}

/// Storage's fee model. Only `sat/kb` exists; `value` is satoshis per 1000 bytes.
public struct ActionBatchFeeModel: Equatable, Sendable {
    public let model: String
    public let value: Double

    public init(model: String = "sat/kb", value: Double) {
        self.model = model
        self.value = value
    }
}

/// A persisted wallet output storage reserved for the batch (`ActionBatchFundingOutput`).
///
/// `lockingScript` may be absent: storage keeps long scripts only inside the raw transaction,
/// and the planner then reads the script from the proof graph, as the reference does.
public struct ActionBatchFundingOutput: Equatable, Sendable {
    public let outputId: Int
    public let txid: String
    public let vout: UInt32
    public let satoshis: UInt64
    public let spendable: Bool
    public let change: Bool
    public let providedBy: String
    public let purpose: String
    public let type: String
    public let basketId: Int?
    public let derivationPrefix: String?
    public let derivationSuffix: String?
    public let senderIdentityKey: String?
    public let customInstructions: String?
    public let lockingScript: [UInt8]?
    public let sourceTransaction: [UInt8]?

    public init(
        outputId: Int, txid: String, vout: UInt32, satoshis: UInt64, spendable: Bool = true,
        change: Bool, providedBy: String, purpose: String, type: String, basketId: Int? = nil,
        derivationPrefix: String? = nil, derivationSuffix: String? = nil,
        senderIdentityKey: String? = nil, customInstructions: String? = nil,
        lockingScript: [UInt8]? = nil, sourceTransaction: [UInt8]? = nil
    ) {
        self.outputId = outputId
        self.txid = txid
        self.vout = vout
        self.satoshis = satoshis
        self.spendable = spendable
        self.change = change
        self.providedBy = providedBy
        self.purpose = purpose
        self.type = type
        self.basketId = basketId
        self.derivationPrefix = derivationPrefix
        self.derivationSuffix = derivationSuffix
        self.senderIdentityKey = senderIdentityKey
        self.customInstructions = customInstructions
        self.lockingScript = lockingScript
        self.sourceTransaction = sourceTransaction
    }

    public var outpoint: String { "\(txid).\(vout)" }
}

/// `beginActionBatch` arguments: a fresh batch id and the batch's first action.
public struct ActionBatchBeginRequest: Equatable, Sendable {
    public let batchId: String
    public let firstAction: WalletCreateActionRequest
    /// Send the first action without scripts or proof bytes, with its output script lengths
    /// beside it (`actionBatchBootstrap`). Storage needs only lengths to reserve funding.
    public let compact: Bool

    public init(batchId: String, firstAction: WalletCreateActionRequest, compact: Bool) {
        self.batchId = batchId
        self.firstAction = firstAction
        self.compact = compact
    }
}

/// What `beginActionBatch` returns (`BeginActionBatchResult`).
public struct ActionBatchBegin: Equatable, Sendable {
    public let batchId: String
    public let expiresAt: Date
    public let hardExpiresAt: Date
    public let changeBasket: ActionBatchChangeBasket
    public let feeModel: ActionBatchFeeModel
    public let commissionSatoshis: UInt64
    public let commissionPubKeyHex: String?
    public let availableChangeCount: Int
    /// Change storage reserved to fund the batch.
    public let reservedOutputs: [ActionBatchFundingOutput]
    /// Persisted outputs the first action names as inputs or `noSendChange`, also reserved.
    public let explicitOutputs: [ActionBatchFundingOutput]
    /// BEEF for every reserved output's transaction.
    public let inputBeef: [UInt8]?

    public init(
        batchId: String, expiresAt: Date, hardExpiresAt: Date,
        changeBasket: ActionBatchChangeBasket, feeModel: ActionBatchFeeModel,
        commissionSatoshis: UInt64, commissionPubKeyHex: String?, availableChangeCount: Int,
        reservedOutputs: [ActionBatchFundingOutput], explicitOutputs: [ActionBatchFundingOutput],
        inputBeef: [UInt8]?
    ) {
        self.batchId = batchId
        self.expiresAt = expiresAt
        self.hardExpiresAt = hardExpiresAt
        self.changeBasket = changeBasket
        self.feeModel = feeModel
        self.commissionSatoshis = commissionSatoshis
        self.commissionPubKeyHex = commissionPubKeyHex
        self.availableChangeCount = availableChangeCount
        self.reservedOutputs = reservedOutputs
        self.explicitOutputs = explicitOutputs
        self.inputBeef = inputBeef
    }
}

/// `extendActionBatch` arguments (`ExtendActionBatchArgs`).
public struct ActionBatchExtendRequest: Equatable, Sendable {
    public let batchId: String
    public let targetSatoshis: UInt64
    public let requestedOutputs: Int
    /// `txid.vout` outpoints of persisted outputs to add to the reservation.
    public let explicitOutpoints: [Outpoint]
    public let includeSourceTransactions: Bool

    public init(
        batchId: String, targetSatoshis: UInt64, requestedOutputs: Int,
        explicitOutpoints: [Outpoint], includeSourceTransactions: Bool
    ) {
        self.batchId = batchId
        self.targetSatoshis = targetSatoshis
        self.requestedOutputs = requestedOutputs
        self.explicitOutpoints = explicitOutpoints
        self.includeSourceTransactions = includeSourceTransactions
    }
}

/// What `extendActionBatch` returns (`ExtendActionBatchResult`).
public struct ActionBatchExtension: Equatable, Sendable {
    public let expiresAt: Date
    public let reservedOutputs: [ActionBatchFundingOutput]
    public let explicitOutputs: [ActionBatchFundingOutput]
    public let inputBeef: [UInt8]?

    public init(
        expiresAt: Date, reservedOutputs: [ActionBatchFundingOutput],
        explicitOutputs: [ActionBatchFundingOutput], inputBeef: [UInt8]?
    ) {
        self.expiresAt = expiresAt
        self.reservedOutputs = reservedOutputs
        self.explicitOutputs = explicitOutputs
        self.inputBeef = inputBeef
    }
}

/// A commit manifest, ready to send.
///
/// `body` is the whole manifest including `digest`, in the exact member order the digest was
/// computed over. It is sent as written, never re-encoded through an unordered type, because
/// storage recomputes the digest from the order it receives.
public struct ActionBatchManifest: Equatable, Sendable {
    public let batchId: String
    public let digest: String
    public let body: OrderedJSON

    public init(batchId: String, digest: String, body: OrderedJSON) {
        self.batchId = batchId
        self.digest = digest
        self.body = body
    }
}

/// What `commitActionBatch` returns (`CommitActionBatchResult`).
public struct ActionBatchCommitResult: Equatable, Sendable {
    public let batchId: String
    public let manifestDigest: String
    public let committedTxids: [String]
    /// True when storage had already committed this exact manifest, so this was a replay.
    public let alreadyCommitted: Bool
    public let sendWithResults: [SendWithResult]

    public init(
        batchId: String, manifestDigest: String, committedTxids: [String],
        alreadyCommitted: Bool, sendWithResults: [SendWithResult]
    ) {
        self.batchId = batchId
        self.manifestDigest = manifestDigest
        self.committedTxids = committedTxids
        self.alreadyCommitted = alreadyCommitted
        self.sendWithResults = sendWithResults
    }
}

/// The storage calls an action batch needs. `StorageClient` conforms.
///
/// `createAction` and `processAction` are the ordinary calls, for the cases the batch hands back
/// to the legacy path.
public protocol ActionBatchStorage: Sendable {
    /// The `actionBatch` capability, or `nil` when storage does not advertise one.
    func actionBatchCapabilities() async throws -> ActionBatchCapabilities?
    func beginActionBatch(_ auth: AuthID, _ request: ActionBatchBeginRequest) async throws -> ActionBatchBegin
    func extendActionBatch(
        _ auth: AuthID, _ request: ActionBatchExtendRequest
    ) async throws -> ActionBatchExtension
    /// Extends the lease; returns the new expiry.
    func renewActionBatch(_ auth: AuthID, batchId: String) async throws -> Date
    func commitActionBatch(
        _ auth: AuthID, _ manifest: ActionBatchManifest
    ) async throws -> ActionBatchCommitResult
    /// Releases every reservation. `false` when the batch had already committed.
    func abortActionBatch(_ auth: AuthID, batchId: String) async throws -> Bool
    /// The ordinary call, for a broadcast the batch does not own (`sendWith` of unrelated txids).
    func processAction(
        _ auth: AuthID, _ request: StorageProcessActionRequest
    ) async throws -> StorageProcessActionResult
}

// MARK: - Validated argument shapes

/// The `@bsv/sdk` validated createAction shapes (`ValidCreateActionInput`, `ValidCreateActionOutput`,
/// `ValidCreateActionArgs`) as ordered JSON, member for member in the SDK's order.
///
/// Ordinary `createAction`, the BRC-177 target and action batches all send this shape, because
/// storage reads it without validating it again: `outpoint.txid` and `outpoint.vout` as an object,
/// `sequenceNumber` always present, identifiers already trimmed and lowercased, and every derived
/// flag set. Action-batch metadata is also part of the manifest digest, so member order matters.
public enum ActionBatchWire {
    /// `specOpThrowReviewActions` (`@bsv/sdk` `validationHelpers.ts`). A label equal to this makes
    /// the validator set `isTestWerrReviewActions`, which asks storage for a test review error.
    public static let throwReviewActionsLabel =
        "a496e747fc3ad5fabdd4ae8f91184e71f87539bd3d962aa2548942faaaf0047a"

    /// A basket, label or tag as the SDK's `validateIdentifier` returns it: trimmed, lowercased.
    /// Storage stores and matches what it receives, so an unnormalised name would be a different
    /// basket, label or tag there than the same name sent by the reference wallet.
    public static func identifier(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    public static func identifiers(_ values: [String]) -> [String] {
        values.map(identifier)
    }

    /// `{txid, vout}`, as `parseWalletOutpoint` produces it.
    public static func outpoint(_ outpoint: Outpoint) -> OrderedJSON {
        .record([
            "txid": .string(outpoint.transactionID.displayHex),
            "vout": .int(outpoint.outputIndex),
        ])
    }

    /// `ValidCreateActionInput`. `sequenceNumber` defaults to 0xffffffff, as the SDK's validator
    /// fills it in; `unlockingScript` is present only when the caller supplied one.
    public static func input(_ input: WalletCreateActionInput, includeUnlockingScript: Bool = true) -> OrderedJSON {
        let script: [UInt8]?
        let length: UInt32
        switch input.unlocking {
        case .script(let bytes):
            script = bytes
            length = UInt32(bytes.count)
        case .scriptLength(let declared):
            script = nil
            length = declared
        }
        return .record([
            "outpoint": outpoint(input.outpoint),
            "inputDescription": .string(input.inputDescription),
            "unlockingScript": includeUnlockingScript ? script.map { .string(hex($0)) } : nil,
            "unlockingScriptLength": .int(length),
            "sequenceNumber": .int(input.sequenceNumber ?? 0xffff_ffff),
        ])
    }

    /// `ValidCreateActionOutput`. An absent basket or custom instructions is left out, as
    /// `JSON.stringify` leaves out the SDK's `undefined`.
    public static func output(_ output: WalletCreateActionOutput, lockingScript: String? = nil) -> OrderedJSON {
        .record([
            "lockingScript": .string(lockingScript ?? hex(output.lockingScript)),
            "satoshis": .int(output.satoshis),
            "outputDescription": .string(output.outputDescription),
            "basket": output.basket.map { .string(identifier($0)) },
            "customInstructions": output.customInstructions.map { .string($0) },
            "tags": .strings(identifiers(output.tags)),
        ])
    }

    /// `ValidCreateActionArgs` for a request the wallet signs itself, with outpoints as objects.
    ///
    /// `compact` is the reference's `actionBatchBootstrap`: proof bytes and unlocking scripts are
    /// dropped and output scripts emptied, because storage needs only their lengths to reserve
    /// funding and derives everything else from the signed transactions at commit.
    ///
    /// `stripUnlockingScripts` is the reference signer's `removeUnlockScripts` and BRC-177
    /// `targetForStorage`: storage never receives an unlocking script, only its length.
    /// `includeAllSourceTransactions` is the value the reference `Wallet` writes over the
    /// validator's default before calling storage.
    ///
    /// The derived flags are computed as `validateCreateActionArgs` computes them, with
    /// `signAndProcess` false because this wallet signs every action itself.
    public static func createActionArguments(
        _ request: WalletCreateActionRequest, compact: Bool, beefLimits: BEEFLimits,
        stripUnlockingScripts: Bool = false, includeAllSourceTransactions: Bool = false
    ) throws -> OrderedJSON {
        let inputs = request.inputs ?? []
        let outputs = request.outputs ?? []
        let options = request.options
        let noSend = options?.noSend ?? false
        let delayed = options?.acceptDelayedBroadcast ?? true
        let sendWith = (options?.sendWith ?? []).map(\.displayHex)
        let inputBEEF: OrderedJSON?
        if compact {
            inputBEEF = nil
        } else {
            inputBEEF = try request.inputBEEF.map { .bytes(try $0.serialized(limits: beefLimits)) }
        }
        let trustSelf: OrderedJSON? = options?.trustSelf.map { .string($0.rawValue) }
        let knownTxids: [String] = (options?.knownTransactionIDs ?? []).map(\.displayHex)
        let noSendChange: [OrderedJSON] = (options?.noSendChange ?? []).map(outpoint)
        let optionsJSON: OrderedJSON = .record([
            "signAndProcess": .bool(false),
            "acceptDelayedBroadcast": .bool(delayed),
            "trustSelf": trustSelf,
            "knownTxids": .strings(knownTxids),
            "returnTXIDOnly": .bool(options?.returnTransactionIDOnly ?? false),
            "noSend": .bool(noSend),
            "noSendChange": .array(noSendChange),
            "sendWith": .strings(sendWith),
            "randomizeOutputs": .bool(options?.randomizeOutputs ?? true),
        ])
        let inputsJSON: [OrderedJSON] = inputs.map {
            input($0, includeUnlockingScript: !compact && !stripUnlockingScripts)
        }
        let outputsJSON: [OrderedJSON] = outputs.map { output($0, lockingScript: compact ? "" : nil) }
        let lockTime: UInt32 = request.lockTime ?? 0
        let version: UInt32 = request.version ?? 1
        let labels = identifiers(request.labels ?? [])
        let isSendWith = !sendWith.isEmpty
        let isRemixChange = !isSendWith && inputs.isEmpty && outputs.isEmpty
        let isNewTx = isRemixChange || !inputs.isEmpty || !outputs.isEmpty
        return .record([
            "description": .string(request.description),
            "inputBEEF": inputBEEF,
            "inputs": .array(inputsJSON),
            "outputs": .array(outputsJSON),
            "lockTime": .int(lockTime),
            "version": .int(version),
            "labels": .strings(labels),
            "options": optionsJSON,
            "isSendWith": .bool(isSendWith),
            "isDelayed": .bool(delayed),
            "isNoSend": .bool(noSend),
            "isNewTx": .bool(isNewTx),
            "isRemixChange": .bool(isRemixChange),
            // `isNewTx && (!signAndProcess || …)`, and signAndProcess is false here.
            "isSignAction": .bool(isNewTx),
            "includeAllSourceTransactions": .bool(includeAllSourceTransactions),
            "isTestWerrReviewActions": .bool(labels.contains(throwReviewActionsLabel)),
        ])
    }

    /// Lowercase hex, which is how every script travels in these shapes.
    public static func hex(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var text = [UInt8]()
        text.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            text.append(digits[Int(byte >> 4)])
            text.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: text, as: UTF8.self)
    }
}
