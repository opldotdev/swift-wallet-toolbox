import Foundation
import BSVCore
import BSVCrypto
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// The commit manifest's content digests, ported from `utility/actionBatchDigest.js`.
///
/// Storage recomputes `digest` from the manifest it receives (`verifyActionBatchManifestDigest`)
/// and refuses the commit on any difference. The digest is SHA-256 of the UTF-8 of
/// `JSON.stringify` of a payload built from the manifest with JavaScript object spreads, so the
/// payload here is built from the very `OrderedJSON` that is sent, with `setting(_:_:)` standing
/// in for each spread. Only the format-2 payload is ported, because only format-2 manifests are
/// built; see `ActionBatchController`.
public enum ActionBatchDigest {

    /// `actionBatchBlobDigest`: lowercase hex SHA-256.
    public static func blob(_ bytes: [UInt8]) -> String {
        ActionBatchWire.hex(BSVHashing.sha256(bytes).bytes)
    }

    /// `actionBatchManifestDigest` for a manifest without its `digest` member.
    public static func manifest(_ manifest: OrderedJSON) throws -> String {
        guard manifest["format"]?.int64Value == 2 else {
            throw ActionBatchError.invalidOperation("only format-2 manifests are supported")
        }
        return blob(try payload(manifest).utf8Bytes())
    }

    /// `verifyActionBatchManifestDigest`: the digest storage will compute for a full manifest.
    public static func verify(_ manifest: OrderedJSON) throws -> Bool {
        guard let digest = manifest["digest"]?.stringValue else { return false }
        return try self.manifest(manifest.setting("digest", nil)) == digest
    }

    /// The format-2 payload of `actionBatchManifestDigestV2`.
    static func payload(_ manifest: OrderedJSON) throws -> OrderedJSON {
        let actions = try (manifest["actions"]?.arrayValue ?? []).map { action -> OrderedJSON in
            guard let plan = action["plan"], let metadata = action["metadata"] else {
                throw ActionBatchError.invalidOperation("manifest action without plan or metadata")
            }
            let rawTxDigest = try nonNull(action["rawTxDigest"]) ?? .string(blob(bytes(action["rawTx"])))
            return .record([
                "reference": action["reference"],
                "txid": action["txid"],
                "rawTxDigest": rawTxDigest,
                "lockingScriptDigests": action["lockingScriptDigests"],
                "deriveLockingScripts": .bool(action["deriveLockingScripts"] == .bool(true)),
                "plan": .record([
                    "inputs": .array((plan["inputs"]?.arrayValue ?? []).map {
                        $0.setting("sourceLockingScript", nil).setting("sourceTransaction", nil)
                    }),
                    "outputs": .array((plan["outputs"]?.arrayValue ?? []).map {
                        $0.setting("lockingScript", .string(""))
                    }),
                    "noSendChangeOutputVouts": plan["noSendChangeOutputVouts"],
                    "derivationPrefix": plan["derivationPrefix"],
                    "version": plan["version"],
                    "lockTime": plan["lockTime"],
                    "reference": plan["reference"],
                ]),
                "metadata": metadata.setting(
                    "outputs",
                    .array((metadata["outputs"]?.arrayValue ?? []).map {
                        $0.setting("lockingScript", .string(""))
                    })
                ),
                "commissionKeyOffset": action["commissionKeyOffset"],
            ])
        }
        let dependencyDigest = try nonNull(manifest["dependencyBeefDigest"])
            ?? .string(blob(bytes(manifest["dependencyBeef"])))
        return .record([
            "format": .integer(2),
            "batchId": manifest["batchId"],
            "actions": .array(actions),
            "dependencyBeefDigest": dependencyDigest,
            "sendWith": manifest["sendWith"],
            "isDelayed": manifest["isDelayed"],
        ])
    }

    /// JavaScript's `??` treats `null` like `undefined`.
    private static func nonNull(_ value: OrderedJSON?) -> OrderedJSON? {
        value == .null ? nil : value
    }

    private static func bytes(_ value: OrderedJSON?) throws -> [UInt8] {
        guard let values = nonNull(value)?.arrayValue else { return [] }
        return try values.map { value in
            guard let byte = value.int64Value.flatMap(UInt8.init(exactly:)) else {
                throw ActionBatchError.invalidOperation("manifest bytes are not a byte array")
            }
            return byte
        }
    }
}

/// A signed member, staged for the commit (the reference's `ActionBatchCommitAction`).
struct StagedAction: Sendable {
    let reference: String
    let txid: String
    let rawTx: [UInt8]
    let inputSourceTxids: [String]
    /// Decided when the action was planned; see `ActionBatchController.process`.
    let isNoSend: Bool
    /// The format-2 action object without `rawTx`, in the reference's member order.
    let json: OrderedJSON

    /// `ActionBatchWorkspace.stage` for a format-2 workspace.
    init(planned: PlannedAction, transaction: Transaction, isDelayed: Bool) throws {
        let limits = WalletTransactionLimits.standard
        let txid = try transaction.transactionID(limits: limits).displayHex
        // Storage checks these at commit; checking here keeps a mismatched signature from being
        // staged as if it were the planned action.
        guard transaction.inputs.count == planned.inputs.count,
              transaction.outputs.count == planned.outputs.count,
              transaction.version == planned.version, transaction.lockTime == planned.lockTime else {
            throw ActionBatchError.invalidOperation("signed transaction does not match its plan")
        }
        let rawTx = try transaction.serialized(limits: limits)
        let scriptDigests = try planned.outputs.map { output -> OrderedJSON in
            guard transaction.outputs.indices.contains(Int(output.vout)) else {
                throw ActionBatchError.invalidOperation("missing staged output script for \(txid).\(output.vout)")
            }
            return .string(ActionBatchDigest.blob(transaction.outputs[Int(output.vout)].lockingScript.bytes))
        }
        let request = planned.request
        let plan = OrderedJSON.record([
            "reference": .string(planned.reference),
            "version": .int(planned.version),
            "lockTime": .int(planned.lockTime),
            "inputs": .array(planned.inputs.map(\.compactJSON)),
            "outputs": .array(try planned.outputs.map { try $0.compactJSON() }),
            "derivationPrefix": .string(planned.derivationPrefix),
            "noSendChangeOutputVouts": planned.noSendChangeOutputVouts.map { .array($0.map { .int($0) }) },
        ])
        let metadata = OrderedJSON.record([
            "description": .string(request.description),
            "labels": .strings(try ActionBatchWire.identifiers(request.labels ?? [], name: "label")),
            "isNoSend": .bool(planned.isNoSend),
            "isDelayed": .bool(isDelayed),
            "inputs": .array((request.inputs ?? []).map { ActionBatchWire.input($0) }),
            "outputs": .array(try (request.outputs ?? []).map { try ActionBatchWire.output($0, lockingScript: "") }),
        ])
        self.reference = planned.reference
        self.txid = txid
        self.rawTx = rawTx
        self.inputSourceTxids = planned.inputs.map(\.sourceTxid)
        self.isNoSend = planned.isNoSend
        self.json = .record([
            "reference": .string(planned.reference),
            "txid": .string(txid),
            "rawTxDigest": .string(ActionBatchDigest.blob(rawTx)),
            "lockingScriptDigests": .array(scriptDigests),
            "deriveLockingScripts": .bool(true),
            "plan": plan,
            "metadata": metadata,
        ])
    }
}

/// `ActionBatchWorkspace.buildManifest` for format 2 with every blob inline.
enum ActionBatchManifestBuilder {
    static func build(
        batchId: String, actions: [StagedAction], sharedBeef: BEEF, sendWith: [String],
        isDelayed: Bool, maxInlineBytes: Int
    ) throws -> ActionBatchManifest {
        // `validateCreateActionOptions({ sendWith: mergeUnique(sendWith) })`: unique, in order.
        var seen = Set<String>()
        let normalizedSendWith = sendWith.filter { seen.insert($0).inserted }

        let staged = Set(actions.map(\.txid))
        let external = try actions.flatMap(\.inputSourceTxids)
            .filter { !staged.contains($0) }
            .map { try TransactionID(displayHex: $0) }
        let dependency = try ActionBatchBEEF.subgraph(sharedBeef, txids: external)
            .serialized(limits: PlannerState.beefLimits)

        var blobs: [(digest: String, bytes: [UInt8])] = []
        func add(_ bytes: [UInt8]) -> String {
            let digest = ActionBatchDigest.blob(bytes)
            if !blobs.contains(where: { $0.digest == digest }) { blobs.append((digest, bytes)) }
            return digest
        }
        let actionJSON = actions.map { action in
            action.json.setting("rawTxDigest", .string(add(action.rawTx)))
        }
        let dependencyDigest = add(dependency)
        let total = blobs.reduce(0) { $0 + $1.bytes.count }
        // The reference uploads blobs past this limit (`prepareActionBatchCommit`,
        // `putActionBatchBlob`, packs, commit by digest). That path is not ported: a SIGMA
        // anchor and its publish are a few kilobytes.
        guard total <= maxInlineBytes else {
            throw ActionBatchError.manifestTooLarge(bytes: total, limit: maxInlineBytes)
        }

        let withoutDigest = OrderedJSON.record([
            "format": .integer(2),
            "batchId": .string(batchId),
            "actions": .array(actionJSON),
            "dependencyBeefDigest": .string(dependencyDigest),
            "inlineBlobs": .object(blobs.map { .init($0.digest, .bytes($0.bytes)) }),
            "sendWith": .strings(normalizedSendWith),
            "isDelayed": .bool(isDelayed),
        ])
        let digest = try ActionBatchDigest.manifest(withoutDigest)
        return ActionBatchManifest(
            batchId: batchId, digest: digest,
            body: withoutDigest.setting("digest", .string(digest))
        )
    }
}
