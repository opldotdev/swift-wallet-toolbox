import Foundation
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// The action-batch storage calls, in the reference client's wire shape
/// (`StorageClientBase.js` in `@bsv/wallet-toolbox` 2.15.3):
///
///     getCapabilities     []
///     beginActionBatch    [auth, {batchId, firstAction, firstActionOutputScriptLengths?}]
///     extendActionBatch   [auth, {batchId, targetSatoshis, requestedOutputs, explicitOutpoints,
///                                 includeSourceTransactions}]
///     renewActionBatch    [auth, batchId]
///     commitActionBatch   [auth, manifest]
///     abortActionBatch    [auth, batchId]
///
/// Every call goes through `call(_:rawParams:)`, so the manifest reaches storage in the member
/// order its digest was computed over.
extension StorageClient: ActionBatchStorage {

    public func actionBatchCapabilities() async throws -> ActionBatchCapabilities? {
        let result = try await call("getCapabilities", rawParams: [])
        guard let batch = result["actionBatch"], batch != .null else { return nil }
        return try Self.decodeCapabilities(batch)
    }

    public func beginActionBatch(
        _ auth: AuthID, _ request: ActionBatchBeginRequest
    ) async throws -> ActionBatchBegin {
        let result = try await call("beginActionBatch", rawParams: [
            Self.authJSON(auth), try Self.beginArguments(request),
        ])
        return try Self.decodeBegin(result)
    }

    public func extendActionBatch(
        _ auth: AuthID, _ request: ActionBatchExtendRequest
    ) async throws -> ActionBatchExtension {
        let result = try await call("extendActionBatch", rawParams: [
            Self.authJSON(auth), Self.extendArguments(request),
        ])
        return try Self.decodeExtension(result)
    }

    public func renewActionBatch(_ auth: AuthID, batchId: String) async throws -> Date {
        let result = try await call("renewActionBatch", rawParams: [
            Self.authJSON(auth), .string(batchId),
        ])
        guard let expiresAt = result["expiresAt"]?.stringValue.flatMap(Self.date) else {
            throw StorageClientError.unreadableResponse(method: "renewActionBatch")
        }
        return expiresAt
    }

    public func commitActionBatch(
        _ auth: AuthID, _ manifest: ActionBatchManifest
    ) async throws -> ActionBatchCommitResult {
        let result = try await call("commitActionBatch", rawParams: [
            Self.authJSON(auth), manifest.body,
        ])
        return try Self.decodeCommit(result)
    }

    public func abortActionBatch(_ auth: AuthID, batchId: String) async throws -> Bool {
        let result = try await call("abortActionBatch", rawParams: [
            Self.authJSON(auth), .string(batchId),
        ])
        guard let aborted = result["aborted"]?.boolValue else {
            throw StorageClientError.unreadableResponse(method: "abortActionBatch")
        }
        return aborted
    }

    // MARK: - Arguments

    static func authJSON(_ auth: AuthID) -> OrderedJSON {
        .record([
            "identityKey": .string(auth.identityKey),
            "userId": auth.userID.map { .int($0) },
        ])
    }

    static func beginArguments(_ request: ActionBatchBeginRequest) throws -> OrderedJSON {
        let outputs = request.firstAction.outputs ?? []
        return .record([
            "batchId": .string(request.batchId),
            "firstAction": try ActionBatchWire.createActionArguments(
                request.firstAction, compact: request.compact, beefLimits: StorageLimits.beef
            ),
            "firstActionOutputScriptLengths": request.compact
                ? .array(outputs.map { .int($0.lockingScript.count) })
                : nil,
        ])
    }

    static func extendArguments(_ request: ActionBatchExtendRequest) -> OrderedJSON {
        .record([
            "batchId": .string(request.batchId),
            "targetSatoshis": .int(request.targetSatoshis),
            "requestedOutputs": .int(request.requestedOutputs),
            "explicitOutpoints": .array(request.explicitOutpoints.map(ActionBatchWire.outpoint)),
            "includeSourceTransactions": .bool(request.includeSourceTransactions),
        ])
    }

    // MARK: - Results

    static func decodeCapabilities(_ value: JSONValue) throws -> ActionBatchCapabilities? {
        guard let version = value["version"]?.intValue else {
            throw StorageClientError.unreadableResponse(method: "getCapabilities")
        }
        // The reference negotiates version 1 only; any other version is "not supported".
        guard version == 1 else { return nil }
        guard let maxInlineBytes = value["maxInlineBytes"]?.intValue,
              let maxBlobBytes = value["maxBlobBytes"]?.intValue,
              let maxConcurrentUploads = value["maxConcurrentUploads"]?.intValue,
              let leaseMs = value["leaseMs"]?.intValue, leaseMs > 0,
              let hardLifetimeMs = value["hardLifetimeMs"]?.intValue else {
            throw StorageClientError.unreadableResponse(method: "getCapabilities")
        }
        return ActionBatchCapabilities(
            version: version,
            maxInlineBytes: maxInlineBytes,
            maxBlobBytes: maxBlobBytes,
            maxConcurrentUploads: maxConcurrentUploads,
            leaseMs: leaseMs,
            hardLifetimeMs: hardLifetimeMs,
            compactBegin: value["compactBegin"]?.boolValue ?? false,
            manifestVersion: value["manifestVersion"]?.intValue,
            commitByDigest: value["commitByDigest"]?.boolValue ?? false,
            resume: value["resume"]?.boolValue ?? false,
            maxReservedOutputs: value["maxReservedOutputs"]?.intValue
        )
    }

    static func decodeBegin(_ result: JSONValue) throws -> ActionBatchBegin {
        let method = "beginActionBatch"
        guard let batchId = result["batchId"]?.stringValue,
              let expiresAt = result["expiresAt"]?.stringValue.flatMap(date),
              let hardExpiresAt = result["hardExpiresAt"]?.stringValue.flatMap(date),
              let basket = result["changeBasket"],
              let basketId = basket["basketId"]?.intValue,
              let basketName = basket["name"]?.stringValue,
              let desiredCount = basket["numberOfDesiredUTXOs"]?.intValue,
              let desiredValue = basket["minimumDesiredUTXOValue"]?.intValue,
              let feeModel = result["feeModel"],
              let feeValue = feeModel["value"]?.doubleValue, feeValue >= 0,
              let commission = result["commissionSatoshis"]?.intValue, commission >= 0,
              let availableChangeCount = result["availableChangeCount"]?.intValue,
              let reserved = result["reservedOutputs"]?.arrayValue,
              let explicit = result["explicitOutputs"]?.arrayValue else {
            throw StorageClientError.unreadableResponse(method: method)
        }
        return ActionBatchBegin(
            batchId: batchId,
            expiresAt: expiresAt,
            hardExpiresAt: hardExpiresAt,
            changeBasket: ActionBatchChangeBasket(
                basketId: basketId, name: basketName, numberOfDesiredUTXOs: desiredCount,
                minimumDesiredUTXOValue: desiredValue
            ),
            feeModel: ActionBatchFeeModel(
                model: feeModel["model"]?.stringValue ?? "sat/kb", value: feeValue
            ),
            commissionSatoshis: UInt64(commission),
            commissionPubKeyHex: result["commissionPubKeyHex"]?.stringValue,
            availableChangeCount: availableChangeCount,
            reservedOutputs: try reserved.map { try fundingOutput($0, method: method) },
            explicitOutputs: try explicit.map { try fundingOutput($0, method: method) },
            inputBeef: try bytes(result["inputBeef"], method: method)
        )
    }

    static func decodeExtension(_ result: JSONValue) throws -> ActionBatchExtension {
        let method = "extendActionBatch"
        guard let expiresAt = result["expiresAt"]?.stringValue.flatMap(date),
              let reserved = result["reservedOutputs"]?.arrayValue,
              let explicit = result["explicitOutputs"]?.arrayValue else {
            throw StorageClientError.unreadableResponse(method: method)
        }
        return ActionBatchExtension(
            expiresAt: expiresAt,
            reservedOutputs: try reserved.map { try fundingOutput($0, method: method) },
            explicitOutputs: try explicit.map { try fundingOutput($0, method: method) },
            inputBeef: try bytes(result["inputBeef"], method: method)
        )
    }

    static func decodeCommit(_ result: JSONValue) throws -> ActionBatchCommitResult {
        let method = "commitActionBatch"
        guard let batchId = result["batchId"]?.stringValue,
              let digest = result["manifestDigest"]?.stringValue,
              let txids = result["committedTxids"]?.arrayValue,
              let alreadyCommitted = result["alreadyCommitted"]?.boolValue else {
            throw StorageClientError.unreadableResponse(method: method)
        }
        let committed = try txids.map { value -> String in
            guard let txid = value.stringValue else {
                throw StorageClientError.unreadableResponse(method: method)
            }
            return txid
        }
        return ActionBatchCommitResult(
            batchId: batchId,
            manifestDigest: digest,
            committedTxids: committed,
            alreadyCommitted: alreadyCommitted,
            sendWithResults: try decodeProcessAction(result).sendWithResults
        )
    }

    /// One `TableOutput` row. Amounts and indexes are required; derivation and scripts are
    /// optional because storage leaves them out for outputs that do not have them.
    static func fundingOutput(_ row: JSONValue, method: String) throws -> ActionBatchFundingOutput {
        guard let outputId = row["outputId"]?.intValue,
              let txid = row["txid"]?.stringValue, txid.count == 64, hexBytes(txid) != nil,
              let vout = row["vout"]?.intValue.flatMap(UInt32.init(exactly:)),
              let satoshis = row["satoshis"]?.intValue, satoshis >= 0 else {
            throw StorageClientError.unreadableResponse(method: method)
        }
        return ActionBatchFundingOutput(
            outputId: outputId,
            txid: txid,
            vout: vout,
            satoshis: UInt64(satoshis),
            spendable: row["spendable"]?.boolValue ?? true,
            change: row["change"]?.boolValue ?? false,
            providedBy: row["providedBy"]?.stringValue ?? "",
            purpose: row["purpose"]?.stringValue ?? "",
            type: row["type"]?.stringValue ?? "",
            basketId: row["basketId"]?.intValue,
            derivationPrefix: row["derivationPrefix"]?.stringValue,
            derivationSuffix: row["derivationSuffix"]?.stringValue,
            senderIdentityKey: row["senderIdentityKey"]?.stringValue,
            customInstructions: row["customInstructions"]?.stringValue,
            lockingScript: try script(row["lockingScript"], method: method),
            sourceTransaction: try bytes(row["sourceTransaction"], method: method)
        )
    }

    /// A script arrives as a byte array from the reference server; a hex string is accepted too.
    private static func script(_ value: JSONValue?, method: String) throws -> [UInt8]? {
        if let text = value?.stringValue {
            guard let decoded = hexBytes(text) else {
                throw StorageClientError.unreadableResponse(method: method)
            }
            return decoded
        }
        return try bytes(value, method: method)
    }

    private static func bytes(_ value: JSONValue?, method: String) throws -> [UInt8]? {
        do {
            return try byteArray(value)
        } catch {
            throw StorageClientError.unreadableResponse(method: method)
        }
    }

    /// `Date.toISOString()`, with or without milliseconds.
    static func date(_ text: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: text) { return date }
        let whole = ISO8601DateFormatter()
        whole.formatOptions = [.withInternetDateTime]
        return whole.date(from: text)
    }
}
