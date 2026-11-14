import Foundation
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// Asking storage to fund a transaction.
///
/// This is the first call that writes. Storage picks which of the wallet's outputs to spend,
/// reserves them, works out the change, and returns an action that is funded but unsigned. Keys
/// never come here; signing happens above this layer.
///
/// Which is why the result is not trusted. Storage also echoes back the outputs it says were
/// requested, and the signer compares them against the real request before signing anything —
/// see `ToolboxActions.OutputVerification` and `docs/DESIGN.md` §6.
extension StorageClient {

    public func createAction(
        _ auth: AuthID, _ request: WalletCreateActionRequest,
        includeAllSourceTransactions: Bool = false
    ) async throws -> StorageCreateActionResult {
        let result = try await call(
            "createAction", rawParams: [Self.authJSON(auth), try Self.createActionWireArguments(
                for: request, includeAllSourceTransactions: includeAllSourceTransactions
            )]
        )
        return try Self.decodeCreateAction(result)
    }

    /// The second positional parameter of `createAction`, as the reference `StorageClient` sends it.
    ///
    /// The validated arguments, less `inputBEEF` when there are no caller inputs: the reference
    /// client drops it there (`StorageClientBase.createAction`), since storage has nothing to
    /// read it for.
    static func createActionWireArguments(
        for request: WalletCreateActionRequest, includeAllSourceTransactions: Bool = false
    ) throws -> OrderedJSON {
        let validated = try validatedArguments(
            for: request, includeAllSourceTransactions: includeAllSourceTransactions
        )
        guard (request.inputs ?? []).isEmpty else { return validated }
        return validated.setting("inputBEEF", nil)
    }

    /// Hands a signed transaction back for finalisation and broadcast.
    ///
    /// This is the call that actually sends money. It carries the reference the inputs were
    /// reserved under and the raw signed transaction plus its txid; storage commits its records and,
    /// unless the action was `noSend`, broadcasts.
    public func processAction(
        _ auth: AuthID, _ request: StorageProcessActionRequest
    ) async throws -> StorageProcessActionResult {
        var arguments: [String: JSONValue] = [
            "reference": .string(request.reference),
            "isNewTx": .bool(request.isNewTx),
            "isSendWith": .bool(request.isSendWith),
            "isNoSend": .bool(request.isNoSend),
            "isDelayed": .bool(request.isDelayed),
            "sendWith": .array(request.sendWith.map { .string($0) }),
        ]
        // Both reference implementations require raw Bitcoin bytes plus their exact txid.
        // Atomic BEEF belongs to the wallet result, not the storage processAction request.
        if let rawTX = request.rawTX {
            let transaction = try Transaction(bytes: rawTX, limits: StorageLimits.transaction)
            arguments["txid"] = .string(try transaction.transactionID(limits: StorageLimits.transaction).displayHex)
            arguments["rawTx"] = .array(rawTX.map { .number(Double($0)) })
        }

        let result = try await call("processAction", [.object(auth.jsonObject), .object(arguments)])
        return try Self.decodeProcessAction(result)
    }

    static func decodeProcessAction(_ result: JSONValue) throws -> StorageProcessActionResult {
        let rows = result["sendWithResults"]?.arrayValue ?? []
        let sendWith = try rows.map { row -> SendWithResult in
            guard let txid = row["txid"]?.stringValue,
                  let statusText = row["status"]?.stringValue,
                  let status = SendWithResult.Status(rawValue: statusText) else {
                throw StorageClientError.unreadableResponse(method: "processAction")
            }
            return SendWithResult(txid: txid, status: status)
        }
        return StorageProcessActionResult(sendWithResults: sendWith)
    }

    /// The validated argument shape the storage protocol expects: `@bsv/sdk`
    /// `validateCreateActionArgs`, then the reference signer's `removeUnlockScripts`.
    ///
    /// Storage does not validate these again. It reads `outpoint.txid` and `outpoint.vout` from
    /// each input and from each `noSendChange` entry, and the derived flags as given, so the raw
    /// BRC-100 shape (outpoints as `"txid.vout"` strings) fails inside storage as `WERR_INTERNAL`.
    /// Fields the reference always sends are always sent, including empty collections.
    static func validatedArguments(
        for request: WalletCreateActionRequest, includeAllSourceTransactions: Bool = false
    ) throws -> OrderedJSON {
        try ActionBatchWire.createActionArguments(
            request, compact: false, beefLimits: StorageLimits.beef,
            stripUnlockingScripts: true,
            includeAllSourceTransactions: includeAllSourceTransactions
        )
    }

    /// `validatedArguments` read back by key, for callers and tests that inspect members.
    static func arguments(
        for request: WalletCreateActionRequest, includeAllSourceTransactions: Bool = false
    ) throws -> [String: JSONValue] {
        try validatedArguments(
            for: request, includeAllSourceTransactions: includeAllSourceTransactions
        ).jsonValue.objectValue ?? [:]
    }

    /// Reads the funded action.
    ///
    /// Every field the protocol mandates is required, not defaulted. A funded action with no
    /// version, no lock time, or no inputs array is a truncated response, and inventing values for
    /// it would hand the signer a transaction storage never actually described.
    static func decodeCreateAction(_ result: JSONValue) throws -> StorageCreateActionResult {
        guard let reference = result["reference"]?.stringValue,
              let versionValue = result["version"]?.intValue,
              let lockTimeValue = result["lockTime"]?.intValue,
              let inputRows = result["inputs"]?.arrayValue,
              let outputRows = result["outputs"]?.arrayValue else {
            throw StorageClientError.unreadableResponse(method: "createAction")
        }

        let inputs = try inputRows.map { row -> StorageActionInput in
            guard let txid = row["sourceTxid"]?.stringValue ?? row["sourceTXID"]?.stringValue,
                  let vout = row["sourceVout"]?.intValue.flatMap(UInt32.init(exactly:)),
                  let satoshis = row["sourceSatoshis"]?.intValue, satoshis >= 0,
                  let scriptText = row["sourceLockingScript"]?.stringValue,
                  let script = hexBytes(scriptText),
                  let unlockingLength = row["unlockingScriptLength"]?.intValue
                    .flatMap(UInt32.init(exactly:)) else {
                throw StorageClientError.unreadableResponse(method: "createAction")
            }
            return StorageActionInput(
                sourceTXID: txid,
                sourceVout: vout,
                sourceSatoshis: Int64(satoshis),
                sourceLockingScript: script,
                unlockingScriptLength: unlockingLength,
                derivationPrefix: row["derivationPrefix"]?.stringValue,
                derivationSuffix: row["derivationSuffix"]?.stringValue,
                senderIdentityKey: row["senderIdentityKey"]?.stringValue,
                vin: row["vin"]?.intValue.flatMap(UInt32.init(exactly:))
            )
        }

        // Every output storage put in the transaction, kept exactly as sent and never merged
        // with our own request. Substituting ours where storage's is absent would make the
        // security comparison compare the request with itself and pass for anything.
        let outputs = try outputRows.enumerated().map { index, row -> StorageActionOutput in
            guard let scriptText = row["lockingScript"]?.stringValue,
                  let script = hexBytes(scriptText),
                  let satoshis = row["satoshis"]?.intValue, satoshis >= 0,
                  let vout = row["vout"]?.intValue.flatMap({ UInt32(exactly: $0) })
                    ?? UInt32(exactly: index) else {
                throw StorageClientError.unreadableResponse(method: "createAction")
            }
            return StorageActionOutput(
                vout: vout,
                satoshis: UInt64(satoshis),
                lockingScript: script,
                providedBy: row["providedBy"]?.stringValue
                    .flatMap(StorageActionOutput.ProvidedBy.init(rawValue:)),
                purpose: row["purpose"]?.stringValue
                    .flatMap(StorageActionOutput.Purpose.init(rawValue:)),
                derivationSuffix: row["derivationSuffix"]?.stringValue
            )
        }

        return StorageCreateActionResult(
            reference: reference,
            version: try narrow(versionValue),
            lockTime: try narrow(lockTimeValue),
            outputs: outputs,
            inputs: inputs,
            // The funded proof graph arrives as a JSON byte array, not a hex string. Reading it as
            // hex silently produced nil and lost the ancestors an Atomic BEEF has to carry.
            inputBEEF: try byteArray(result["inputBeef"]),
            derivationPrefix: result["derivationPrefix"]?.stringValue
        )
    }

    /// Reads a JSON array of byte values, bounded. Absent is `nil`; malformed is a refusal, not a
    /// silent `nil`, because an unreadable proof graph is not the same as no proof graph.
    static func byteArray(_ value: JSONValue?, maximumCount: Int = 8 << 20) throws -> [UInt8]? {
        guard let value, value != .null else { return nil }
        guard let elements = value.arrayValue, elements.count <= maximumCount else {
            throw StorageClientError.unreadableResponse(method: "createAction")
        }
        return try elements.map { element in
            guard let byte = element.intValue, let narrowed = UInt8(exactly: byte) else {
                throw StorageClientError.unreadableResponse(method: "createAction")
            }
            return narrowed
        }
    }

    /// Narrows a wire integer, refusing rather than trapping. A hostile server sending
    /// 4294967296 would otherwise crash the process.
    static func narrow(_ value: Int) throws -> UInt32 {
        guard let narrowed = UInt32(exactly: value) else {
            throw StorageClientError.unreadableResponse(method: "createAction")
        }
        return narrowed
    }

    static func hexText(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
