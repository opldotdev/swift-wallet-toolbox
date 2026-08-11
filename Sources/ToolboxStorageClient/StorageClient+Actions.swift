import Foundation
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
        _ auth: AuthID, _ request: WalletCreateActionRequest
    ) async throws -> StorageCreateActionResult {
        let result = try await call(
            "createAction", [.object(auth.jsonObject), .object(Self.arguments(for: request))]
        )
        return try Self.decodeCreateAction(result, requested: request.outputs ?? [])
    }

    /// The validated argument shape the storage protocol expects.
    ///
    /// Fields the reference client always sends are always sent, including empty collections. The
    /// server reads several of them without checking they exist, so an omitted empty array is a
    /// fault there rather than a default here — `tags` on `listOutputs` proved that the hard way.
    static func arguments(for request: WalletCreateActionRequest) -> [String: JSONValue] {
        let requestedOutputs = request.outputs ?? []
        let outputs = requestedOutputs.map { output -> JSONValue in
            var encoded: [String: JSONValue] = [
                "lockingScript": .string(hexText(output.lockingScript)),
                "satoshis": .number(Double(output.satoshis)),
                "outputDescription": .string(output.outputDescription),
                "tags": .array(output.tags.map { .string($0) }),
            ]
            if let basket = output.basket { encoded["basket"] = .string(basket) }
            if let instructions = output.customInstructions {
                encoded["customInstructions"] = .string(instructions)
            }
            return .object(encoded)
        }

        let isNewTx = !requestedOutputs.isEmpty || !(request.inputs ?? []).isEmpty

        return [
            "description": .string(request.description),
            "inputs": .array([]),
            "outputs": .array(outputs),
            "lockTime": .number(Double(request.lockTime ?? 0)),
            "version": .number(Double(request.version ?? 1)),
            "labels": .array((request.labels ?? []).map { .string($0) }),
            "options": .object([
                "acceptDelayedBroadcast": .bool(false),
                "returnTXIDOnly": .bool(false),
                "noSend": .bool(false),
                "sendWith": .array([]),
                "signAndProcess": .bool(false),
                "knownTxids": .array([]),
                "noSendChange": .array([]),
                "randomizeOutputs": .bool(false),
            ]),
            // The wallet signs, so storage must stop and hand the action back rather than
            // completing it. Anything else would mean storage holds keys, which it does not.
            "isSignAction": .bool(true),
            "isSendWith": .bool(false),
            "isNewTx": .bool(isNewTx),
            "isRemixChange": .bool(false),
            "isNoSend": .bool(false),
            "isDelayed": .bool(false),
            "isTestWerrReviewActions": .bool(false),
            "includeAllSourceTransactions": .bool(false),
        ]
    }

    /// Reads the funded action.
    ///
    /// `requested` is carried through so the outputs storage claims we asked for can be compared
    /// with the ones we did. This function does not perform that comparison — the signer does,
    /// where it cannot be skipped — but it keeps them together so the check has both sides.
    static func decodeCreateAction(
        _ result: JSONValue, requested: [WalletCreateActionOutput]
    ) throws -> StorageCreateActionResult {
        guard let reference = result["reference"]?.stringValue else {
            throw StorageClientError.unreadableResponse(method: "createAction")
        }

        let inputs = try (result["inputs"]?.arrayValue ?? []).map { row -> StorageActionInput in
            guard let txid = row["sourceTxid"]?.stringValue ?? row["sourceTXID"]?.stringValue,
                  let vout = row["sourceVout"]?.intValue, vout >= 0,
                  let satoshis = row["sourceSatoshis"]?.intValue, satoshis >= 0,
                  let scriptText = row["sourceLockingScript"]?.stringValue,
                  let script = hexBytes(scriptText),
                  let unlockingLength = row["unlockingScriptLength"]?.intValue,
                  unlockingLength >= 0 else {
                throw StorageClientError.unreadableResponse(method: "createAction")
            }
            return StorageActionInput(
                sourceTXID: txid,
                sourceVout: UInt32(vout),
                sourceSatoshis: Int64(satoshis),
                sourceLockingScript: script,
                unlockingScriptLength: UInt32(unlockingLength),
                derivationPrefix: row["derivationPrefix"]?.stringValue,
                derivationSuffix: row["derivationSuffix"]?.stringValue
            )
        }

        // What storage says we asked for. Kept exactly as sent, never merged with our own request,
        // because the whole point of the later comparison is that these two can differ.
        let echoed = try (result["outputs"]?.arrayValue).map { rows in
            try rows.map { row -> WalletCreateActionOutput in
                guard let scriptText = row["lockingScript"]?.stringValue,
                      let script = hexBytes(scriptText),
                      let satoshis = row["satoshis"]?.intValue, satoshis >= 0 else {
                    throw StorageClientError.unreadableResponse(method: "createAction")
                }
                return try WalletCreateActionOutput(
                    lockingScript: script,
                    satoshis: UInt64(satoshis),
                    outputDescription: row["outputDescription"]?.stringValue ?? "",
                    basket: row["basket"]?.stringValue,
                    customInstructions: row["customInstructions"]?.stringValue,
                    tags: row["tags"]?.arrayValue?.compactMap(\.stringValue) ?? []
                )
            }
        } ?? requested

        return StorageCreateActionResult(
            reference: reference,
            version: UInt32(max(0, result["version"]?.intValue ?? 1)),
            lockTime: UInt32(max(0, result["lockTime"]?.intValue ?? 0)),
            outputs: echoed,
            inputs: inputs,
            inputBEEF: result["inputBeef"]?.stringValue.flatMap(hexBytes),
            derivationPrefix: result["derivationPrefix"]?.stringValue
        )
    }

    static func hexText(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
