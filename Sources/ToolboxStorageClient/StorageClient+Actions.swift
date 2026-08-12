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
        return try Self.decodeCreateAction(result)
    }

    /// The validated argument shape the storage protocol expects.
    ///
    /// Fields the reference client always sends are always sent, including empty collections. The
    /// server reads several of them without checking they exist, so an omitted empty array is a
    /// fault there rather than a default here — `tags` on `listOutputs` proved that the hard way.
    static func arguments(for request: WalletCreateActionRequest) -> [String: JSONValue] {
        let requestedOutputs = request.outputs ?? []
        let requestedInputs = request.inputs ?? []
        let options = request.options

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

        // Caller inputs travel with their outpoint, sequence and the length of the unlocking
        // script they will carry once signed. The script bytes themselves are not sent — storage
        // does not sign — but the length is, so the fee it funds matches the final weight.
        let inputs = requestedInputs.map { input -> JSONValue in
            var encoded: [String: JSONValue] = [
                "outpoint": .string(input.outpoint.description),
                "inputDescription": .string(input.inputDescription),
                "unlockingScriptLength": .number(Double(unlockingLength(of: input.unlocking))),
            ]
            if let sequence = input.sequenceNumber {
                encoded["sequenceNumber"] = .number(Double(sequence))
            }
            return .object(encoded)
        }

        let isNewTx = !requestedOutputs.isEmpty || !requestedInputs.isEmpty
        let noSend = options?.noSend ?? false
        let delayed = options?.acceptDelayedBroadcast ?? false
        let sendWith = (options?.sendWith ?? []).map { JSONValue.string($0.displayHex) }

        return [
            "description": .string(request.description),
            "inputs": .array(inputs),
            "outputs": .array(outputs),
            "lockTime": .number(Double(request.lockTime ?? 0)),
            "version": .number(Double(request.version ?? 1)),
            "labels": .array((request.labels ?? []).map { .string($0) }),
            "options": .object([
                "acceptDelayedBroadcast": .bool(delayed),
                "returnTXIDOnly": .bool(options?.returnTransactionIDOnly ?? false),
                "noSend": .bool(noSend),
                "sendWith": .array(sendWith),
                // Overridden, and only this one: the wallet holds the keys, so storage must stop
                // and hand the action back rather than completing it.
                "signAndProcess": .bool(false),
                "knownTxids": .array(
                    (options?.knownTransactionIDs ?? []).map { .string($0.displayHex) }
                ),
                "noSendChange": .array(
                    (options?.noSendChange ?? []).map { .string($0.description) }
                ),
                "randomizeOutputs": .bool(options?.randomizeOutputs ?? true),
            ]),
            "isSignAction": .bool(true),
            "isSendWith": .bool(!sendWith.isEmpty),
            "isNewTx": .bool(isNewTx),
            "isRemixChange": .bool(false),
            "isNoSend": .bool(noSend),
            "isDelayed": .bool(delayed),
            "isTestWerrReviewActions": .bool(false),
            "includeAllSourceTransactions": .bool(false),
        ]
    }

    private static func unlockingLength(of unlocking: WalletInputUnlocking) -> UInt32 {
        switch unlocking {
        case .script(let bytes): UInt32(bytes.count)
        case .scriptLength(let length): length
        }
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
                derivationSuffix: row["derivationSuffix"]?.stringValue
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
