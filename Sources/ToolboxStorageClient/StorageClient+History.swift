import Foundation
import BSVCore
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// The read and housekeeping calls: history, abandoning an action, and giving up an output.
///
/// None of these move money, so none need the signer. They round out the storage surface a wallet
/// application actually calls between payments.
extension StorageClient {

    /// The wallet's transaction history.
    public func listActions(
        _ auth: AuthID, _ request: WalletListActionsRequest
    ) async throws -> WalletListActionsResult {
        var arguments: [String: JSONValue] = [
            "labels": .array(request.labels.map { .string($0) })
        ]
        if let limit = request.pagination.limit { arguments["limit"] = .number(Double(limit)) }
        if let offset = request.pagination.offset { arguments["offset"] = .number(Double(offset)) }
        if let mode = request.labelQueryMode {
            arguments["labelQueryMode"] = .string(mode.rawValue)
        }
        if let include = request.includeLabels {
            arguments["includeLabels"] = .bool(include)
        }
        if let include = request.includeInputs {
            arguments["includeInputs"] = .bool(include)
        }
        if let include = request.includeInputSourceLockingScripts {
            arguments["includeInputSourceLockingScripts"] = .bool(include)
        }
        if let include = request.includeInputUnlockingScripts {
            arguments["includeInputUnlockingScripts"] = .bool(include)
        }
        if let include = request.includeOutputs {
            arguments["includeOutputs"] = .bool(include)
        }
        if let include = request.includeOutputLockingScripts {
            arguments["includeOutputLockingScripts"] = .bool(include)
        }
        if let seek = request.seekPermission {
            arguments["seekPermission"] = .bool(seek)
        }

        let result = try await call("listActions", [.object(auth.jsonObject), .object(arguments)])
        return try Self.decodeActions(result)
    }

    static func decodeActions(_ result: JSONValue) throws -> WalletListActionsResult {
        guard let total = result["totalActions"]?.intValue,
              let totalActions = UInt32(exactly: total),
              let rows = result["actions"]?.arrayValue else {
            throw StorageClientError.unreadableResponse(method: "listActions")
        }
        let actions = try rows.map { row -> WalletAction in
            guard let txidText = row["txid"]?.stringValue,
                  let satoshis = row["satoshis"]?.intValue,
                  let statusText = row["status"]?.stringValue,
                  let status = decodeActionStatus(statusText),
                  let isOutgoing = row["isOutgoing"]?.boolValue,
                  let description = row["description"]?.stringValue,
                  let version = row["version"]?.intValue.flatMap(UInt32.init(exactly:)),
                  let lockTime = row["lockTime"]?.intValue.flatMap(UInt32.init(exactly:)) else {
                throw StorageClientError.unreadableResponse(method: "listActions")
            }
            do {
                return try WalletAction(
                    transactionID: try TransactionID(displayHex: txidText),
                    satoshis: Int64(satoshis),
                    status: status,
                    isOutgoing: isOutgoing,
                    description: description,
                    labels: try stringArray(row["labels"], method: "listActions"),
                    version: version,
                    lockTime: lockTime,
                    inputs: try decodeActionInputs(row["inputs"]),
                    outputs: try decodeActionOutputs(row["outputs"])
                )
            } catch let error as StorageClientError {
                throw error
            } catch {
                throw StorageClientError.unreadableResponse(method: "listActions")
            }
        }
        return try WalletListActionsResult(
            totalActions: totalActions, actions: actions
        )
    }

    /// Kept separate so unknown wire values fail closed instead of being flattened into a
    /// different history state. The pinned ABI represents every current BRC-100 status.
    private static func decodeActionStatus(_ text: String) -> WalletActionStatus? {
        WalletActionStatus(rawValue: text)
    }

    private static func decodeActionInputs(_ value: JSONValue?) throws -> [WalletActionInput]? {
        guard let rows = try optionalRows(value) else { return nil }
        return try rows.map { row in
            guard let outpointText = row["sourceOutpoint"]?.stringValue,
                  let sourceSatoshis = unsigned(row["sourceSatoshis"]),
                  let description = row["inputDescription"]?.stringValue,
                  let sequence = row["sequenceNumber"]?.intValue.flatMap(UInt32.init(exactly:)) else {
                throw StorageClientError.unreadableResponse(method: "listActions")
            }
            do {
                return try WalletActionInput(
                    sourceOutpoint: try Outpoint(outpointText),
                    sourceSatoshis: sourceSatoshis,
                    sourceLockingScript: try optionalHex(
                        row["sourceLockingScript"]
                    ),
                    unlockingScript: try optionalHex(row["unlockingScript"]),
                    inputDescription: description,
                    sequenceNumber: sequence
                )
            } catch let error as StorageClientError {
                throw error
            } catch {
                throw StorageClientError.unreadableResponse(method: "listActions")
            }
        }
    }

    private static func decodeActionOutputs(_ value: JSONValue?) throws -> [WalletActionOutput]? {
        guard let rows = try optionalRows(value) else { return nil }
        return try rows.map { row in
            guard let satoshis = unsigned(row["satoshis"]),
                  let spendable = row["spendable"]?.boolValue,
                  let tags = try requiredStrings(row["tags"]),
                  let outputIndex = row["outputIndex"]?.intValue.flatMap(UInt32.init(exactly:)),
                  let description = row["outputDescription"]?.stringValue,
                  let basket = row["basket"]?.stringValue else {
                throw StorageClientError.unreadableResponse(method: "listActions")
            }
            do {
                return try WalletActionOutput(
                    satoshis: satoshis,
                    lockingScript: try optionalHex(row["lockingScript"]),
                    spendable: spendable,
                    customInstructions: try optionalText(row["customInstructions"]),
                    tags: tags,
                    outputIndex: outputIndex,
                    outputDescription: description,
                    basket: basket
                )
            } catch let error as StorageClientError {
                throw error
            } catch {
                throw StorageClientError.unreadableResponse(method: "listActions")
            }
        }
    }

    private static func optionalRows(_ value: JSONValue?) throws -> [JSONValue]? {
        guard let value, value != .null else { return nil }
        guard let rows = value.arrayValue else {
            throw StorageClientError.unreadableResponse(method: "listActions")
        }
        return rows
    }

    private static func requiredStrings(_ value: JSONValue?) throws -> [String]? {
        guard let value, let rows = value.arrayValue else { return nil }
        var strings: [String] = []
        strings.reserveCapacity(rows.count)
        for row in rows {
            guard let string = row.stringValue else { return nil }
            strings.append(string)
        }
        return strings
    }

    private static func unsigned(_ value: JSONValue?) -> UInt64? {
        guard let integer = value?.intValue, integer >= 0 else { return nil }
        return UInt64(integer)
    }

    private static func optionalText(_ value: JSONValue?) throws -> String? {
        guard let value, value != .null else { return nil }
        guard let text = value.stringValue else {
            throw StorageClientError.unreadableResponse(method: "listActions")
        }
        return text
    }

    private static func optionalHex(_ value: JSONValue?) throws -> [UInt8]? {
        guard let text = try optionalText(value) else { return nil }
        guard let bytes = hexBytes(text) else {
            throw StorageClientError.unreadableResponse(method: "listActions")
        }
        return bytes
    }

    /// Abandons an unsigned action, releasing the inputs it reserved. Without this a cancelled
    /// payment leaves its coins locked until the store times them out.
    public func abortAction(
        _ auth: AuthID, _ request: WalletAbortActionRequest
    ) async throws -> WalletAbortActionResult {
        let result = try await call(
            "abortAction",
            [.object(auth.jsonObject), .object(["reference": .string(request.reference.base64)])]
        )
        guard let aborted = result["aborted"]?.boolValue else {
            throw StorageClientError.unreadableResponse(method: "abortAction")
        }
        return WalletAbortActionResult(aborted: aborted)
    }

    /// Gives up tracking an output — it stays on chain, the wallet just stops counting it.
    public func relinquishOutput(
        _ auth: AuthID, _ request: WalletRelinquishOutputRequest
    ) async throws -> WalletRelinquishOutputResult {
        let result = try await call("relinquishOutput", [
            .object(auth.jsonObject),
            .object([
                "basket": .string(request.basket),
                "output": .string(request.output.description),
            ]),
        ])
        // The storage contract returns its update count, while BRC-100 returns a boolean. The live
        // TypeScript wallet considers any successful storage call relinquished; the count is not
        // part of the public result. Still require the actual storage shape so a null or truncated
        // response cannot silently become success.
        guard let updated = result.intValue, updated >= 0 else {
            throw StorageClientError.unreadableResponse(method: "relinquishOutput")
        }
        return WalletRelinquishOutputResult(relinquished: true)
    }
}
