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
        if request.includeLabels == true { arguments["includeLabels"] = .bool(true) }
        if request.includeInputs == true { arguments["includeInputs"] = .bool(true) }
        if request.includeOutputs == true { arguments["includeOutputs"] = .bool(true) }

        let result = try await call("listActions", [.object(auth.jsonObject), .object(arguments)])
        return try Self.decodeActions(result)
    }

    static func decodeActions(_ result: JSONValue) throws -> WalletListActionsResult {
        guard let total = result["totalActions"]?.intValue,
              let rows = result["actions"]?.arrayValue else {
            throw StorageClientError.unreadableResponse(method: "listActions")
        }
        let actions = try rows.map { row -> WalletAction in
            guard let txidText = row["txid"]?.stringValue,
                  let satoshis = row["satoshis"]?.intValue,
                  let statusText = row["status"]?.stringValue,
                  let status = WalletActionStatus(rawValue: statusText),
                  let isOutgoing = row["isOutgoing"]?.boolValue else {
                throw StorageClientError.unreadableResponse(method: "listActions")
            }
            return try WalletAction(
                transactionID: try TransactionID(displayHex: txidText),
                satoshis: Int64(satoshis),
                status: status,
                isOutgoing: isOutgoing,
                description: row["description"]?.stringValue ?? "",
                labels: try stringArray(row["labels"], method: "listActions"),
                version: try narrow(row["version"]?.intValue ?? 1),
                lockTime: try narrow(row["lockTime"]?.intValue ?? 0),
                inputs: nil,
                outputs: nil
            )
        }
        return try WalletListActionsResult(
            totalActions: try narrow(total), actions: actions
        )
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
        return WalletAbortActionResult(aborted: result["aborted"]?.boolValue ?? true)
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
        return WalletRelinquishOutputResult(relinquished: result["relinquished"]?.boolValue ?? true)
    }
}
