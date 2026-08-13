import Foundation
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// Reading what the wallet owns.
///
/// This is the first call that returns records rather than facts about the store, and it is what
/// a balance is made of. Everything the action layer does starts from knowing which outputs exist
/// and which of them can still be spent.
extension StorageClient {

    /// The outputs in a basket.
    ///
    /// `basket` is required by the protocol rather than defaulted: an unqualified "all outputs"
    /// would mix ordinary coins with ordinals, and paying somebody with an ordinal by accident is
    /// exactly the mistake baskets exist to prevent.
    public func listOutputs(
        _ auth: AuthID, _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult {
        // `tags` is always sent, even empty. The server reads its length without checking it
        // exists, so omitting it is a crash there rather than a default here.
        var arguments: [String: JSONValue] = [
            "basket": .string(request.basket),
            "tags": .array(request.tags.map { .string($0) }),
        ]
        if let limit = request.pagination.limit {
            arguments["limit"] = .number(Double(limit))
        }
        if let offset = request.pagination.offset {
            arguments["offset"] = .number(Double(offset))
        }
        if request.includeTags == true { arguments["includeTags"] = .bool(true) }
        if request.includeLabels == true { arguments["includeLabels"] = .bool(true) }
        if request.includeCustomInstructions == true {
            arguments["includeCustomInstructions"] = .bool(true)
        }
        if let include = request.include {
            arguments["include"] = .string(include.rawValue)
        }
        if let tagQueryMode = request.tagQueryMode {
            arguments["tagQueryMode"] = .string(tagQueryMode.rawValue)
        }

        let result = try await call("listOutputs", [.object(auth.jsonObject), .object(arguments)])
        return try Self.decodeOutputs(result)
    }

    /// Turns the store's answer into wallet records.
    ///
    /// A field this cannot read is a refusal, not a zero. An output whose outpoint or amount was
    /// unreadable would otherwise become a spendable coin the wallet has invented.
    static func decodeOutputs(_ result: JSONValue) throws -> WalletListOutputsResult {
        guard let total = result["totalOutputs"]?.intValue,
              let rows = result["outputs"]?.arrayValue else {
            throw StorageClientError.unreadableResponse(method: "listOutputs")
        }

        let outputs = try rows.map { row -> WalletOutput in
            guard let outpointText = row["outpoint"]?.stringValue,
                  let satoshis = row["satoshis"]?.intValue, satoshis >= 0,
                  let spendable = row["spendable"]?.boolValue else {
                throw StorageClientError.unreadableResponse(method: "listOutputs")
            }
            return try WalletOutput(
                satoshis: UInt64(satoshis),
                lockingScript: row["lockingScript"]?.stringValue.flatMap(Self.hexBytes),
                spendable: spendable,
                customInstructions: row["customInstructions"]?.stringValue,
                tags: try Self.stringArray(row["tags"], method: "listOutputs"),
                outpoint: try Outpoint(outpointText),
                labels: try Self.stringArray(row["labels"], method: "listOutputs")
            )
        }

        let beefBytes = try byteArray(result["BEEF"] ?? result["beef"])
        let beef = try beefBytes.map { try BEEF(bytes: $0, limits: StorageLimits.beef) }
        return try WalletListOutputsResult(
            totalOutputs: UInt32(max(0, total)),
            beef: beef,
            outputs: outputs
        )
    }

    /// A JSON array of strings, or nil when absent. A non-string element is a refusal, not a value
    /// to drop: `compactMap` would turn `["a", 7]` into `["a"]` and quietly change what a tag
    /// filter or a label matches.
    static func stringArray(_ value: JSONValue?, method: String) throws -> [String]? {
        guard let value, value != .null else { return nil }
        guard let elements = value.arrayValue else {
            throw StorageClientError.unreadableResponse(method: method)
        }
        return try elements.map { element in
            guard let string = element.stringValue else {
                throw StorageClientError.unreadableResponse(method: method)
            }
            return string
        }
    }

    static func hexBytes(_ text: String) -> [UInt8]? {
        guard text.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
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
