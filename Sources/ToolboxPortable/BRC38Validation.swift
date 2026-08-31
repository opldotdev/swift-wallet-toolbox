import Foundation
import ToolboxCore

enum BRC38Validator {
    private static let binaryFields: [String: Set<String>] = [
        "commission": ["lockingScript"],
        "output": ["lockingScript"],
        "provenTx": ["merklePath", "rawTx"],
        "provenTxReq": ["rawTx", "inputBEEF"],
        "transaction": ["inputBEEF", "rawTx"],
    ]

    private static let jsonFields: [String: Set<String>] = [
        "provenTxReq": ["history", "notify"],
        "syncState": ["syncMap", "errorLocal", "errorOther"],
    ]

    private static let dateFields: [String: Set<String>] = [
        "settings": ["created_at", "updated_at"],
        "user": ["created_at", "updated_at"],
        "provenTx": ["created_at", "updated_at"],
        "provenTxReq": ["created_at", "updated_at"],
        "outputBasket": ["created_at", "updated_at"],
        "transaction": ["created_at", "updated_at"],
        "commission": ["created_at", "updated_at"],
        "output": ["created_at", "updated_at"],
        "outputTag": ["created_at", "updated_at"],
        "outputTagMap": ["created_at", "updated_at"],
        "txLabel": ["created_at", "updated_at"],
        "txLabelMap": ["created_at", "updated_at"],
        "certificate": ["created_at", "updated_at"],
        "certificateField": ["created_at", "updated_at"],
        "syncState": ["created_at", "updated_at", "when"],
    ]

    static func validate(_ data: BRC38WalletData, limits: BRC38Limits) throws {
        guard limits.maximumUTF8ByteCount > 0, limits.maximumRowCount >= 0 else {
            throw BRC38Error.canonicalization
        }
        guard data.tables.rowCount <= limits.maximumRowCount else {
            throw BRC38Error.tooManyRows(maximum: limits.maximumRowCount)
        }
        try rejectNulls(.object(data.sourceStorage), path: "sourceStorage")
        try rejectNulls(.object(data.user), path: "user")
        for (name, kind, rows) in rowGroups(data.tables) {
            try rejectNulls(.array(rows.map(JSONValue.object)), path: "tables.\(name)")
            try validateRows(kind, rows, path: name)
        }
        try timestamp(.string(data.exportedAt), path: "exportedAt")
        try validateRows("settings", [data.sourceStorage], path: "sourceStorage")
        try validateRows("user", [data.user], path: "user")
        try relationships(data)
    }

    private static func rowGroups(
        _ tables: BRC38Tables
    ) -> [(String, String, [BRC38PortableRow])] {
        [
            ("provenTxs", "provenTx", tables.provenTxs),
            ("provenTxReqs", "provenTxReq", tables.provenTxReqs),
            ("outputBaskets", "outputBasket", tables.outputBaskets),
            ("transactions", "transaction", tables.transactions),
            ("commissions", "commission", tables.commissions),
            ("outputs", "output", tables.outputs),
            ("outputTags", "outputTag", tables.outputTags),
            ("outputTagMaps", "outputTagMap", tables.outputTagMaps),
            ("txLabels", "txLabel", tables.txLabels),
            ("txLabelMaps", "txLabelMap", tables.txLabelMaps),
            ("certificates", "certificate", tables.certificates),
            ("certificateFields", "certificateField", tables.certificateFields),
            ("syncStates", "syncState", tables.syncStates),
        ]
    }

    static func rejectNulls(_ value: JSONValue, path: String) throws {
        switch value {
        case .null:
            throw BRC38Error.nullValue(path)
        case .array(let values):
            for (index, child) in values.enumerated() {
                try rejectNulls(child, path: "\(path)[\(index)]")
            }
        case .object(let object):
            for (key, child) in object {
                try rejectNulls(child, path: "\(path).\(key)")
            }
        default:
            break
        }
    }

    static func row(_ value: JSONValue?, path: String) throws -> BRC38PortableRow {
        guard let object = value?.objectValue else { throw BRC38Error.expectedObject(path) }
        return object
    }

    static func rows(_ tables: [String: JSONValue], _ name: String) throws -> [BRC38PortableRow] {
        guard let values = tables[name]?.arrayValue else {
            throw BRC38Error.expectedArray("tables.\(name)")
        }
        return try values.enumerated().map { index, value in
            try row(value, path: "tables.\(name)[\(index)]")
        }
    }

    private static func validateRows(
        _ kind: String,
        _ rows: [BRC38PortableRow],
        path: String
    ) throws {
        for (index, row) in rows.enumerated() {
            let rowPath = "\(path)[\(index)]"
            for field in dateFields[kind] ?? [] where row[field] != nil {
                try timestamp(row[field], path: "\(rowPath).\(field)")
            }
            for field in binaryFields[kind] ?? [] where row[field] != nil {
                try base64(row[field], path: "\(rowPath).\(field)")
            }
            for field in jsonFields[kind] ?? []
                where row[field] != nil && row[field]?.objectValue == nil
            {
                throw BRC38Error.invalidJSONField("\(rowPath).\(field)")
            }
        }
    }

    private static func timestamp(_ value: JSONValue?, path: String) throws {
        guard let string = value?.stringValue,
              string.utf8.count == 24,
              string.utf8.enumerated().allSatisfy({ offset, byte in
                  switch offset {
                  case 4, 7: byte == 45
                  case 10: byte == 84
                  case 13, 16: byte == 58
                  case 19: byte == 46
                  case 23: byte == 90
                  default: byte >= 48 && byte <= 57
                  }
              })
        else { throw BRC38Error.invalidTimestamp(path) }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: string), formatter.string(from: date) == string else {
            throw BRC38Error.invalidTimestamp(path)
        }
    }

    private static func base64(_ value: JSONValue?, path: String) throws {
        guard let string = value?.stringValue,
              string.utf8.count.isMultiple(of: 4),
              let decoded = Data(base64Encoded: string),
              decoded.base64EncodedString() == string
        else { throw BRC38Error.invalidBase64(path) }
    }

    private struct Index {
        let userID: Int
        let transactionIDs: Set<Int>
        let transactionTXIDs: Set<String>
        let provenTxIDs: Set<Int>
        let basketIDs: Set<Int>
        let outputIDs: Set<Int>
        let outputTagIDs: Set<Int>
        let txLabelIDs: Set<Int>
        let certificateIDs: Set<Int>
    }

    private static func relationships(_ data: BRC38WalletData) throws {
        let index = try Index(
            userID: integer(data.user["userId"], path: "user.userId"),
            transactionIDs: ids(data.tables.transactions, "transactionId", "transactions"),
            transactionTXIDs: Set(data.tables.transactions.compactMap { $0["txid"]?.stringValue }),
            provenTxIDs: ids(data.tables.provenTxs, "provenTxId", "provenTxs"),
            basketIDs: ids(data.tables.outputBaskets, "basketId", "outputBaskets"),
            outputIDs: ids(data.tables.outputs, "outputId", "outputs"),
            outputTagIDs: ids(data.tables.outputTags, "outputTagId", "outputTags"),
            txLabelIDs: ids(data.tables.txLabels, "txLabelId", "txLabels"),
            certificateIDs: ids(data.tables.certificates, "certificateId", "certificates")
        )

        for row in data.tables.transactions {
            try user(row, index.userID, "transactions.userId")
            try optionalReference(row["provenTxId"], in: index.provenTxIDs, "transaction.provenTxId")
        }
        for row in data.tables.outputBaskets { try user(row, index.userID, "outputBaskets.userId") }
        for row in data.tables.outputTags { try user(row, index.userID, "outputTags.userId") }
        for row in data.tables.txLabels { try user(row, index.userID, "txLabels.userId") }
        for row in data.tables.certificates { try user(row, index.userID, "certificates.userId") }
        for row in data.tables.syncStates { try user(row, index.userID, "syncStates.userId") }

        for row in data.tables.outputs {
            try user(row, index.userID, "outputs.userId")
            try reference(row["transactionId"], in: index.transactionIDs, "output.transactionId")
            try optionalReference(row["basketId"], in: index.basketIDs, "output.basketId")
            try optionalReference(row["spentBy"], in: index.transactionIDs, "output.spentBy")
        }
        for row in data.tables.commissions {
            try user(row, index.userID, "commissions.userId")
            try reference(row["transactionId"], in: index.transactionIDs, "commission.transactionId")
        }
        for row in data.tables.txLabelMaps {
            try reference(row["transactionId"], in: index.transactionIDs, "txLabelMap.transactionId")
            try reference(row["txLabelId"], in: index.txLabelIDs, "txLabelMap.txLabelId")
        }
        for row in data.tables.outputTagMaps {
            try reference(row["outputId"], in: index.outputIDs, "outputTagMap.outputId")
            try reference(row["outputTagId"], in: index.outputTagIDs, "outputTagMap.outputTagId")
        }
        for row in data.tables.certificateFields {
            try user(row, index.userID, "certificateFields.userId")
            try reference(
                row["certificateId"], in: index.certificateIDs,
                "certificateField.certificateId"
            )
        }
        for row in data.tables.provenTxReqs {
            let txid = try string(row["txid"], path: "provenTxReq.txid")
            guard index.transactionTXIDs.contains(txid) else {
                throw BRC38Error.relationship("provenTxReq.txid")
            }
            try optionalReference(row["provenTxId"], in: index.provenTxIDs, "provenTxReq.provenTxId")
        }
    }

    private static func ids(
        _ rows: [BRC38PortableRow],
        _ field: String,
        _ label: String
    ) throws -> Set<Int> {
        var result = Set<Int>()
        for row in rows {
            let id = try integer(row[field], path: "\(label).\(field)")
            guard result.insert(id).inserted else {
                throw BRC38Error.duplicateID("\(label).\(field)")
            }
        }
        return result
    }

    private static func user(_ row: BRC38PortableRow, _ userID: Int, _ path: String) throws {
        guard try integer(row["userId"], path: path) == userID else {
            throw BRC38Error.relationship(path)
        }
    }

    private static func reference(_ value: JSONValue?, in ids: Set<Int>, _ path: String) throws {
        guard ids.contains(try integer(value, path: path)) else {
            throw BRC38Error.relationship(path)
        }
    }

    private static func optionalReference(
        _ value: JSONValue?,
        in ids: Set<Int>,
        _ path: String
    ) throws {
        if value != nil { try reference(value, in: ids, path) }
    }

    static func integer(_ value: JSONValue?, path: String) throws -> Int {
        guard let integer = value?.intValue else { throw BRC38Error.invalidInteger(path) }
        return integer
    }

    static func string(_ value: JSONValue?, path: String) throws -> String {
        guard let string = value?.stringValue else { throw BRC38Error.invalidString(path) }
        return string
    }
}

extension BRC38Tables {
    func canonicalObject() throws -> [String: JSONValue] {
        [
            "provenTxs": .array(try sorted(provenTxs, by: ["provenTxId"])),
            "provenTxReqs": .array(try sorted(provenTxReqs, by: ["provenTxReqId"])),
            "outputBaskets": .array(try sorted(outputBaskets, by: ["basketId"])),
            "transactions": .array(try sorted(transactions, by: ["transactionId"])),
            "commissions": .array(try sorted(commissions, by: ["commissionId"])),
            "outputs": .array(try sorted(outputs, by: ["outputId"])),
            "outputTags": .array(try sorted(outputTags, by: ["outputTagId"])),
            "outputTagMaps": .array(try sorted(outputTagMaps, by: ["outputId", "outputTagId"])),
            "txLabels": .array(try sorted(txLabels, by: ["txLabelId"])),
            "txLabelMaps": .array(try sorted(txLabelMaps, by: ["transactionId", "txLabelId"])),
            "certificates": .array(try sorted(certificates, by: ["certificateId"])),
            "certificateFields": .array(try certificateFields.sorted { left, right in
                let leftID = try BRC38Validator.integer(left["certificateId"], path: "certificateId")
                let rightID = try BRC38Validator.integer(right["certificateId"], path: "certificateId")
                if leftID != rightID { return leftID < rightID }
                return try BRC38Validator.string(left["fieldName"], path: "fieldName")
                    < BRC38Validator.string(right["fieldName"], path: "fieldName")
            }.map(JSONValue.object)),
            "syncStates": .array(try sorted(syncStates, by: ["syncStateId"])),
        ]
    }

    private func sorted(
        _ rows: [BRC38PortableRow],
        by fields: [String]
    ) throws -> [JSONValue] {
        try rows.sorted { left, right in
            for field in fields {
                let lhs = try BRC38Validator.integer(left[field], path: field)
                let rhs = try BRC38Validator.integer(right[field], path: field)
                if lhs != rhs { return lhs < rhs }
            }
            return false
        }.map(JSONValue.object)
    }
}
