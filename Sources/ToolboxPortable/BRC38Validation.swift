import Foundation
import ToolboxCore

enum BRC38Validator {
    private static let requiredFields: [String: Set<String>] = [
        "settings": [
            "created_at", "updated_at", "storageIdentityKey", "storageName", "chain", "dbtype",
            "maxOutputScript",
        ],
        "user": ["created_at", "updated_at", "userId", "identityKey", "activeStorage"],
        "provenTx": [
            "created_at", "updated_at", "provenTxId", "txid", "height", "index", "merklePath",
            "rawTx", "blockHash", "merkleRoot",
        ],
        "provenTxReq": [
            "created_at", "updated_at", "provenTxReqId", "status", "attempts", "notified", "txid",
            "history", "notify", "rawTx",
        ],
        "outputBasket": [
            "created_at", "updated_at", "basketId", "userId", "name", "numberOfDesiredUTXOs",
            "minimumDesiredUTXOValue", "isDeleted",
        ],
        "transaction": [
            "created_at", "updated_at", "transactionId", "userId", "status", "reference",
            "isOutgoing", "satoshis", "description",
        ],
        "commission": [
            "created_at", "updated_at", "commissionId", "userId", "transactionId", "satoshis",
            "keyOffset", "isRedeemed", "lockingScript",
        ],
        "output": [
            "created_at", "updated_at", "outputId", "userId", "transactionId", "spendable", "change",
            "outputDescription", "vout", "satoshis", "providedBy", "purpose", "type",
        ],
        "outputTag": ["created_at", "updated_at", "outputTagId", "userId", "tag", "isDeleted"],
        "outputTagMap": ["created_at", "updated_at", "outputTagId", "outputId", "isDeleted"],
        "txLabel": ["created_at", "updated_at", "txLabelId", "userId", "label", "isDeleted"],
        "txLabelMap": ["created_at", "updated_at", "txLabelId", "transactionId", "isDeleted"],
        "certificate": [
            "created_at", "updated_at", "certificateId", "userId", "type", "serialNumber", "certifier",
            "subject", "revocationOutpoint", "signature", "isDeleted",
        ],
        "certificateField": [
            "created_at", "updated_at", "userId", "certificateId", "fieldName", "fieldValue", "masterKey",
        ],
        "syncState": [
            "created_at", "updated_at", "syncStateId", "userId", "storageIdentityKey", "storageName",
            "status", "init", "refNum", "syncMap",
        ],
    ]

    private static let base64Fields: [String: Set<String>] = [
        "commission": ["lockingScript"],
        "output": ["lockingScript", "derivationPrefix", "derivationSuffix"],
        "provenTx": ["merklePath", "rawTx"],
        "provenTxReq": ["rawTx", "inputBEEF"],
        "transaction": ["reference", "inputBEEF", "rawTx"],
        "certificate": ["type", "serialNumber"],
        "certificateField": ["masterKey"],
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

    private static let integerFields: [String: Set<String>] = [
        "settings": ["maxOutputScript"],
        "user": ["userId"],
        "provenTx": ["provenTxId", "height", "index"],
        "provenTxReq": ["provenTxReqId", "provenTxId", "attempts", "rebroadcastAttempts"],
        "outputBasket": ["basketId", "userId", "numberOfDesiredUTXOs", "minimumDesiredUTXOValue"],
        "transaction": ["transactionId", "userId", "provenTxId", "satoshis", "version", "lockTime"],
        "commission": ["commissionId", "userId", "transactionId", "satoshis"],
        "output": [
            "outputId", "userId", "transactionId", "basketId", "vout", "satoshis", "spentBy",
            "sequenceNumber", "scriptLength", "scriptOffset",
        ],
        "outputTag": ["outputTagId", "userId"],
        "outputTagMap": ["outputTagId", "outputId"],
        "txLabel": ["txLabelId", "userId"],
        "txLabelMap": ["txLabelId", "transactionId"],
        "certificate": ["certificateId", "userId"],
        "certificateField": ["userId", "certificateId"],
        "syncState": ["syncStateId", "userId", "satoshis"],
    ]

    private static let stringFields: [String: Set<String>] = [
        "settings": ["storageIdentityKey", "storageName", "chain", "dbtype"],
        "user": ["identityKey", "activeStorage"],
        "provenTx": ["txid", "blockHash", "merkleRoot"],
        "provenTxReq": ["status", "txid", "batch"],
        "outputBasket": ["name"],
        "transaction": ["status", "reference", "description", "txid"],
        "commission": ["keyOffset"],
        "output": [
            "outputDescription", "providedBy", "purpose", "type", "txid", "senderIdentityKey",
            "derivationPrefix", "derivationSuffix", "customInstructions", "spendingDescription",
        ],
        "outputTag": ["tag"],
        "txLabel": ["label"],
        "certificate": [
            "type", "serialNumber", "certifier", "subject", "verifier", "revocationOutpoint", "signature",
        ],
        "certificateField": ["fieldName", "fieldValue", "masterKey"],
        "syncState": ["storageIdentityKey", "storageName", "status", "refNum"],
    ]

    private static let booleanFields: [String: Set<String>] = [
        "provenTxReq": ["notified", "wasBroadcast"],
        "outputBasket": ["isDeleted"],
        "transaction": ["isOutgoing"],
        "commission": ["isRedeemed"],
        "output": ["spendable", "change"],
        "outputTag": ["isDeleted"],
        "outputTagMap": ["isDeleted"],
        "txLabel": ["isDeleted"],
        "txLabelMap": ["isDeleted"],
        "certificate": ["isDeleted"],
        "syncState": ["init"],
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
            for field in (requiredFields[kind] ?? []).sorted() where row[field] == nil {
                throw BRC38Error.missingField("\(rowPath).\(field)")
            }
            for field in dateFields[kind] ?? [] where row[field] != nil {
                try timestamp(row[field], path: "\(rowPath).\(field)")
            }
            for field in base64Fields[kind] ?? [] where row[field] != nil {
                try base64(row[field], path: "\(rowPath).\(field)")
            }
            for field in integerFields[kind] ?? [] where row[field] != nil {
                _ = try integer(row[field], path: "\(rowPath).\(field)")
            }
            for field in stringFields[kind] ?? [] where row[field] != nil {
                _ = try string(row[field], path: "\(rowPath).\(field)")
            }
            for field in booleanFields[kind] ?? [] where row[field] != nil {
                guard row[field]?.boolValue != nil else {
                    throw BRC38Error.invalidBoolean("\(rowPath).\(field)")
                }
            }
            for field in jsonFields[kind] ?? []
                where row[field] != nil && row[field]?.objectValue == nil
            {
                throw BRC38Error.invalidJSONField("\(rowPath).\(field)")
            }
            if kind == "provenTxReq" { try validateProvenTxReqObjects(row, path: rowPath) }
            if kind == "syncState" { try validateSyncStateObjects(row, path: rowPath) }
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

    private static func validateProvenTxReqObjects(
        _ row: BRC38PortableRow,
        path: String
    ) throws {
        let history = try object(row["history"], path: "\(path).history")
        if let notes = history["notes"] {
            guard let values = notes.arrayValue else {
                throw BRC38Error.invalidJSONField("\(path).history.notes")
            }
            for (index, value) in values.enumerated() {
                let notePath = "\(path).history.notes[\(index)]"
                let note = try object(value, path: notePath)
                _ = try string(note["what"], path: "\(notePath).what")
                if note["when"] != nil { try timestamp(note["when"], path: "\(notePath).when") }
            }
        }

        let notify = try object(row["notify"], path: "\(path).notify")
        if let transactionIDs = notify["transactionIds"] {
            guard let values = transactionIDs.arrayValue else {
                throw BRC38Error.invalidJSONField("\(path).notify.transactionIds")
            }
            for (index, value) in values.enumerated() {
                _ = try integer(value, path: "\(path).notify.transactionIds[\(index)]")
            }
        }
    }

    private static let syncEntities = [
        "provenTx", "outputBasket", "transaction", "provenTxReq", "txLabel", "txLabelMap",
        "output", "outputTag", "outputTagMap", "certificate", "certificateField", "commission",
    ]

    private static func validateSyncStateObjects(
        _ row: BRC38PortableRow,
        path: String
    ) throws {
        let syncMap = try object(row["syncMap"], path: "\(path).syncMap")
        for name in syncEntities {
            let entityPath = "\(path).syncMap.\(name)"
            let entity = try object(syncMap[name], path: entityPath)
            guard try string(entity["entityName"], path: "\(entityPath).entityName") == name else {
                throw BRC38Error.invalidJSONField("\(entityPath).entityName")
            }
            _ = try integer(entity["count"], path: "\(entityPath).count")
            let idMap = try object(entity["idMap"], path: "\(entityPath).idMap")
            for (foreignID, localID) in idMap {
                guard Int(foreignID) != nil else {
                    throw BRC38Error.invalidInteger("\(entityPath).idMap.\(foreignID)")
                }
                _ = try integer(localID, path: "\(entityPath).idMap.\(foreignID)")
            }
            if entity["maxUpdated_at"] != nil {
                try timestamp(entity["maxUpdated_at"], path: "\(entityPath).maxUpdated_at")
            }
        }
        if row["errorLocal"] != nil {
            try validateSyncError(row["errorLocal"], path: "\(path).errorLocal")
        }
        if row["errorOther"] != nil {
            try validateSyncError(row["errorOther"], path: "\(path).errorOther")
        }
    }

    private static func validateSyncError(_ value: JSONValue?, path: String) throws {
        let error = try object(value, path: path)
        _ = try string(error["code"], path: "\(path).code")
        _ = try string(error["description"], path: "\(path).description")
        if error["stack"] != nil { _ = try string(error["stack"], path: "\(path).stack") }
    }

    private static func object(_ value: JSONValue?, path: String) throws -> [String: JSONValue] {
        guard let object = value?.objectValue else { throw BRC38Error.invalidJSONField(path) }
        return object
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
        try validateUniqueness(data.tables)
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

    private static func validateUniqueness(_ tables: BRC38Tables) throws {
        _ = try ids(tables.provenTxs, "provenTxId", "provenTxs")
        _ = try ids(tables.provenTxReqs, "provenTxReqId", "provenTxReqs")
        _ = try ids(tables.outputBaskets, "basketId", "outputBaskets")
        _ = try ids(tables.transactions, "transactionId", "transactions")
        _ = try ids(tables.commissions, "commissionId", "commissions")
        _ = try ids(tables.outputs, "outputId", "outputs")
        _ = try ids(tables.outputTags, "outputTagId", "outputTags")
        _ = try ids(tables.txLabels, "txLabelId", "txLabels")
        _ = try ids(tables.certificates, "certificateId", "certificates")
        _ = try ids(tables.syncStates, "syncStateId", "syncStates")

        try unique(tables.provenTxs, by: [.string("txid")], label: "provenTxs.txid")
        try unique(tables.provenTxReqs, by: [.string("txid")], label: "provenTxReqs.txid")
        try unique(
            tables.outputBaskets,
            by: [.string("name"), .integer("userId")],
            label: "outputBaskets.name+userId"
        )
        try unique(tables.transactions, by: [.string("reference")], label: "transactions.reference")
        try unique(
            tables.commissions,
            by: [.integer("transactionId")],
            label: "commissions.transactionId"
        )
        try unique(
            tables.outputs,
            by: [.integer("transactionId"), .integer("vout"), .integer("userId")],
            label: "outputs.transactionId+vout+userId"
        )
        try unique(
            tables.outputTags,
            by: [.string("tag"), .integer("userId")],
            label: "outputTags.tag+userId"
        )
        try unique(
            tables.outputTagMaps,
            by: [.integer("outputId"), .integer("outputTagId")],
            label: "outputTagMaps.outputId+outputTagId"
        )
        try unique(
            tables.txLabels,
            by: [.string("label"), .integer("userId")],
            label: "txLabels.label+userId"
        )
        try unique(
            tables.txLabelMaps,
            by: [.integer("transactionId"), .integer("txLabelId")],
            label: "txLabelMaps.transactionId+txLabelId"
        )
        try unique(
            tables.certificates,
            by: [
                .integer("userId"), .string("type"), .string("certifier"),
                .string("serialNumber"),
            ],
            label: "certificates.userId+type+certifier+serialNumber"
        )
        try unique(
            tables.certificateFields,
            by: [.integer("certificateId"), .string("fieldName")],
            label: "certificateFields.certificateId+fieldName"
        )
        try unique(tables.syncStates, by: [.string("refNum")], label: "syncStates.refNum")
    }

    private enum UniqueField {
        case integer(String)
        case string(String)
    }

    private enum UniquePart: Hashable {
        case integer(Int)
        case string([UInt16])
    }

    private static func unique(
        _ rows: [BRC38PortableRow],
        by fields: [UniqueField],
        label: String
    ) throws {
        var values = Set<[UniquePart]>()
        for row in rows {
            let key = try fields.map { field -> UniquePart in
                switch field {
                case .integer(let name):
                    return .integer(try integer(row[name], path: label))
                case .string(let name):
                    return .string(Array(try string(row[name], path: label).utf16))
                }
            }
            guard values.insert(key).inserted else { throw BRC38Error.duplicateID(label) }
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
        guard let integer = value?.intValue,
              integer >= -9_007_199_254_740_991,
              integer <= 9_007_199_254_740_991
        else { throw BRC38Error.invalidInteger(path) }
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
                return try JCS.utf16Less(
                    BRC38Validator.string(left["fieldName"], path: "fieldName"),
                    BRC38Validator.string(right["fieldName"], path: "fieldName")
                )
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
