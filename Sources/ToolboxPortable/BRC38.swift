import Foundation
import ToolboxCore

public typealias BRC38PortableRow = [String: JSONValue]

/// Resource bounds applied before and during BRC-38 parsing.
public struct BRC38Limits: Equatable, Sendable {
    public let maximumUTF8ByteCount: Int
    public let maximumRowCount: Int

    public init(maximumUTF8ByteCount: Int, maximumRowCount: Int) {
        self.maximumUTF8ByteCount = maximumUTF8ByteCount
        self.maximumRowCount = maximumRowCount
    }

    public static let standard = BRC38Limits(
        maximumUTF8ByteCount: 64 << 20,
        maximumRowCount: 1_000_000
    )
}

public struct BRC38Tables: Equatable, Sendable {
    public let provenTxs: [BRC38PortableRow]
    public let provenTxReqs: [BRC38PortableRow]
    public let outputBaskets: [BRC38PortableRow]
    public let transactions: [BRC38PortableRow]
    public let commissions: [BRC38PortableRow]
    public let outputs: [BRC38PortableRow]
    public let outputTags: [BRC38PortableRow]
    public let outputTagMaps: [BRC38PortableRow]
    public let txLabels: [BRC38PortableRow]
    public let txLabelMaps: [BRC38PortableRow]
    public let certificates: [BRC38PortableRow]
    public let certificateFields: [BRC38PortableRow]
    public let syncStates: [BRC38PortableRow]

    public init(
        provenTxs: [BRC38PortableRow],
        provenTxReqs: [BRC38PortableRow],
        outputBaskets: [BRC38PortableRow],
        transactions: [BRC38PortableRow],
        commissions: [BRC38PortableRow],
        outputs: [BRC38PortableRow],
        outputTags: [BRC38PortableRow],
        outputTagMaps: [BRC38PortableRow],
        txLabels: [BRC38PortableRow],
        txLabelMaps: [BRC38PortableRow],
        certificates: [BRC38PortableRow],
        certificateFields: [BRC38PortableRow],
        syncStates: [BRC38PortableRow]
    ) {
        self.provenTxs = provenTxs
        self.provenTxReqs = provenTxReqs
        self.outputBaskets = outputBaskets
        self.transactions = transactions
        self.commissions = commissions
        self.outputs = outputs
        self.outputTags = outputTags
        self.outputTagMaps = outputTagMaps
        self.txLabels = txLabels
        self.txLabelMaps = txLabelMaps
        self.certificates = certificates
        self.certificateFields = certificateFields
        self.syncStates = syncStates
    }

    public static let empty = BRC38Tables(
        provenTxs: [], provenTxReqs: [], outputBaskets: [], transactions: [], commissions: [],
        outputs: [], outputTags: [], outputTagMaps: [], txLabels: [], txLabelMaps: [],
        certificates: [], certificateFields: [], syncStates: []
    )

    var rowCount: Int {
        provenTxs.count + provenTxReqs.count + outputBaskets.count + transactions.count
            + commissions.count + outputs.count + outputTags.count + outputTagMaps.count
            + txLabels.count + txLabelMaps.count + certificates.count + certificateFields.count
            + syncStates.count
    }
}

/// A validated BRC-38 plaintext wallet-data document.
///
/// BRC-38 contains Wallet Toolbox storage records. It does not contain root keys, mnemonics, or
/// wallet-runtime custody snapshots.
public struct BRC38WalletData: Equatable, Sendable {
    public static let title = "User Wallet Data Format"

    public let exportedAt: String
    public let sourceStorage: BRC38PortableRow
    public let user: BRC38PortableRow
    public let tables: BRC38Tables

    public init(
        exportedAt: String,
        sourceStorage: BRC38PortableRow,
        user: BRC38PortableRow,
        tables: BRC38Tables,
        limits: BRC38Limits = .standard
    ) throws {
        self.exportedAt = exportedAt
        self.sourceStorage = sourceStorage
        self.user = user
        self.tables = tables
        try BRC38Validator.validate(self, limits: limits)
    }

    /// Parses and validates an untrusted BRC-38 JSON document.
    public static func parse(
        _ json: String,
        limits: BRC38Limits = .standard
    ) throws -> BRC38WalletData {
        let bytes = Array(json.utf8)
        guard bytes.count <= limits.maximumUTF8ByteCount else {
            throw BRC38Error.documentTooLarge(maximumByteCount: limits.maximumUTF8ByteCount)
        }

        let root: JSONValue
        do {
            root = try JSONDecoder().decode(JSONValue.self, from: Data(bytes))
        } catch {
            throw BRC38Error.invalidJSON
        }
        try BRC38Validator.rejectNulls(root, path: "document")
        guard let object = root.objectValue else { throw BRC38Error.expectedObject("document") }
        guard object["brc"]?.intValue == 38 else { throw BRC38Error.invalidConstant("brc") }
        guard object["title"]?.stringValue == title else {
            throw BRC38Error.invalidConstant("title")
        }
        guard object["formatVersion"]?.intValue == 1 else {
            throw BRC38Error.invalidConstant("formatVersion")
        }
        guard let exportedAt = object["exportedAt"]?.stringValue else {
            throw BRC38Error.missingField("exportedAt")
        }
        let sourceStorage = try BRC38Validator.row(object["sourceStorage"], path: "sourceStorage")
        let user = try BRC38Validator.row(object["user"], path: "user")
        guard let tableObject = object["tables"]?.objectValue else {
            throw BRC38Error.expectedObject("tables")
        }

        let tables = try BRC38Tables(
            provenTxs: BRC38Validator.rows(tableObject, "provenTxs"),
            provenTxReqs: BRC38Validator.rows(tableObject, "provenTxReqs"),
            outputBaskets: BRC38Validator.rows(tableObject, "outputBaskets"),
            transactions: BRC38Validator.rows(tableObject, "transactions"),
            commissions: BRC38Validator.rows(tableObject, "commissions"),
            outputs: BRC38Validator.rows(tableObject, "outputs"),
            outputTags: BRC38Validator.rows(tableObject, "outputTags"),
            outputTagMaps: BRC38Validator.rows(tableObject, "outputTagMaps"),
            txLabels: BRC38Validator.rows(tableObject, "txLabels"),
            txLabelMaps: BRC38Validator.rows(tableObject, "txLabelMaps"),
            certificates: BRC38Validator.rows(tableObject, "certificates"),
            certificateFields: BRC38Validator.rows(tableObject, "certificateFields"),
            syncStates: BRC38Validator.rows(tableObject, "syncStates")
        )
        return try BRC38WalletData(
            exportedAt: exportedAt,
            sourceStorage: sourceStorage,
            user: user,
            tables: tables,
            limits: limits
        )
    }

    /// Serializes this document using RFC 8785 JCS and BRC-38's required table ordering.
    public func canonicalJSON() throws -> String {
        try JCS.serialize(.object([
            "brc": .number(38),
            "title": .string(Self.title),
            "formatVersion": .number(1),
            "exportedAt": .string(exportedAt),
            "sourceStorage": .object(sourceStorage),
            "user": .object(user),
            "tables": .object(try tables.canonicalObject()),
        ]))
    }
}

public enum BRC38Error: Error, Equatable, Sendable {
    case invalidJSON
    case documentTooLarge(maximumByteCount: Int)
    case tooManyRows(maximum: Int)
    case missingField(String)
    case invalidConstant(String)
    case expectedObject(String)
    case expectedArray(String)
    case nullValue(String)
    case invalidTimestamp(String)
    case invalidBase64(String)
    case invalidJSONField(String)
    case invalidInteger(String)
    case invalidString(String)
    case duplicateID(String)
    case relationship(String)
    case canonicalization
}

extension BRC38Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidJSON: "Invalid BRC-38 JSON"
        case .documentTooLarge(let maximum): "BRC-38 document exceeds \(maximum) bytes"
        case .tooManyRows(let maximum): "BRC-38 document exceeds \(maximum) rows"
        case .missingField(let path): "BRC-38 is missing \(path)"
        case .invalidConstant(let path): "BRC-38 has an unsupported \(path)"
        case .expectedObject(let path): "BRC-38 \(path) must be an object"
        case .expectedArray(let path): "BRC-38 \(path) must be an array"
        case .nullValue(let path): "BRC-38 \(path) must be omitted instead of null"
        case .invalidTimestamp(let path): "BRC-38 \(path) must be a UTC millisecond timestamp"
        case .invalidBase64(let path): "BRC-38 \(path) must be padded base64"
        case .invalidJSONField(let path): "BRC-38 \(path) must be an object"
        case .invalidInteger(let path): "BRC-38 \(path) must be an integer"
        case .invalidString(let path): "BRC-38 \(path) must be a string"
        case .duplicateID(let path): "BRC-38 contains duplicate \(path)"
        case .relationship(let path): "BRC-38 relationship does not resolve: \(path)"
        case .canonicalization: "BRC-38 contains a value that cannot be canonicalized"
        }
    }
}
