import Foundation
import BSVCore
import BSVWallet
import ToolboxCore
import ToolboxStorage

extension StorageClient {
    /// Lists stored certificates using the same authenticated storage RPC as the reference wallets.
    public func listCertificates(
        _ auth: AuthID, _ request: WalletListCertificatesRequest
    ) async throws -> WalletListCertificatesResult {
        let codec = try WalletBRC100JSONCodec(beefLimits: StorageLimits.beef)
        let bytes = try codec.encodeRequest(.certificate(.listCertificates(request)))
        let arguments = try JSONDecoder().decode(JSONValue.self, from: Data(bytes))
        let result = try await call("listCertificates", [.object(auth.jsonObject), arguments])
        do {
            let encoded = try JSONEncoder().encode(result)
            guard case .certificate(.listCertificates(let certificates)) = try codec.decodeResult(
                route: WalletJSONRoute(methodName: "listCertificates")!, from: Array(encoded)
            ) else {
                throw StorageClientError.unreadableResponse(method: "listCertificates")
            }
            return certificates
        } catch {
            throw StorageClientError.unreadableResponse(method: "listCertificates")
        }
    }

    /// Stores a certificate with its fields and master keyring, returning storage's record id.
    ///
    /// The reference sends this as `insertCertificateAuth` with the `TableCertificateX` row that
    /// `acquireDirectCertificate` builds: ids zero for storage to assign, both timestamps `now`,
    /// `isDeleted` false, and one field row per certificate field whose `masterKey` is that
    /// field's keyring entry, or empty when the keyring has none. Storage binds the row to the
    /// authenticated user, so `userId` is the known id or zero.
    public func insertCertificate(
        _ auth: AuthID, _ record: StorageCertificate, now: Date = Date()
    ) async throws -> Int {
        let result = try await call(
            "insertCertificateAuth",
            [.object(auth.jsonObject), .object(Self.certificateRow(auth, record, now: now))]
        )
        guard let id = result.intValue, id > 0 else {
            throw StorageClientError.unreadableResponse(method: "insertCertificateAuth")
        }
        return id
    }

    /// Marks a certificate deleted, returning storage's update count.
    ///
    /// Storage keeps the row for replication and stops listing it. The count is storage's, not
    /// BRC-100's: the wallet decides what a count other than one means.
    public func relinquishCertificate(
        _ auth: AuthID, _ request: WalletRelinquishCertificateRequest
    ) async throws -> Int {
        let result = try await call("relinquishCertificate", [
            .object(auth.jsonObject),
            .object([
                "type": .string(request.type.base64),
                "serialNumber": .string(request.serialNumber.base64),
                "certifier": .string(Hex.encode(request.certifier.compressedBytes)),
            ]),
        ])
        guard let updated = result.intValue, updated >= 0 else {
            throw StorageClientError.unreadableResponse(method: "relinquishCertificate")
        }
        return updated
    }

    static func certificateRow(
        _ auth: AuthID, _ record: StorageCertificate, now: Date
    ) -> [String: JSONValue] {
        let certificate = record.certificate
        let stamp = JSONValue.string(isoTimestamp(now))
        let userID = JSONValue.number(Double(auth.userID ?? 0))
        let fields = certificate.fields.keys.sorted().map { name -> JSONValue in
            .object([
                "certificateId": .number(0),
                "created_at": stamp,
                "updated_at": stamp,
                "userId": userID,
                "fieldName": .string(name.value),
                "fieldValue": .string(certificate.fields[name]?.base64 ?? ""),
                "masterKey": .string(record.masterKeyring[name]?.base64 ?? ""),
            ])
        }
        return [
            "certificateId": .number(0),
            "created_at": stamp,
            "updated_at": stamp,
            "userId": userID,
            "type": .string(certificate.type.base64),
            "subject": .string(Hex.encode(certificate.subject.compressedBytes)),
            "verifier": .string(Hex.encode(record.verifier.compressedBytes)),
            "serialNumber": .string(certificate.serialNumber.base64),
            "certifier": .string(Hex.encode(certificate.certifier.compressedBytes)),
            "revocationOutpoint": .string(certificate.revocationOutpoint.description),
            "signature": .string(certificate.signature.map { Hex.encode($0.derBytes) } ?? ""),
            "fields": .array(fields),
            "isDeleted": .bool(false),
        ]
    }

    /// `Date.toISOString()`: UTC with milliseconds.
    static func isoTimestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
