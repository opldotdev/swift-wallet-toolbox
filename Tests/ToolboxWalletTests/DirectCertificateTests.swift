import XCTest
import BSVAuth
import BSVCore
import BSVKeys
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
import ToolboxStorageClient
@testable import ToolboxWallet

/// `acquireCertificate` (direct) and `relinquishCertificate`, against `Wallet.acquireCertificate`,
/// `acquireDirectCertificate` and `Wallet.relinquishCertificate` in `@bsv/wallet-toolbox`.
///
/// Certificates are issued in-test by a certifier wallet, so every case is offline. Storage is a
/// recording transport: a refusal must never reach it.
final class DirectCertificateTests: XCTestCase {

    private actor RecordingTransport: AuthenticatedTransport {
        private var results: [String]
        private(set) var bodies: [JSONValue] = []

        init(results: [String]) { self.results = results }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            if let reply = ActiveStorageFixture.reply(to: body) { return reply }
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
            bodies.append(request)
            let result = results.isEmpty ? "null" : results.removeFirst()
            let response = JSONValue.object([
                "jsonrpc": .string("2.0"),
                "id": request["id"] ?? .number(1),
                "result": try JSONDecoder().decode(JSONValue.self, from: Data(result.utf8)),
            ])
            return AuthenticatedResponse(
                statusCode: 200, headers: [:], body: Array(try JSONEncoder().encode(response))
            )
        }
    }

    private func key(_ byte: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [byte])
    }

    private func hex(_ key: PublicKey) -> String { Hex.encode(key.compressedBytes) }

    private let typeID = try! CertificateTypeID([UInt8](repeating: 0x5a, count: 32))

    private func wallet(_ root: PrivateKey, _ transport: RecordingTransport) -> RemoteWallet {
        RemoteWallet(
            storage: StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport),
            identityKey: root,
            auth: AuthID(identityKey: hex(root.publicKey))
        )
    }

    /// A certificate signed by `certifier` for `subject`, as a certifier would hand it over.
    private func issue(
        to subject: PublicKey, by certifier: PrivateKey,
        fields: [String: String] = ["handle": "alice", "domain": "1sat.app"]
    ) async throws -> MasterCertificate {
        var plaintext: [CertificateFieldName: String] = [:]
        for (name, value) in fields { plaintext[try CertificateFieldName(name)] = value }
        return try await CertificateEngine.issue(
            type: typeID,
            subject: .publicKey(subject),
            plaintextFields: plaintext,
            using: ProtoWallet(rootKey: certifier)
        )
    }

    private func directRequest(
        _ master: MasterCertificate,
        signature: ECDSASignature? = nil,
        keyring: [CertificateFieldName: CertificateCiphertext]? = nil,
        revealer: WalletKeyringRevealer = .certifier
    ) throws -> WalletAcquireCertificateRequest {
        let certificate = master.certificate
        var fields: [CertificateFieldName: String] = [:]
        for (name, value) in certificate.fields { fields[name] = value.base64 }
        return try WalletAcquireCertificateRequest(
            type: certificate.type,
            certifier: certificate.certifier,
            fields: fields,
            acquisition: .direct(try WalletDirectCertificateAcquisition(
                serialNumber: certificate.serialNumber,
                revocationOutpoint: certificate.revocationOutpoint,
                signature: try XCTUnwrap(signature ?? certificate.signature),
                keyringRevealer: revealer,
                keyringForSubject: keyring ?? master.masterKeyring.entries
            ))
        )
    }

    private func assertRefused(
        _ request: WalletAcquireCertificateRequest, by root: PrivateKey,
        file: StaticString = #filePath, line: UInt = #line
    ) async throws {
        let transport = RecordingTransport(results: ["7"])
        do {
            _ = try await wallet(root, transport).acquireCertificate(request)
            XCTFail("an unverifiable certificate was accepted", file: file, line: line)
        } catch WalletError.invalidCertificate(_) {
        }
        let bodies = await transport.bodies
        XCTAssertTrue(bodies.isEmpty, "storage was called for a refused certificate", file: file, line: line)
    }

    // MARK: - Direct acquisition

    func test_directAcquireVerifiesThenInsertsTheReferenceRow() async throws {
        let subject = try key(1)
        let certifier = try key(9)
        let master = try await issue(to: subject.publicKey, by: certifier)
        let transport = RecordingTransport(results: ["42"])
        let now = Date(timeIntervalSince1970: 1_700_000_000.5)

        let stored = try await wallet(subject, transport).acquireCertificate(
            try directRequest(master), now: now
        )
        XCTAssertEqual(stored, master.certificate)

        let bodies = await transport.bodies
        XCTAssertEqual(bodies.count, 1)
        XCTAssertEqual(bodies[0]["method"], .string("insertCertificateAuth"))
        let params = try XCTUnwrap(bodies[0]["params"]?.arrayValue)
        XCTAssertEqual(params[0]["identityKey"], .string(hex(subject.publicKey)))
        let row = try XCTUnwrap(params[1].objectValue)
        let certificate = master.certificate
        let stamp = JSONValue.string("2023-11-14T22:13:20.500Z")
        XCTAssertEqual(row["certificateId"], .number(0))
        XCTAssertEqual(row["created_at"], stamp)
        XCTAssertEqual(row["updated_at"], stamp)
        XCTAssertEqual(row["userId"], .number(0))
        XCTAssertEqual(row["type"], .string(certificate.type.base64))
        XCTAssertEqual(row["subject"], .string(hex(subject.publicKey)))
        XCTAssertEqual(row["verifier"], .string(hex(certifier.publicKey)))
        XCTAssertEqual(row["certifier"], .string(hex(certifier.publicKey)))
        XCTAssertEqual(row["serialNumber"], .string(certificate.serialNumber.base64))
        XCTAssertEqual(row["revocationOutpoint"], .string(String(repeating: "0", count: 64) + ".0"))
        XCTAssertEqual(
            row["signature"], .string(Hex.encode(try XCTUnwrap(certificate.signature).derBytes))
        )
        XCTAssertEqual(row["isDeleted"], .bool(false))

        let fieldRows = try XCTUnwrap(row["fields"]?.arrayValue)
        XCTAssertEqual(fieldRows.compactMap { $0["fieldName"]?.stringValue }, ["domain", "handle"])
        for fieldRow in fieldRows {
            let name = try CertificateFieldName(try XCTUnwrap(fieldRow["fieldName"]?.stringValue))
            XCTAssertEqual(fieldRow["fieldValue"], .string(try XCTUnwrap(certificate.fields[name]).base64))
            XCTAssertEqual(
                fieldRow["masterKey"],
                .string(try XCTUnwrap(master.masterKeyring.entries[name]).base64)
            )
            XCTAssertEqual(fieldRow["certificateId"], .number(0))
            XCTAssertEqual(fieldRow["userId"], .number(0))
            XCTAssertEqual(fieldRow["created_at"], stamp)
        }
    }

    func test_aNamedRevealerIsStoredAsTheVerifier() async throws {
        let subject = try key(1)
        let master = try await issue(to: subject.publicKey, by: try key(9))
        let revealer = try key(5).publicKey
        let transport = RecordingTransport(results: ["1"])
        _ = try await wallet(subject, transport).acquireCertificate(
            try directRequest(master, revealer: .publicKey(revealer))
        )
        let bodies = await transport.bodies
        XCTAssertEqual(bodies[0]["params"]?.arrayValue?[1]["verifier"], .string(hex(revealer)))
    }

    func test_aCertificateForAnotherSubjectIsRefused() async throws {
        // The reference replaces the subject with the wallet's own identity before verifying, so a
        // certificate signed for someone else fails its signature here.
        let master = try await issue(to: try key(2).publicKey, by: try key(9))
        try await assertRefused(try directRequest(master), by: try key(1))
    }

    func test_aBadSignatureIsRefused() async throws {
        let subject = try key(1)
        let master = try await issue(to: subject.publicKey, by: try key(9))
        let other = try await issue(to: subject.publicKey, by: try key(9))
        try await assertRefused(
            try directRequest(master, signature: other.certificate.signature), by: subject
        )
    }

    func test_anIncompleteKeyringIsRefused() async throws {
        let subject = try key(1)
        let master = try await issue(to: subject.publicKey, by: try key(9))
        var keyring = master.masterKeyring.entries
        keyring.removeValue(forKey: try CertificateFieldName("domain"))
        try await assertRefused(try directRequest(master, keyring: keyring), by: subject)
    }

    func test_aKeyringThatDoesNotDecryptIsRefused() async throws {
        let subject = try key(1)
        let master = try await issue(to: subject.publicKey, by: try key(9))
        let foreign = try await issue(to: try key(3).publicKey, by: try key(9))
        try await assertRefused(
            try directRequest(master, keyring: foreign.masterKeyring.entries), by: subject
        )
    }

    func test_issuanceIsNotImplementedAndNeverReachesStorage() async throws {
        let transport = RecordingTransport(results: [])
        let request = try WalletAcquireCertificateRequest(
            type: typeID,
            certifier: try key(9).publicKey,
            fields: [try CertificateFieldName("handle"): "alice"],
            acquisition: .issuance(try WalletIssuanceCertificateAcquisition(
                certifierURL: "https://certifier.example"
            ))
        )
        do {
            _ = try await wallet(try key(1), transport).acquireCertificate(request)
            XCTFail("issuance must not be accepted")
        } catch WalletError.notImplemented(_) {
        }
        let bodies = await transport.bodies
        XCTAssertTrue(bodies.isEmpty)
    }

    func test_anUnreadableInsertResultIsAnError() async throws {
        let subject = try key(1)
        let master = try await issue(to: subject.publicKey, by: try key(9))
        for answer in ["null", "0", #""1""#] {
            let transport = RecordingTransport(results: [answer])
            do {
                _ = try await wallet(subject, transport).acquireCertificate(try directRequest(master))
                XCTFail("accepted insert result \(answer)")
            } catch let error as StorageClientError {
                XCTAssertEqual(error, .unreadableResponse(method: "insertCertificateAuth"))
            }
        }
    }

    // MARK: - Relinquish

    private func relinquishRequest() throws -> WalletRelinquishCertificateRequest {
        WalletRelinquishCertificateRequest(
            type: typeID,
            serialNumber: try CertificateSerialNumber([UInt8](repeating: 0x07, count: 32)),
            certifier: try key(9).publicKey
        )
    }

    func test_relinquishSendsTheReferenceArguments() async throws {
        let transport = RecordingTransport(results: ["1"])
        let result = try await wallet(try key(1), transport).relinquishCertificate(try relinquishRequest())
        XCTAssertTrue(result.relinquished)

        let bodies = await transport.bodies
        XCTAssertEqual(bodies[0]["method"], .string("relinquishCertificate"))
        XCTAssertEqual(bodies[0]["params"]?.arrayValue?[1], .object([
            "type": .string(typeID.base64),
            "serialNumber": .string(try CertificateSerialNumber([UInt8](repeating: 0x07, count: 32)).base64),
            "certifier": .string(hex(try key(9).publicKey)),
        ]))
    }

    func test_relinquishNeedsExactlyOneUpdatedCertificate() async throws {
        for count in ["0", "2"] {
            let transport = RecordingTransport(results: [count])
            do {
                _ = try await wallet(try key(1), transport).relinquishCertificate(try relinquishRequest())
                XCTFail("an update count of \(count) is not a relinquishment")
            } catch let error as WalletError {
                XCTAssertEqual(error, .storageMutationIncomplete("certificate relinquishment"))
            }
        }
        let transport = RecordingTransport(results: ["null"])
        do {
            _ = try await wallet(try key(1), transport).relinquishCertificate(try relinquishRequest())
            XCTFail("a null update count is not a relinquishment")
        } catch let error as StorageClientError {
            XCTAssertEqual(error, .unreadableResponse(method: "relinquishCertificate"))
        }
    }
}
