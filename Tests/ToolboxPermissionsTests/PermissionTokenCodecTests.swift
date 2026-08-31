import BSVKeys
import BSVScript
import BSVWallet
import XCTest
@testable import ToolboxPermissions

final class PermissionTokenCodecTests: XCTestCase {
    func testConstantsBasketsAndNormativeFieldOrder() async throws {
        XCTAssertEqual(PermissionTokenBasket.protocolPermission.rawValue, "admin protocol-permission")
        XCTAssertEqual(PermissionTokenBasket.basketAccess.rawValue, "admin basket-access")
        XCTAssertEqual(PermissionTokenBasket.certificateAccess.rawValue, "admin certificate-access")
        XCTAssertEqual(PermissionTokenBasket.spendingAuthorization.rawValue, "admin spending-authorization")
        XCTAssertEqual(PermissionTokenCodec.encryptionProtocolName, "admin permission token encryption")
        XCTAssertEqual(PermissionTokenCodec.encryptionSecurityLevel, .everyAppAndCounterparty)
        XCTAssertEqual(PermissionTokenCodec.encryptionKeyID, "1")
        XCTAssertEqual(PermissionTokenCodec.counterparty, .self)
        XCTAssertTrue(PermissionTokenCodec.forSelf)
        XCTAssertTrue(PermissionTokenCodec.includesSignature)
        XCTAssertEqual(PermissionTokenCodec.lockPosition, .beforeCompatibility)

        let tokens = try fixtures()
        XCTAssertEqual(try textFields(tokens[0]), [
            "example.com", "123", "true", "2", "example signing", "self",
        ])
        XCTAssertEqual(try textFields(tokens[1]), [
            "example.com", "456", "payments",
        ])
        XCTAssertEqual(try textFields(tokens[2]), [
            "example.com", "789", "false", "identity type", "[\"email\",\"name\"]",
            CanonicalCounterparty(publicKey: try testKey(9)).rawValue,
        ])
        XCTAssertEqual(try textFields(tokens[3]), ["example.com", "10000"])
        XCTAssertEqual(tokens.map(\.basket), PermissionTokenBasket.allCases)

        let levelOne = PermissionToken.dpacp(try .init(
            scope: .init(
                originator: CanonicalOriginator("example.com"),
                privileged: false,
                securityLevel: .application,
                protocolName: "example signing",
                counterparty: .anyone
            ),
            expiry: 0
        ))
        XCTAssertEqual(try textFields(levelOne), [
            "example.com", "0", "false", "1", "example signing", "",
        ])

        let wallet = RecordingLegacyWallet(rootKey: try testPrivateKey(1))
        _ = try await PermissionTokenCodec.encode(tokens[0], using: wallet)
        let calls = await wallet.encryptRequests
        XCTAssertEqual(calls.map { String(decoding: $0.plaintext, as: UTF8.self) }, try textFields(tokens[0]))
        XCTAssertTrue(calls.allSatisfy {
            $0.protocolID.securityLevel == .everyAppAndCounterparty
                && $0.protocolID.name == "admin permission token encryption"
                && $0.keyID.value == "1"
                && $0.counterparty == .self
        })
    }

    func testAllTokenTypesRoundTripWithEncryptedSignedLockBeforePushDrop() async throws {
        let wallet = ProtoWallet(rootKey: try testPrivateKey(7))
        for token in try fixtures() {
            let script = try await PermissionTokenCodec.encode(token, using: wallet)
            XCTAssertThrowsError(try PushDrop.decode(script, lockPosition: .after))
            let structural = try PushDrop.decode(script, lockPosition: .beforeCompatibility)
            XCTAssertEqual(structural.fields.count, expectedSemanticCount(token) + 1)
            XCTAssertNoThrow(try ECDSASignature(derBytes: structural.fields.last!))
            let roundTripped = try await PermissionTokenCodec.decode(
                script,
                from: token.basket,
                using: wallet
            )
            XCTAssertEqual(roundTripped, token)
        }
    }

    func testTrailingSignatureMustBePresentAndValid() async throws {
        let wallet = ProtoWallet(rootKey: try testPrivateKey(2))
        let token = try fixtures()[1]
        let script = try await PermissionTokenCodec.encode(token, using: wallet)
        let decoded = try PushDrop.decode(script, lockPosition: .beforeCompatibility)

        let unsigned = try PushDrop.lockingScript(
            fields: Array(decoded.fields.dropLast()),
            publicKey: decoded.publicKey,
            lockPosition: .beforeCompatibility
        )
        await assertTokenError(.unexpectedFieldCount(actual: 3, expected: 4)) {
            try await PermissionTokenCodec.decode(unsigned, from: token.basket, using: wallet)
        }

        var badFields = decoded.fields
        badFields[badFields.count - 1][badFields.last!.count - 1] ^= 1
        let badSignature = try PushDrop.lockingScript(
            fields: badFields,
            publicKey: decoded.publicKey,
            lockPosition: .beforeCompatibility
        )
        await assertTokenError(.invalidSignature) {
            try await PermissionTokenCodec.decode(badSignature, from: token.basket, using: wallet)
        }
    }

    func testLockMustBelongToInjectedWallet() async throws {
        let owner = ProtoWallet(rootKey: try testPrivateKey(2))
        let other = ProtoWallet(rootKey: try testPrivateKey(3))
        let token = try fixtures()[3]
        let script = try await PermissionTokenCodec.encode(token, using: owner)
        await assertTokenError(.lockingPublicKeyMismatch) {
            try await PermissionTokenCodec.decode(script, from: token.basket, using: other)
        }
    }

    func testLegacyPlaintextFallbackIsOnlyAfterDecryptFailure() async throws {
        let wallet = RecordingLegacyWallet(rootKey: try testPrivateKey(4))
        let token = try fixtures()[0]
        let script = try await PermissionTokenCodec.encode(token, using: wallet)
        let roundTripped = try await PermissionTokenCodec.decode(
            script,
            from: token.basket,
            using: wallet
        )
        XCTAssertEqual(roundTripped, token)
        let decryptCallCount = await wallet.decryptCallCount
        XCTAssertEqual(decryptCallCount, 6)

        let malformed = try await signedPlaintextScript(
            fields: ["example.com", "123", "not-bool", "2", "example protocol", "self"],
            wallet: wallet
        )
        await assertTokenError(.invalidBoolean(field: "privileged")) {
            try await PermissionTokenCodec.decode(
                malformed,
                from: .protocolPermission,
                using: wallet
            )
        }
    }

    func testStrictProtocolValidationRejectsLevelZeroUnknownAndMalformedFields() async throws {
        let wallet = RecordingLegacyWallet(rootKey: try testPrivateKey(5))
        for level in ["0", "3", "-1"] {
            let script = try await signedPlaintextScript(
                fields: ["example.com", "1", "false", level, "example protocol", "self"],
                wallet: wallet
            )
            await assertTokenError(.invalidProtocolSecurityLevel(level)) {
                try await PermissionTokenCodec.decode(
                    script,
                    from: .protocolPermission,
                    using: wallet
                )
            }
        }

        for validLevelOneCounterparty in ["", "self", "anyone"] {
            let script = try await signedPlaintextScript(
                fields: ["example.com", "0", "false", "1", "example signing", validLevelOneCounterparty],
                wallet: wallet
            )
            let decoded = try await PermissionTokenCodec.decode(
                script,
                from: .protocolPermission,
                using: wallet
            )
            guard case .dpacp(let token) = decoded else {
                return XCTFail("Expected DPACP")
            }
            XCTAssertNil(token.scope.counterparty)
        }

        let invalidCases: [(PermissionTokenBasket, [[UInt8]], PermissionTokenError)] = [
            (.basketAccess, [[0xff], bytes("1"), bytes("basket")], .invalidUTF8(field: "originator")),
            (.basketAccess, [bytes("bad host / path"), bytes("1"), bytes("basket")], .invalidOriginator),
            (.basketAccess, [bytes("example.com"), bytes("01"), bytes("basket")], .invalidUnsignedInteger(field: "expiry")),
            (.basketAccess, [bytes("example.com"), bytes("18446744073709551616"), bytes("basket")], .invalidUnsignedInteger(field: "expiry")),
            (.certificateAccess, [bytes("example.com"), bytes("1"), bytes("true"), bytes("type"), bytes("{}"), bytes("self")], .invalidCertificateFieldsJSON),
            (.certificateAccess, [bytes("example.com"), bytes("1"), bytes("true"), bytes("type"), bytes("[\"name\"]"), bytes("anyone")], .invalidVerifier),
            (.spendingAuthorization, [bytes("example.com"), bytes("-1")], .invalidUnsignedInteger(field: "authorizedAmount")),
        ]
        for (basket, fields, expected) in invalidCases {
            let script = try await signedPlaintextScript(fields: fields, wallet: wallet)
            await assertTokenError(expected) {
                try await PermissionTokenCodec.decode(script, from: basket, using: wallet)
            }
        }
    }

    func testExactCountsIncludingDSAPTwoFields() async throws {
        let wallet = RecordingLegacyWallet(rootKey: try testPrivateKey(6))
        let cases: [(PermissionTokenBasket, [String], Int)] = [
            (.protocolPermission, ["example.com", "0", "false", "1", "example protocol"], 7),
            (.basketAccess, ["example.com", "0"], 4),
            (.certificateAccess, ["example.com", "0", "false", "type", "[]"], 7),
            (.spendingAuthorization, ["example.com", "100", "unexpected-expiry"], 3),
        ]
        for (basket, fields, expected) in cases {
            let script = try await signedPlaintextScript(fields: fields, wallet: wallet)
            await assertTokenError(.unexpectedFieldCount(actual: fields.count + 1, expected: expected)) {
                try await PermissionTokenCodec.decode(script, from: basket, using: wallet)
            }
        }
    }

    func testExpiryBoundariesAndDSAPNeverExpires() throws {
        let tokens = try fixtures()
        XCTAssertFalse(tokens[0].isExpired(at: 123))
        XCTAssertTrue(tokens[0].isExpired(at: 124))
        XCTAssertFalse(tokens[3].isExpired(at: .max))

        let never = PermissionToken.dbap(try DBAPPermissionToken(
            scope: .init(originator: CanonicalOriginator("example.com"), basket: "basket"),
            expiry: 0
        ))
        XCTAssertFalse(never.isExpired(at: .max))
    }

    func testDCAPCanonicalizesFieldsAndUsesSubsetCoverage() throws {
        let verifier = CanonicalCounterparty(publicKey: try testKey(8))
        let token = try DCAPPermissionToken(
            scope: .init(
                originator: CanonicalOriginator("HTTPS://EXAMPLE.COM:443/path"),
                privileged: false,
                certificateType: "identity",
                verifier: verifier,
                fields: ["name", "email", "name"]
            ),
            expiry: 0
        )
        XCTAssertEqual(token.scope.originator.rawValue, "example.com")
        XCTAssertEqual(token.scope.fields, ["email", "name"])
        XCTAssertTrue(token.covers(fields: ["name"]))
        XCTAssertTrue(token.covers(fields: ["email", "name", "name"]))
        XCTAssertFalse(token.covers(fields: ["photo"]))
    }

    private func fixtures() throws -> [PermissionToken] {
        let originator = try CanonicalOriginator("HTTPS://EXAMPLE.COM:443/path")
        return [
            .dpacp(try .init(
                scope: .init(
                    originator: originator,
                    privileged: true,
                    securityLevel: .applicationAndCounterparty,
                    protocolName: "Example Signing",
                    counterparty: .selfCounterparty
                ),
                expiry: 123
            )),
            .dbap(try .init(
                scope: .init(originator: originator, basket: "payments"),
                expiry: 456
            )),
            .dcap(try .init(
                scope: .init(
                    originator: originator,
                    privileged: false,
                    certificateType: "identity type",
                    verifier: CanonicalCounterparty(publicKey: try testKey(9)),
                    fields: ["name", "email", "name"]
                ),
                expiry: 789
            )),
            .dsap(.init(
                scope: .init(originator: originator),
                authorizedAmount: 10_000
            )),
        ]
    }

    private func textFields(_ token: PermissionToken) throws -> [String] {
        try PermissionTokenCodec.semanticFields(for: token).map {
            guard let text = String(bytes: $0, encoding: .utf8) else {
                throw TestWalletError.invalidUTF8
            }
            return text
        }
    }

    private func expectedSemanticCount(_ token: PermissionToken) -> Int {
        switch token {
        case .dpacp, .dcap: 6
        case .dbap: 3
        case .dsap: 2
        }
    }

    private func signedPlaintextScript(
        fields: [String],
        wallet: RecordingLegacyWallet
    ) async throws -> Script {
        try await signedPlaintextScript(fields: fields.map(bytes), wallet: wallet)
    }

    private func signedPlaintextScript(
        fields: [[UInt8]],
        wallet: RecordingLegacyWallet
    ) async throws -> Script {
        try await PushDrop.lockingScript(
            fields: fields,
            using: wallet,
            protocolID: .walletInternalAdmin(
                securityLevel: .everyAppAndCounterparty,
                name: "admin permission token encryption"
            ),
            keyID: WalletKeyID("1"),
            counterparty: .self,
            forSelf: true,
            includeSignature: true,
            lockPosition: .beforeCompatibility
        )
    }

    private func assertTokenError<T>(
        _ expected: PermissionTokenError,
        operation: () async throws -> T
    ) async {
        do {
            _ = try await operation()
            XCTFail("Expected \(expected)")
        } catch {
            XCTAssertEqual(error as? PermissionTokenError, expected)
        }
    }
}

private func bytes(_ value: String) -> [UInt8] { Array(value.utf8) }

private enum TestWalletError: Error {
    case decryptionFailure
    case invalidUTF8
}

private actor RecordingLegacyWallet:
    WalletPublicKeyProviding,
    WalletCipherOperations,
    WalletSignatureOperations
{
    private let wallet: ProtoWallet
    private(set) var encryptRequests = [WalletEncryptRequest]()
    private(set) var decryptCallCount = 0

    init(rootKey: PrivateKey) {
        wallet = ProtoWallet(rootKey: rootKey)
    }

    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult {
        try await wallet.getPublicKey(request)
    }

    func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult {
        encryptRequests.append(request)
        return .init(ciphertext: request.plaintext)
    }

    func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult {
        decryptCallCount += 1
        throw TestWalletError.decryptionFailure
    }

    func createSignature(_ request: WalletCreateSignatureRequest) async throws -> WalletCreateSignatureResult {
        try await wallet.createSignature(request)
    }

    func verifySignature(_ request: WalletVerifySignatureRequest) async throws -> WalletVerifySignatureResult {
        try await wallet.verifySignature(request)
    }
}
