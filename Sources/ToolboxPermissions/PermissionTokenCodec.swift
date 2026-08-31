import BSVCrypto
import BSVKeys
import BSVScript
import BSVWallet
import Foundation

/// The minimum wallet capabilities needed to encrypt, sign, and decode permission tokens.
public typealias PermissionTokenCrypto = WalletPublicKeyProviding
    & WalletCipherOperations
    & WalletSignatureOperations

/// BRC-116's encrypted, signed, lock-before PushDrop token codec.
public enum PermissionTokenCodec {
    public static let encryptionProtocolName = "admin permission token encryption"
    public static let encryptionSecurityLevel = WalletSecurityLevel.everyAppAndCounterparty
    public static let encryptionKeyID = "1"
    public static let counterparty = WalletCounterparty.`self`
    public static let forSelf = true
    public static let lockPosition = PushDropLockPosition.beforeCompatibility
    public static let includesSignature = true

    /// Encrypts the normative semantic fields independently, then creates the signed PushDrop lock.
    public static func encode(
        _ token: PermissionToken,
        using wallet: any PermissionTokenCrypto,
        limits: PushDropLimits = .standard
    ) async throws -> Script {
        let plaintextFields = try semanticFields(for: token)
        let protocolID = try encryptionProtocol()
        let keyID = try WalletKeyID(encryptionKeyID)
        var encryptedFields = [[UInt8]]()
        encryptedFields.reserveCapacity(plaintextFields.count)
        for field in plaintextFields {
            try Task.checkCancellation()
            let result = try await wallet.encrypt(.init(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: counterparty,
                plaintext: field
            ))
            encryptedFields.append(result.ciphertext)
        }
        try Task.checkCancellation()
        return try await PushDrop.lockingScript(
            fields: encryptedFields,
            using: wallet,
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            forSelf: forSelf,
            includeSignature: includesSignature,
            lockPosition: lockPosition,
            limits: limits
        )
    }

    /// Decodes a token from the admin basket that identifies its encrypted field schema.
    ///
    /// For compatibility with the live TypeScript wallet-toolbox, a field whose decrypt call
    /// fails is treated as a legacy plaintext field. The signed lock, wallet-owned locking key,
    /// exact field count, and all semantic validation remain mandatory.
    public static func decode(
        _ script: Script,
        from basket: PermissionTokenBasket,
        using wallet: any PermissionTokenCrypto,
        limits: PushDropLimits = .standard
    ) async throws -> PermissionToken {
        let semanticCount = fieldCount(for: basket)
        let decoded: PushDropDecoded
        do {
            decoded = try PushDrop.decode(
                script,
                lockPosition: lockPosition,
                limits: limits
            )
        } catch {
            throw PermissionTokenError.invalidPushDrop
        }
        let signedCount = semanticCount + 1
        guard decoded.fields.count == signedCount else {
            throw PermissionTokenError.unexpectedFieldCount(
                actual: decoded.fields.count,
                expected: signedCount
            )
        }

        let encryptedFields = Array(decoded.fields.prefix(semanticCount))
        let signature: ECDSASignature
        do {
            signature = try ECDSASignature(derBytes: decoded.fields[semanticCount])
        } catch {
            throw PermissionTokenError.invalidSignature
        }
        var signedPayload = signingPayload(encryptedFields)
        let primarySignatureIsValid = decoded.publicKey.verify(
            signature,
            digest: BSVHashing.sha256(signedPayload)
        )
        var legacyEmptyLevelOneCounterparty = false
        if !primarySignatureIsValid,
           basket == .protocolPermission,
           encryptedFields[5] == [0] {
            // Script OP_0 cannot preserve the distinction between an empty byte vector and the
            // single zero byte returned by Swift PushDrop.decode. The TS encoder signs the
            // original empty Level-1 counterparty, so retry exactly that one legacy shape.
            var legacyFields = encryptedFields
            legacyFields[5] = []
            signedPayload = signingPayload(legacyFields)
            legacyEmptyLevelOneCounterparty = decoded.publicKey.verify(
                signature,
                digest: BSVHashing.sha256(signedPayload)
            )
        }
        guard primarySignatureIsValid || legacyEmptyLevelOneCounterparty else {
            throw PermissionTokenError.invalidSignature
        }

        let protocolID = try encryptionProtocol()
        let keyID = try WalletKeyID(encryptionKeyID)
        let expectedPublicKey = try await wallet.getPublicKey(.init(selection: .derived(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            forSelf: forSelf
        ))).publicKey
        guard decoded.publicKey == expectedPublicKey else {
            throw PermissionTokenError.lockingPublicKeyMismatch
        }

        var plaintextFields = [[UInt8]]()
        plaintextFields.reserveCapacity(semanticCount)
        for (index, field) in encryptedFields.enumerated() {
            try Task.checkCancellation()
            do {
                let result = try await wallet.decrypt(.init(
                    protocolID: protocolID,
                    keyID: keyID,
                    counterparty: counterparty,
                    ciphertext: field
                ))
                plaintextFields.append(result.plaintext)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                // Exact compatibility with WalletPermissionsManager.decryptPermissionTokenField.
                plaintextFields.append(
                    legacyEmptyLevelOneCounterparty && index == 5 ? [] : field
                )
            }
        }
        try Task.checkCancellation()
        return try decodeSemanticFields(plaintextFields, basket: basket)
    }

    /// Normative plaintext fields, exposed for deterministic cross-implementation vectors.
    public static func semanticFields(for token: PermissionToken) throws -> [[UInt8]] {
        switch token {
        case .dpacp(let token):
            let counterparty = switch token.scope.securityLevel {
            // The live TypeScript WalletPermissionsManager writes an empty field for Level 1,
            // whose authorization identity deliberately ignores counterparties.
            case .application: ""
            case .applicationAndCounterparty: token.scope.counterparty!.rawValue
            }
            return utf8Fields([
                token.scope.originator.rawValue,
                String(token.expiry),
                token.scope.privileged ? "true" : "false",
                String(token.scope.securityLevel.rawValue),
                token.scope.protocolName,
                counterparty,
            ])
        case .dbap(let token):
            return utf8Fields([
                token.scope.originator.rawValue,
                String(token.expiry),
                token.scope.basket,
            ])
        case .dcap(let token):
            let fieldsData = try JSONSerialization.data(withJSONObject: token.scope.fields)
            guard let fieldsJSON = String(data: fieldsData, encoding: .utf8) else {
                throw PermissionTokenError.invalidCertificateFieldsJSON
            }
            return utf8Fields([
                token.scope.originator.rawValue,
                String(token.expiry),
                token.scope.privileged ? "true" : "false",
                token.scope.certificateType,
                fieldsJSON,
                token.scope.verifier.rawValue,
            ])
        case .dsap(let token):
            return utf8Fields([
                token.scope.originator.rawValue,
                String(token.authorizedAmount),
            ])
        }
    }

    private static func decodeSemanticFields(
        _ fields: [[UInt8]],
        basket: PermissionTokenBasket
    ) throws -> PermissionToken {
        switch basket {
        case .protocolPermission:
            let originator = try decodeOriginator(fields[0])
            let expiry = try decodeUInt(fields[1], name: "expiry")
            let privileged = try decodeBool(fields[2], name: "privileged")
            let levelText = try decodeText(fields[3], name: "securityLevel")
            let level: ProtocolPermissionLevel
            switch levelText {
            case "1": level = .application
            case "2": level = .applicationAndCounterparty
            default: throw PermissionTokenError.invalidProtocolSecurityLevel(levelText)
            }
            let protocolName = try decodeText(fields[4], name: "protocolName")
            guard !protocolName.isEmpty else {
                throw PermissionTokenError.emptyValue(field: "protocolName")
            }
            let counterpartyText = try decodeText(fields[5], name: "counterparty")
            let counterparty: CanonicalCounterparty?
            switch level {
            case .application:
                // Accept the TS canonical empty representation and the three values allowed by
                // BRC-116's table. Level 1 always erases the value from authorization identity.
                if !counterpartyText.isEmpty {
                    do {
                        _ = try CanonicalCounterparty(counterpartyText)
                    } catch {
                        throw PermissionTokenError.invalidCounterparty
                    }
                }
                counterparty = nil
            case .applicationAndCounterparty:
                do {
                    counterparty = try CanonicalCounterparty(counterpartyText)
                } catch {
                    throw PermissionTokenError.invalidCounterparty
                }
            }
            let scope: ProtocolPermissionScope
            do {
                scope = try ProtocolPermissionScope(
                    originator: originator,
                    privileged: privileged,
                    securityLevel: level,
                    protocolName: protocolName,
                    counterparty: counterparty
                )
                return .dpacp(try DPACPPermissionToken(scope: scope, expiry: expiry))
            } catch let error as PermissionTokenError {
                throw error
            } catch {
                throw PermissionTokenError.invalidProtocolName
            }

        case .basketAccess:
            let originator = try decodeOriginator(fields[0])
            let expiry = try decodeUInt(fields[1], name: "expiry")
            let basket = try decodeText(fields[2], name: "basketName")
            return .dbap(try DBAPPermissionToken(
                scope: .init(originator: originator, basket: basket),
                expiry: expiry
            ))

        case .certificateAccess:
            let originator = try decodeOriginator(fields[0])
            let expiry = try decodeUInt(fields[1], name: "expiry")
            let privileged = try decodeBool(fields[2], name: "privileged")
            let certificateType = try decodeText(fields[3], name: "certType")
            let certificateFields = try decodeCertificateFields(fields[4])
            let verifierText = try decodeText(fields[5], name: "verifier")
            let verifier: CanonicalCounterparty
            do {
                verifier = try CanonicalCounterparty(verifierText)
            } catch {
                throw PermissionTokenError.invalidVerifier
            }
            return .dcap(try DCAPPermissionToken(
                scope: .init(
                    originator: originator,
                    privileged: privileged,
                    certificateType: certificateType,
                    verifier: verifier,
                    fields: certificateFields
                ),
                expiry: expiry
            ))

        case .spendingAuthorization:
            let originator = try decodeOriginator(fields[0])
            let amount = try decodeUInt(fields[1], name: "authorizedAmount")
            return .dsap(.init(
                scope: .init(originator: originator),
                authorizedAmount: amount
            ))
        }
    }

    private static func decodeOriginator(_ bytes: [UInt8]) throws -> CanonicalOriginator {
        let text = try decodeText(bytes, name: "originator")
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw PermissionTokenError.invalidOriginator }
        let hasScheme = trimmed.range(
            of: #"^[A-Za-z][A-Za-z0-9+.-]*://"#,
            options: .regularExpression
        ) != nil
        let candidate = hasScheme ? trimmed : "https://\(trimmed)"
        guard let components = URLComponents(string: candidate),
              let host = components.host,
              !host.isEmpty else {
            throw PermissionTokenError.invalidOriginator
        }
        do {
            return try CanonicalOriginator(text)
        } catch {
            throw PermissionTokenError.invalidOriginator
        }
    }

    private static func decodeText(_ bytes: [UInt8], name: String) throws -> String {
        guard let text = String(bytes: bytes, encoding: .utf8) else {
            throw PermissionTokenError.invalidUTF8(field: name)
        }
        return text
    }

    private static func decodeUInt(_ bytes: [UInt8], name: String) throws -> UInt64 {
        let text = try decodeText(bytes, name: name)
        guard !text.isEmpty,
              text.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              (text == "0" || !text.hasPrefix("0")),
              let value = UInt64(text) else {
            throw PermissionTokenError.invalidUnsignedInteger(field: name)
        }
        return value
    }

    private static func decodeBool(_ bytes: [UInt8], name: String) throws -> Bool {
        switch try decodeText(bytes, name: name) {
        case "true": true
        case "false": false
        default: throw PermissionTokenError.invalidBoolean(field: name)
        }
    }

    private static func decodeCertificateFields(_ bytes: [UInt8]) throws -> [String] {
        guard let data = String(bytes: bytes, encoding: .utf8)?.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let values = object as? [String] else {
            throw PermissionTokenError.invalidCertificateFieldsJSON
        }
        return Array(Set(values)).sorted()
    }

    private static func fieldCount(for basket: PermissionTokenBasket) -> Int {
        switch basket {
        case .protocolPermission, .certificateAccess: 6
        case .basketAccess: 3
        case .spendingAuthorization: 2
        }
    }

    private static func encryptionProtocol() throws -> WalletProtocolID {
        try .walletInternalAdmin(
            securityLevel: encryptionSecurityLevel,
            name: encryptionProtocolName
        )
    }

    private static func utf8Fields(_ values: [String]) -> [[UInt8]] {
        values.map { Array($0.utf8) }
    }

    private static func signingPayload(_ fields: [[UInt8]]) -> [UInt8] {
        fields.reduce(into: [UInt8]()) { $0.append(contentsOf: $1) }
    }
}
