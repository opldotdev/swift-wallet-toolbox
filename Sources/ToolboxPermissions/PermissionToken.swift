import BSVWallet

/// The four BRC-116 administrative baskets used for persisted permission grants.
public enum PermissionTokenBasket: String, CaseIterable, Hashable, Codable, Sendable {
    case protocolPermission = "admin protocol-permission"
    case basketAccess = "admin basket-access"
    case certificateAccess = "admin certificate-access"
    case spendingAuthorization = "admin spending-authorization"
}

/// A DPACP grant. Level 0 is intentionally unrepresentable.
public struct DPACPPermissionToken: Hashable, Sendable {
    public let scope: ProtocolPermissionScope
    public let expiry: UInt64

    public init(scope: ProtocolPermissionScope, expiry: UInt64) throws {
        let walletLevel: WalletSecurityLevel = switch scope.securityLevel {
        case .application: .everyApp
        case .applicationAndCounterparty: .everyAppAndCounterparty
        }
        let protocolID = try WalletProtocolID(
            securityLevel: walletLevel,
            name: scope.protocolName
        )
        self.scope = try ProtocolPermissionScope(
            originator: scope.originator,
            privileged: scope.privileged,
            securityLevel: scope.securityLevel,
            protocolName: protocolID.name,
            counterparty: scope.counterparty
        )
        self.expiry = expiry
    }

    public func isExpired(at unixTime: UInt64) -> Bool {
        expiry != 0 && expiry < unixTime
    }
}

/// A DBAP grant.
public struct DBAPPermissionToken: Hashable, Sendable {
    public let scope: BasketPermissionScope
    public let expiry: UInt64

    public init(scope: BasketPermissionScope, expiry: UInt64) throws {
        guard !scope.basket.isEmpty else { throw PermissionTokenError.emptyValue(field: "basketName") }
        self.scope = scope
        self.expiry = expiry
    }

    public func isExpired(at unixTime: UInt64) -> Bool {
        expiry != 0 && expiry < unixTime
    }
}

/// A DCAP grant. Its field set is canonicalized by `CertificatePermissionScope`.
public struct DCAPPermissionToken: Hashable, Sendable {
    public let scope: CertificatePermissionScope
    public let expiry: UInt64

    public init(scope: CertificatePermissionScope, expiry: UInt64) throws {
        guard !scope.certificateType.isEmpty else {
            throw PermissionTokenError.emptyValue(field: "certType")
        }
        guard scope.verifier != .selfCounterparty, scope.verifier != .anyone else {
            throw PermissionTokenError.invalidVerifier
        }
        self.scope = CertificatePermissionScope(
            originator: scope.originator,
            privileged: scope.privileged,
            certificateType: scope.certificateType,
            verifier: scope.verifier,
            fields: scope.fields
        )
        self.expiry = expiry
    }

    public func isExpired(at unixTime: UInt64) -> Bool {
        expiry != 0 && expiry < unixTime
    }

    /// BRC-116 DCAP lookup uses subset semantics.
    public func covers(fields requestedFields: [String]) -> Bool {
        Set(requestedFields).isSubset(of: Set(scope.fields))
    }
}

/// A DSAP monthly spending grant. BRC-116 deliberately gives this token no expiry field.
public struct DSAPPermissionToken: Hashable, Sendable {
    public let scope: SpendingPermissionScope
    public let authorizedAmount: UInt64

    public init(scope: SpendingPermissionScope, authorizedAmount: UInt64) {
        self.scope = scope
        self.authorizedAmount = authorizedAmount
    }
}

/// A strictly typed BRC-116 permission token.
public enum PermissionToken: Hashable, Sendable {
    case dpacp(DPACPPermissionToken)
    case dbap(DBAPPermissionToken)
    case dcap(DCAPPermissionToken)
    case dsap(DSAPPermissionToken)

    public var basket: PermissionTokenBasket {
        switch self {
        case .dpacp: .protocolPermission
        case .dbap: .basketAccess
        case .dcap: .certificateAccess
        case .dsap: .spendingAuthorization
        }
    }

    public var originator: CanonicalOriginator {
        switch self {
        case .dpacp(let token): token.scope.originator
        case .dbap(let token): token.scope.originator
        case .dcap(let token): token.scope.originator
        case .dsap(let token): token.scope.originator
        }
    }

    public func isExpired(at unixTime: UInt64) -> Bool {
        switch self {
        case .dpacp(let token): token.isExpired(at: unixTime)
        case .dbap(let token): token.isExpired(at: unixTime)
        case .dcap(let token): token.isExpired(at: unixTime)
        case .dsap: false
        }
    }
}

/// Strict structural and semantic failures while decoding a BRC-116 token.
public enum PermissionTokenError: Error, Equatable, Sendable {
    case invalidPushDrop
    case unexpectedFieldCount(actual: Int, expected: Int)
    case invalidSignature
    case lockingPublicKeyMismatch
    case decryptionFailed(fieldIndex: Int)
    case invalidUTF8(field: String)
    case invalidUnsignedInteger(field: String)
    case invalidBoolean(field: String)
    case invalidOriginator
    case invalidProtocolSecurityLevel(String)
    case invalidProtocolName
    case invalidCounterparty
    case invalidVerifier
    case invalidCertificateFieldsJSON
    case emptyValue(field: String)
}
