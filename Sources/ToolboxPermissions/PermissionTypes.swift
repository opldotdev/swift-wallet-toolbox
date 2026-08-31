import BSVKeys
import BSVWallet

/// A normalized application originator used in every persisted or ephemeral permission identity.
public struct CanonicalOriginator: Hashable, Codable, Sendable {
    public let rawValue: String

    public init(_ value: String) throws {
        let normalized = OriginatorCanonicalizer.normalize(value)
        guard !normalized.isEmpty else { throw PermissionPolicyError.missingOriginator }
        self.rawValue = normalized
    }

    public init(from decoder: Decoder) throws {
        try self.init(decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// Canonical BRC-43 counterparty text (`self`, `anyone`, or lowercase compressed-key hex).
public struct CanonicalCounterparty: Hashable, Codable, Sendable {
    public let rawValue: String

    public static let selfCounterparty = CanonicalCounterparty(canonicalValue: "self")
    public static let anyone = CanonicalCounterparty(canonicalValue: "anyone")

    private init(canonicalValue: String) {
        self.rawValue = canonicalValue
    }

    public init(_ rawValue: String) throws {
        let normalized = rawValue.lowercased()
        guard normalized == "self" || normalized == "anyone" || Self.isCompressedPublicKey(normalized) else {
            throw PermissionPolicyError.invalidCounterparty(rawValue)
        }
        self.rawValue = normalized
    }

    public init(from decoder: Decoder) throws {
        try self.init(decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public init(_ value: WalletCounterparty) {
        switch value {
        case .self:
            self = .selfCounterparty
        case .anyone:
            self = .anyone
        case .publicKey(let key):
            self.init(canonicalValue: Self.lowercaseHex(key.compressedBytes))
        }
    }

    public init(publicKey: PublicKey) {
        self.init(canonicalValue: Self.lowercaseHex(publicKey.compressedBytes))
    }

    private static func isCompressedPublicKey(_ value: String) -> Bool {
        guard value.count == 66,
              value.hasPrefix("02") || value.hasPrefix("03") else { return false }
        var bytes = [UInt8]()
        bytes.reserveCapacity(33)
        let characters = Array(value.utf8)
        for index in stride(from: 0, to: characters.count, by: 2) {
            guard let high = hexNibble(characters[index]),
                  let low = hexNibble(characters[index + 1]) else { return false }
            bytes.append((high << 4) | low)
        }
        return (try? PublicKey(bytes)) != nil
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48...57: return byte - 48
        case 97...102: return byte - 87
        default: return nil
        }
    }

    private static func lowercaseHex(_ bytes: [UInt8]) -> String {
        let alphabet = Array("0123456789abcdef".utf8)
        var result = [UInt8]()
        result.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            result.append(alphabet[Int(byte >> 4)])
            result.append(alphabet[Int(byte & 0x0f)])
        }
        return String(decoding: result, as: UTF8.self)
    }
}

/// BRC-43 levels that actually produce a permission scope. Level 0 is intentionally absent.
public enum ProtocolPermissionLevel: UInt8, Hashable, Codable, Sendable {
    case application = 1
    case applicationAndCounterparty = 2

    public init(from decoder: Decoder) throws {
        let rawValue = try decoder.singleValueContainer().decode(UInt8.self)
        guard let value = Self(rawValue: rawValue) else {
            throw PermissionPolicyError.invalidProtocolSecurityLevel(rawValue)
        }
        self = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct ProtocolPermissionScope: Hashable, Codable, Sendable {
    public let originator: CanonicalOriginator
    public let privileged: Bool
    public let securityLevel: ProtocolPermissionLevel
    public let protocolName: String
    /// Nil for level 1. Level 2 retains `self`, `anyone`, or the concrete public key.
    public let counterparty: CanonicalCounterparty?

    public init(
        originator: CanonicalOriginator,
        privileged: Bool,
        securityLevel: ProtocolPermissionLevel,
        protocolName: String,
        counterparty: CanonicalCounterparty?
    ) throws {
        guard securityLevel != .applicationAndCounterparty || counterparty != nil else {
            throw PermissionPolicyError.missingLevelTwoCounterparty
        }
        self.originator = originator
        self.privileged = privileged
        self.securityLevel = securityLevel
        self.protocolName = protocolName
        self.counterparty = securityLevel == .application ? nil : counterparty
    }

    private enum CodingKeys: String, CodingKey {
        case originator, privileged, securityLevel, protocolName, counterparty
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            originator: container.decode(CanonicalOriginator.self, forKey: .originator),
            privileged: container.decode(Bool.self, forKey: .privileged),
            securityLevel: container.decode(ProtocolPermissionLevel.self, forKey: .securityLevel),
            protocolName: container.decode(String.self, forKey: .protocolName),
            counterparty: container.decodeIfPresent(CanonicalCounterparty.self, forKey: .counterparty)
        )
    }
}

public struct BasketPermissionScope: Hashable, Codable, Sendable {
    public let originator: CanonicalOriginator
    public let basket: String

    public init(originator: CanonicalOriginator, basket: String) {
        self.originator = originator
        self.basket = basket
    }
}

/// Exact requested certificate-disclosure identity. Fields are sorted and unique.
public struct CertificatePermissionScope: Hashable, Codable, Sendable {
    public let originator: CanonicalOriginator
    public let privileged: Bool
    public let certificateType: String
    public let verifier: CanonicalCounterparty
    public let fields: [String]

    public init(
        originator: CanonicalOriginator,
        privileged: Bool,
        certificateType: String,
        verifier: CanonicalCounterparty,
        fields: [String]
    ) {
        self.originator = originator
        self.privileged = privileged
        self.certificateType = certificateType
        self.verifier = verifier
        self.fields = Array(Set(fields)).sorted()
    }

    private enum CodingKeys: String, CodingKey {
        case originator, privileged, certificateType, verifier, fields
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            originator: try container.decode(CanonicalOriginator.self, forKey: .originator),
            privileged: try container.decode(Bool.self, forKey: .privileged),
            certificateType: try container.decode(String.self, forKey: .certificateType),
            verifier: try container.decode(CanonicalCounterparty.self, forKey: .verifier),
            fields: try container.decode([String].self, forKey: .fields)
        )
    }
}

public struct SpendingPermissionScope: Hashable, Codable, Sendable {
    public let originator: CanonicalOriginator

    public init(originator: CanonicalOriginator) {
        self.originator = originator
    }
}

/// Stable identities a repository can use as primary keys. No display text participates.
public enum PermissionScopeKey: Hashable, Codable, Sendable {
    case protocolAccess(ProtocolPermissionScope)
    case basketAccess(BasketPermissionScope)
    case certificateAccess(CertificatePermissionScope)
    case spendingAuthorization(SpendingPermissionScope)
}

public enum PermissionUsage: String, Hashable, Codable, Sendable {
    case publicKey
    case identityKey
    case encrypt
    case decrypt
    case hmac
    case signing
    case linkageRevelation
    case basketInsertion
    case basketListing
    case basketRemoval
    case actionLabelApplication
    case actionLabelListing
    case certificateAcquisition
    case certificateListing
    case certificateRelinquishment
    case certificateDisclosure
    case identityResolution
}

public enum MissingPermissionBehavior: String, Hashable, Codable, Sendable {
    case promptUser
    case denyWithoutPrompt
}

public struct PermissionRequirement: Hashable, Codable, Sendable {
    public let scope: PermissionScopeKey
    public let usage: PermissionUsage
    public let whenMissing: MissingPermissionBehavior

    public init(
        scope: PermissionScopeKey,
        usage: PermissionUsage,
        whenMissing: MissingPermissionBehavior
    ) {
        self.scope = scope
        self.usage = usage
        self.whenMissing = whenMissing
    }
}

/// Data required to compute authoritative net spend after `createAction` returns its transaction.
/// Descriptions are deliberately absent: they are display-only and cannot change authorization.
public struct SpendingAuthorizationSeed: Hashable, Codable, Sendable {
    public struct DeclaredOutput: Hashable, Codable, Sendable {
        public let satoshis: UInt64
        public init(satoshis: UInt64) { self.satoshis = satoshis }
    }

    public let scope: SpendingPermissionScope
    public let inputOutpoints: [String]
    public let outputs: [DeclaredOutput]

    public init(
        scope: SpendingPermissionScope,
        inputOutpoints: [String],
        outputs: [DeclaredOutput]
    ) {
        self.scope = scope
        self.inputOutpoints = inputOutpoints
        self.outputs = outputs
    }
}

public struct PermissionAuthorizationPlan: Hashable, Codable, Sendable {
    public let requirements: [PermissionRequirement]
    public let spending: SpendingAuthorizationSeed?

    public init(requirements: [PermissionRequirement], spending: SpendingAuthorizationSeed? = nil) {
        var seen = Set<PermissionRequirement>()
        self.requirements = requirements.filter { seen.insert($0).inserted }
        self.spending = spending
    }

    private enum CodingKeys: String, CodingKey { case requirements, spending }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            requirements: try container.decode([PermissionRequirement].self, forKey: .requirements),
            spending: try container.decodeIfPresent(SpendingAuthorizationSeed.self, forKey: .spending)
        )
    }
}

public enum PermissionPolicyRejection: Error, Hashable, Codable, Sendable {
    case missingOriginator
    case reservedProtocol(String)
    case reservedBasket(String)
    case reservedLabel(String)
    case unsupportedPermissionScheme(kind: String, scheme: String)
    case unsupportedSecurityLevel(UInt8)
    case invalidActionTimeLabel(String)
    case unsupportedMethod(String)
}

public enum PermissionDecision: Hashable, Codable, Sendable {
    /// Safe before wallet authentication. These calls never prompt.
    case bootstrapNoPrompt
    /// No BRC-116 scope is needed, but the host must require an authenticated wallet session.
    case authenticatedPassThrough
    /// The configured admin originator bypasses application permission checks.
    case adminPassThrough
    case authorizationRequired(PermissionAuthorizationPlan)
    case denied(PermissionPolicyRejection)
}

/// Human-provided text is isolated from `PermissionDecision`, `Hashable`, and repository keys.
public struct PermissionDisplayMetadata: Sendable {
    public struct LineItem: Sendable {
        public enum Kind: Sendable { case input, output }
        public let kind: Kind
        public let description: String
        public let satoshis: UInt64?

        public init(kind: Kind, description: String, satoshis: UInt64?) {
            self.kind = kind
            self.description = description
            self.satoshis = satoshis
        }
    }

    public let reason: String?
    public let spendingLineItems: [LineItem]

    public init(reason: String? = nil, spendingLineItems: [LineItem] = []) {
        self.reason = reason
        self.spendingLineItems = spendingLineItems
    }
}

public struct PermissionClassification: Sendable {
    public let decision: PermissionDecision
    public let display: PermissionDisplayMetadata

    public init(decision: PermissionDecision, display: PermissionDisplayMetadata = .init()) {
        self.decision = decision
        self.display = display
    }
}

public enum PermissionPolicyError: Error, Equatable, Sendable {
    case missingOriginator
    case invalidCounterparty(String)
    case invalidProtocolSecurityLevel(UInt8)
    case missingLevelTwoCounterparty
}
