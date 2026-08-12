import Foundation

/// An output as storage returned it.
///
/// Storage returns more outputs than the caller asked for: the caller's own come first, then at
/// most one commission, then change. Which is which is not cosmetic — it decides whether the
/// output's locking script may be trusted at all.
public struct StorageActionOutput: Equatable, Sendable {
    /// Who put this output in the transaction.
    public enum ProvidedBy: String, Equatable, Sendable {
        /// The caller asked for it. Its script must match the request exactly.
        case you
        /// Storage added it. Only change and commission are acceptable reasons.
        case storage
        /// Both, for an output the caller asked for and storage completed.
        case youAndStorage = "you-and-storage"
    }

    /// Why storage added an output it was not asked for.
    public enum Purpose: String, Equatable, Sendable {
        /// Money coming back to the wallet. Its script is re-derived from our own keys and
        /// storage's copy is ignored, so it cannot pay anybody else.
        case change
        case storageCommission = "storage-commission"
        /// The label an older store uses for a commission. Accepted so the check works across
        /// versions rather than failing open on one of them.
        case serviceCharge = "service-charge"
    }

    public let vout: UInt32
    public let satoshis: UInt64
    public let lockingScript: [UInt8]
    public let providedBy: ProvidedBy?
    public let purpose: Purpose?
    /// Present on change, and needed to re-derive the script that actually gets used.
    public let derivationSuffix: String?

    public init(
        vout: UInt32, satoshis: UInt64, lockingScript: [UInt8],
        providedBy: ProvidedBy?, purpose: Purpose?, derivationSuffix: String?
    ) {
        self.vout = vout
        self.satoshis = satoshis
        self.lockingScript = lockingScript
        self.providedBy = providedBy
        self.purpose = purpose
        self.derivationSuffix = derivationSuffix
    }

    public var isChange: Bool {
        providedBy == .storage && purpose == .change
    }

    public var isCommission: Bool {
        providedBy == .storage && (purpose == .storageCommission || purpose == .serviceCharge)
    }
}
