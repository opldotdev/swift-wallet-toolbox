import Foundation
import BSVWallet

/// BRC-177: a `noSend` action that storage can revoke on its own once it expires.
///
/// A `noSend` transaction is signed and handed to someone else to broadcast. Without an expiry the
/// inputs it spends stay reserved forever if they never do. BRC-177 has the action spend one extra
/// input, an anchor output funded just for it, and leaves storage holding a signed reclaim of that
/// anchor. Broadcasting the reclaim after the deadline double-spends the anchor, which invalidates
/// the handed-off transaction and frees everything else it spent.
///
/// The label `p nosend expiry …` asks for this. It is a client protocol, not a storage option:
/// storage's `createAction` records the label and nothing more, so a client that only forwards it
/// gets an ordinary, never-expiring `noSend` action. See `NoSendExpiryAction` in `ToolboxActions`.
public enum NoSendExpiry {
    public static let labelPrefix = "p nosend "
    public static let fundingLabel = "admin brc177 funding"

    /// The deadline a protected action carries.
    public enum Expiry: Equatable, Sendable {
        case never
        case seconds(UInt64)
        case timestamp(UInt64)
        case blockHeight(UInt64)

        public var mode: String {
            switch self {
            case .never: "never"
            case .seconds: "seconds"
            case .timestamp: "timestamp"
            case .blockHeight: "blockheight"
            }
        }

        public var label: String {
            switch self {
            case .never: "p nosend expiry never"
            case .seconds(let value): "p nosend expiry seconds \(value)"
            case .timestamp(let value): "p nosend expiry timestamp \(value)"
            case .blockHeight(let value): "p nosend expiry blockheight \(value)"
            }
        }
    }

    /// Reads the expiry a label set asks for, or `nil` when none does.
    ///
    /// At most one label may start with `p nosend `, and it must be exactly one of the four forms
    /// with a canonical decimal value. Anything else is refused rather than ignored, because a
    /// label that looks like an expiry but is not one would leave the action unprotected silently.
    public static func parse(labels: [String]) throws -> Expiry? {
        let matching = labels.filter { $0.hasPrefix(labelPrefix) }
        guard let label = matching.first else { return nil }
        guard matching.count == 1 else {
            throw NoSendExpiryError.invalidLabel("more than one BRC-177 label")
        }
        let parts = label.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4, parts[0] == "p", parts[1] == "nosend", parts[2] == "expiry" else {
            throw NoSendExpiryError.invalidLabel(label)
        }
        if parts.count == 4, parts[3] == "never" { return .never }
        guard parts.count == 5, let value = canonicalInteger(parts[4]) else {
            throw NoSendExpiryError.invalidLabel(label)
        }
        switch parts[3] {
        case "seconds":
            guard value > 0 else { throw NoSendExpiryError.invalidLabel(label) }
            return .seconds(value)
        case "timestamp": return .timestamp(value)
        case "blockheight": return .blockHeight(value)
        default: throw NoSendExpiryError.invalidLabel(label)
        }
    }

    /// A decimal with no sign, no leading zero, and no more than 2^53 - 1, which is the range the
    /// reference reads as an exact JavaScript number.
    private static func canonicalInteger(_ text: String) -> UInt64? {
        guard !text.isEmpty, text.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              text == "0" || !text.hasPrefix("0"),
              let value = UInt64(text), value <= 9_007_199_254_740_991 else { return nil }
        return value
    }
}

public enum NoSendExpiryError: Error, Equatable, Sendable, LocalizedError {
    case invalidLabel(String)
    case unsupported
    case invalidRequest(String)
    case fundingFailed(String)
    case unexpectedAction(String)

    public var errorDescription: String? {
        switch self {
        case .invalidLabel(let label): "Invalid BRC-177 expiry label: \(label)"
        case .unsupported: "Active storage does not support BRC-177 noSend expiry"
        case .invalidRequest(let reason): "BRC-177 protected action: \(reason)"
        case .fundingFailed(let reason): "BRC-177 anchor funding failed: \(reason)"
        case .unexpectedAction(let reason): "BRC-177 storage returned an unexpected action: \(reason)"
        }
    }
}

/// What `prepareNoSendExpiry` returns: the funding action storage built for the anchor, and the
/// amounts it fixed for the anchor and its reclaim.
public struct NoSendExpiryPrepared: Equatable, Sendable {
    public let funding: StorageCreateActionResult
    public let anchorSatoshis: UInt64
    public let anchorVout: UInt32
    public let reclaimFee: UInt64
    public let reclaimSatoshis: UInt64

    public init(
        funding: StorageCreateActionResult, anchorSatoshis: UInt64, anchorVout: UInt32,
        reclaimFee: UInt64, reclaimSatoshis: UInt64
    ) {
        self.funding = funding
        self.anchorSatoshis = anchorSatoshis
        self.anchorVout = anchorVout
        self.reclaimFee = reclaimFee
        self.reclaimSatoshis = reclaimSatoshis
    }
}

/// What `activateNoSendExpiry` returns: the protected action itself, funded with the anchor as
/// its only storage-managed input.
public struct NoSendExpiryActivated: Equatable, Sendable {
    public let action: StorageCreateActionResult
    public let mode: String
    public let deadline: UInt64?
    public let anchorTxid: String
    public let anchorVout: UInt32

    public init(
        action: StorageCreateActionResult, mode: String, deadline: UInt64?,
        anchorTxid: String, anchorVout: UInt32
    ) {
        self.action = action
        self.mode = mode
        self.deadline = deadline
        self.anchorTxid = anchorTxid
        self.anchorVout = anchorVout
    }
}

/// The signed reclaim handed to storage by `armNoSendExpiry`.
public struct NoSendExpiryArm: Equatable, Sendable {
    public let reference: String
    public let reclaimTxid: String
    public let reclaimRawTx: [UInt8]
    public let reclaimDerivationPrefix: String
    public let reclaimDerivationSuffix: String
    public let reclaimSatoshis: UInt64

    public init(
        reference: String, reclaimTxid: String, reclaimRawTx: [UInt8],
        reclaimDerivationPrefix: String, reclaimDerivationSuffix: String, reclaimSatoshis: UInt64
    ) {
        self.reference = reference
        self.reclaimTxid = reclaimTxid
        self.reclaimRawTx = reclaimRawTx
        self.reclaimDerivationPrefix = reclaimDerivationPrefix
        self.reclaimDerivationSuffix = reclaimDerivationSuffix
        self.reclaimSatoshis = reclaimSatoshis
    }
}

/// The storage calls a BRC-177 protected action needs. `StorageClient` conforms.
public protocol NoSendExpiryStorage: Sendable {
    func supportsNoSendExpiry() async throws -> Bool
    func prepareNoSendExpiry(
        _ auth: AuthID, _ target: WalletCreateActionRequest
    ) async throws -> NoSendExpiryPrepared
    func activateNoSendExpiry(
        _ auth: AuthID, target: WalletCreateActionRequest, fundingReference: String,
        fundingTxid: String, anchorVout: UInt32
    ) async throws -> NoSendExpiryActivated
    func armNoSendExpiry(_ auth: AuthID, _ arm: NoSendExpiryArm) async throws
    func processAction(
        _ auth: AuthID, _ request: StorageProcessActionRequest
    ) async throws -> StorageProcessActionResult
    func abortAction(
        _ auth: AuthID, _ request: WalletAbortActionRequest
    ) async throws -> WalletAbortActionResult
}
