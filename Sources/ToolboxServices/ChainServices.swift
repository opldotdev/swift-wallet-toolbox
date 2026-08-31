import Foundation
import BSVSPV

/// The two chain queries exposed by BRC-100.
///
/// Keeping this capability smaller than `WalletServices` lets a wallet host inject a block-header
/// client without also manufacturing broadcast, exchange-rate, and UTXO services. Full toolbox
/// service implementations inherit this protocol and therefore remain directly injectable.
public protocol ChainInformationService: Sendable {
    func currentHeight() async throws -> UInt32
    func header(atHeight height: UInt32) async throws -> ChainBlockHeader
}

/// What the wallet needs to know about the chain.
///
/// The operations are the Go toolbox's `pkg/services` set, in Swift spelling. They are shaped for
/// a wallet rather than for a block explorer: `isUTXO` answers "can I spend this", not "tell me
/// about this output", because that is the question the action layer actually asks.
///
/// Each is answered by one of several providers tried in order — see `ServiceQueue`. A provider
/// being down is not an outage, which is why this is a protocol and not a concrete client.
///
/// **Provider clients belong to the SDK, not here.** `swift-sdk` already ships ARC, WhatsOnChain
/// broadcast and chain tracking, and a block-headers client, mirroring `go-sdk`'s
/// `transaction/broadcaster` and `transaction/chaintracker`. This module adapts and orders them.
/// It writes a new provider only where the SDK has none, and then the question to ask first is
/// whether the provider belongs upstream instead.
public protocol WalletServices: ChainInformationService, Sendable {
    /// The raw bytes of a transaction, by identifier.
    func rawTX(txid: String) async throws -> [UInt8]

    /// Submits a BEEF-encoded transaction set for broadcast.
    func postBEEF(_ beef: [UInt8], txids: [String]) async throws -> [BroadcastOutcome]

    /// The merkle path proving a transaction is in a block. Absent until it is mined.
    func merklePath(txid: String) async throws -> [UInt8]?

    func chainTipHeader() async throws -> ChainBlockHeader
    func header(forHash hash: String) async throws -> ChainBlockHeader

    /// Whether a merkle root is the real one for that height. This is the check that makes a
    /// proof worth having, so it is a first-class operation rather than a detail of proof code.
    func isValidRoot(_ root: [UInt8], atHeight height: UInt32) async throws -> Bool

    func statusForTXIDs(_ txids: [String]) async throws -> [TransactionStatusReport]

    /// Whether an output is still unspent, which is the only form of this question the action
    /// layer asks before selecting an input.
    func isUTXO(scriptHash: String, txid: String, vout: UInt32) async throws -> Bool

    func scriptHashHistory(_ scriptHash: String) async throws -> [ScriptHistoryEntry]

    /// United States dollars per whole bitcoin.
    func usdPerBSV() async throws -> Double
}

// MARK: - Results

public struct BroadcastOutcome: Equatable, Sendable {
    public let txid: String
    public let accepted: Bool
    /// The provider's own words when it refused. Kept because "rejected" alone cannot be acted on.
    public let detail: String?

    public init(txid: String, accepted: Bool, detail: String?) {
        self.txid = txid
        self.accepted = accepted
        self.detail = detail
    }
}

/// A chain-positioned Bitcoin block-header record.
///
/// Some chain-tip APIs expose only a hash and Merkle root, so the original summary representation
/// remains supported. A record built from a `BlockHeader` additionally retains the exact canonical
/// 80 bytes required by BRC-100. Callers that require those bytes must check `serializedBytes`.
public struct ChainBlockHeader: Equatable, Sendable {
    public let height: UInt32
    private let content: Content

    private enum Content: Equatable, Sendable {
        case canonical(BlockHeader)
        case summary(hash: String, merkleRoot: [UInt8])
    }

    /// The parsed header when this record was created from canonical bytes.
    public var header: BlockHeader? {
        guard case .canonical(let header) = content else { return nil }
        return header
    }

    /// The display-order block hash. Canonical records compute it from their bytes; summary records
    /// preserve the provider's value exactly for source and behavior compatibility.
    public var hash: String {
        switch content {
        case .canonical(let header): header.hash.displayHex
        case .summary(let hash, _): hash
        }
    }

    /// The Merkle root in Bitcoin wire order for canonical records. Summary records preserve the
    /// provider's byte array exactly, matching the original model.
    public var merkleRoot: [UInt8] {
        switch content {
        case .canonical(let header): header.merkleRoot.bytes
        case .summary(_, let merkleRoot): merkleRoot
        }
    }

    /// The exact canonical 80-byte encoding, or `nil` when the provider supplied only a summary.
    public var serializedBytes: [UInt8]? { header?.serializedBytes }

    public init(height: UInt32, header: BlockHeader) {
        self.height = height
        content = .canonical(header)
    }

    /// The original summary initializer used by chain-tip providers that do not return 80 bytes.
    public init(height: UInt32, hash: String, merkleRoot: [UInt8]) {
        self.height = height
        content = .summary(hash: hash, merkleRoot: merkleRoot)
    }

    /// Parses exactly one canonical 80-byte block header.
    public init(height: UInt32, serializedBytes: [UInt8]) throws {
        self.init(height: height, header: try BlockHeader(bytes: serializedBytes))
    }

    /// Accepts a provider's claimed hash only when it identifies the supplied header.
    public init(height: UInt32, hash: String, header: BlockHeader) throws {
        let declaredHash: BlockHash
        do {
            declaredHash = try BlockHash(displayHex: hash)
        } catch {
            throw ChainBlockHeaderError.invalidHash(hash)
        }
        guard declaredHash == header.hash else {
            throw ChainBlockHeaderError.hashMismatch(
                declared: declaredHash.displayHex,
                computed: header.hash.displayHex
            )
        }
        self.init(height: height, header: header)
    }
}

public enum ChainBlockHeaderError: Error, Equatable, Sendable {
    case invalidHash(String)
    case hashMismatch(declared: String, computed: String)
}

public struct TransactionStatusReport: Equatable, Sendable {
    public enum Status: String, Equatable, Sendable {
        case unknown
        case mempool
        case mined
    }

    public let txid: String
    public let status: Status
    public let depth: UInt32?

    public init(txid: String, status: Status, depth: UInt32?) {
        self.txid = txid
        self.status = status
        self.depth = depth
    }
}

public struct ScriptHistoryEntry: Equatable, Sendable {
    public let txid: String
    public let height: UInt32?

    public init(txid: String, height: UInt32?) {
        self.txid = txid
        self.height = height
    }
}

public enum ServiceError: Error, Equatable, Sendable {
    case notImplemented(String)
    /// Every provider in the chain failed. Carries each failure by provider name, because one
    /// message would hide which provider is actually broken.
    case allProvidersFailed([(provider: String, reason: String)])

    public static func == (lhs: ServiceError, rhs: ServiceError) -> Bool {
        switch (lhs, rhs) {
        case (.notImplemented(let a), .notImplemented(let b)):
            a == b
        case (.allProvidersFailed(let a), .allProvidersFailed(let b)):
            a.map(\.provider) == b.map(\.provider) && a.map(\.reason) == b.map(\.reason)
        default:
            false
        }
    }
}
