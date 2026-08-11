import Foundation

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
public protocol WalletServices: Sendable {
    /// The raw bytes of a transaction, by identifier.
    func rawTX(txid: String) async throws -> [UInt8]

    /// Submits a BEEF-encoded transaction set for broadcast.
    func postBEEF(_ beef: [UInt8], txids: [String]) async throws -> [BroadcastOutcome]

    /// The merkle path proving a transaction is in a block. Absent until it is mined.
    func merklePath(txid: String) async throws -> [UInt8]?

    func currentHeight() async throws -> UInt32
    func chainTipHeader() async throws -> ChainBlockHeader
    func header(atHeight height: UInt32) async throws -> ChainBlockHeader
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

public struct ChainBlockHeader: Equatable, Sendable {
    public let height: UInt32
    public let hash: String
    public let merkleRoot: [UInt8]

    public init(height: UInt32, hash: String, merkleRoot: [UInt8]) {
        self.height = height
        self.hash = hash
        self.merkleRoot = merkleRoot
    }
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
