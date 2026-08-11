import Foundation

/// The chain-facing layer.
///
/// Each capability is a protocol with several providers behind it, tried in order. One provider
/// being down is not an outage, which is why these are not concrete types.
public protocol TransactionBroadcaster: Sendable {
    /// Submits a BEEF-encoded transaction and returns its identifier.
    func broadcast(beef: [UInt8]) async throws -> String
}

public protocol OutputStatusProvider: Sendable {
    func isSpent(txid: String, vout: UInt32) async throws -> Bool
}

public protocol ChainHeightProvider: Sendable {
    func currentHeight() async throws -> UInt32
}

public protocol ExchangeRateProvider: Sendable {
    /// United States dollars per whole bitcoin.
    func usdPerBSV() async throws -> Double
}

public enum ServiceError: Error, Equatable, Sendable {
    case notImplemented(String)
    /// Every provider in the chain failed. Carries each failure, because a single message would
    /// hide which provider is actually broken.
    case allProvidersFailed([String])
}
