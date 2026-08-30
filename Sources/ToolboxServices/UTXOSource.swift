import BSVKeys
import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Where spendable outputs come from when they are not in BRC-100 storage.
///
/// Storage answers `listOutputs` for a wallet it tracks. This is the other case: reading the chain
/// directly for an address the wallet did not create through storage — a legacy key being swept, or
/// a balance check against a public explorer. The provider is chosen by the wallet's settings, the
/// same preference that picks the block explorer.
///
/// Every returned output carries its **locking script**, because a signature commits to the script
/// and the amount together — an output whose script the signer does not have cannot be spent.
/// Providers differ in whether they include it: an indexer returns it inline, while WhatsOnChain
/// returns only the outpoint and amount. Each adapter's job is to deliver a script regardless, so
/// the caller never has to know which kind of provider it holds.
public protocol UTXOSource: Sendable {
    /// The spendable outputs at an address.
    func spendableOutputs(forAddress address: String) async throws -> [SpendableUTXO]
}

/// One spendable output, with everything needed to spend it.
public struct SpendableUTXO: Equatable, Sendable {
    public let txid: String
    public let vout: UInt32
    public let satoshis: UInt64
    public let lockingScript: [UInt8]

    public init(txid: String, vout: UInt32, satoshis: UInt64, lockingScript: [UInt8]) {
        self.txid = txid
        self.vout = vout
        self.satoshis = satoshis
        self.lockingScript = lockingScript
    }
}

public enum UTXOSourceError: Error, Equatable, Sendable {
    /// The provider's response could not be read as this protocol.
    case unreadableResponse(provider: String)
    /// The output's locking script could not be established — the one thing that makes it
    /// spendable. Never recoverable by retrying.
    case missingScript(txid: String, vout: UInt32)
    case httpFailure(provider: String, statusCode: Int)
}

/// A bare HTTP GET, injectable so a provider can be tested without a network.
public protocol HTTPGet: Sendable {
    func get(_ url: URL) async throws -> (status: Int, body: [UInt8])
}

/// The real GET, over `URLSession`, with a cap so a hostile or broken endpoint cannot stream
/// without bound.
public struct URLSessionHTTPGet: HTTPGet {
    private let session: URLSession
    private let maximumResponseBytes: Int

    public init(session: URLSession = .shared, maximumResponseBytes: Int = 16 << 20) {
        self.session = session
        self.maximumResponseBytes = maximumResponseBytes
    }

    public func get(_ url: URL) async throws -> (status: Int, body: [UInt8]) {
#if canImport(Darwin)
        let (stream, response) = try await session.bytes(from: url)
#else
        let (data, response) = try await session.data(from: url)
#endif
        guard let http = response as? HTTPURLResponse else {
            throw UTXOSourceError.httpFailure(provider: url.host ?? "http", statusCode: 0)
        }
#if canImport(Darwin)
        var bytes: [UInt8] = []
        for try await byte in stream {
            bytes.append(byte)
            if bytes.count > maximumResponseBytes {
                throw UTXOSourceError.httpFailure(
                    provider: url.host ?? "http", statusCode: http.statusCode
                )
            }
        }
#else
        guard data.count <= maximumResponseBytes else {
            throw UTXOSourceError.httpFailure(
                provider: url.host ?? "http", statusCode: http.statusCode
            )
        }
        let bytes = Array(data)
#endif
        return (http.statusCode, bytes)
    }
}
