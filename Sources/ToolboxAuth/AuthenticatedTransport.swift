import Foundation

/// An HTTP transport that authenticates both ends with BRC-103.
///
/// This is the Swift counterpart of the TypeScript `AuthFetch`. Remote storage will not answer
/// without it, so nothing above this layer works until it does.
///
/// The SDK carries BRC-103's protocol and value types but drives no transport with them. That is
/// what this module adds: the live handshake, the session it produces, and the signing of each
/// subsequent request.
public protocol AuthenticatedTransport: Sendable {
    /// Sends a request to an authenticated peer and returns its response body.
    ///
    /// The identity used is the wallet's own, which is why the storage client takes a wallet
    /// rather than a key: authenticating as the user is the whole point.
    func send(to url: URL, body: [UInt8], headers: [String: String]) async throws -> [UInt8]
}

public enum AuthError: Error, Equatable, Sendable {
    case notImplemented(String)
    case handshakeFailed(String)
    case peerRejected(String)
    case responseNotSigned
}
