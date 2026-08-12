import Foundation
import BSVAuth

/// An HTTP client where both ends have proved who they are.
///
/// This is the Swift counterpart of the TypeScript `AuthFetch`. Remote storage will not answer
/// without it, so nothing above this layer works until it does.
///
/// The SDK supplies the parts: `PeerAuthenticator` holds the BRC-103 state machine, and
/// `BRC104HTTPFraming` turns a message into HTTP headers and back. What it does not supply is the
/// loop that carries them — send the challenge, read the reply, feed it back, then send the real
/// request inside a signed envelope. That loop is this module.
///
/// Neither the Go toolbox nor the TypeScript one has a Swift-shaped answer to copy here: Go's
/// storage server calls its own `/.well-known/auth` handler a workaround and does not implement
/// mutual authentication at all. This is the one place in the toolbox where we are first.
public protocol AuthenticatedTransport: Sendable {
    /// Sends a request to an authenticated peer and returns its response.
    ///
    /// The identity used is the wallet's own, which is why a session is built from a wallet rather
    /// than from a key: authenticating *as the user* is the whole point. Storage decides which
    /// records to hand back from the identity that asked.
    func send(
        method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?
    ) async throws -> AuthenticatedResponse
}

public struct AuthenticatedResponse: Equatable, Sendable {
    public let statusCode: Int
    public let headers: [String: String]
    public let body: [UInt8]

    public init(statusCode: Int, headers: [String: String], body: [UInt8]) {
        self.statusCode = statusCode
        self.headers = headers
        self.body = body
    }
}

public enum AuthTransportError: Error, Equatable, Sendable {
    case notImplemented(String)
    /// The peer never completed the handshake. Carries what it did instead.
    case handshakeFailed(String)
    /// The peer answered, but not in a form that proves it holds the key it claims. Never
    /// recoverable by retrying: an unauthenticated answer is not a slower authenticated one.
    case responseNotAuthenticated(String)
    /// A reply arrived for a request other than the one being awaited.
    case requestMismatch
    case transportFailed(String)
    /// The authenticated session was evicted by the peer. Recoverable by one re-handshake.
    case sessionExpired
    /// The peer is not the one expected. Raised only when a caller named the peer up front, which
    /// is the case worth failing loudly for.
    case unexpectedPeer
}
