import Foundation
import BSVAuth
import ToolboxCore

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

/// Which call an error belongs to: enough to find it in a server's log, and nothing that could
/// authenticate (no query, headers or body).
public struct AuthRequestContext: Equatable, Sendable {
    public let method: String
    public let host: String
    /// The request path, without its query.
    public let path: String

    public init(method: String, host: String, path: String) {
        self.method = method
        self.host = host
        self.path = path
    }
}

public enum AuthTransportError: Error, Equatable, Sendable, LocalizedError {
    case notImplemented(String)
    /// The peer never completed the handshake. Carries what it did instead.
    case handshakeFailed(String)
    /// The peer answered, but not in a form that proves it holds the key it claims. Never
    /// recoverable by retrying: an unauthenticated answer is not a slower authenticated one.
    case responseNotAuthenticated(String)
    /// The peer refused the request with an error status and no auth frame at all, as a gate
    /// in front of its auth middleware does. Carries the status and the start of the body, as
    /// TS `SimplifiedFetchTransport` reports them, so a caller can say what was refused, and the
    /// call it refused (`request`, set by ``AuthenticatedSession``; not part of `==`). The body is
    /// unauthenticated: read it to describe the failure, never to act on.
    case unauthenticatedReply(status: Int, body: [UInt8], request: AuthRequestContext? = nil)
    /// A reply arrived for a request other than the one being awaited.
    case requestMismatch
    case transportFailed(String)
    /// The authenticated session was evicted. Before the request reached the peer's application
    /// (no local session, or an unsigned 401) it is re-handshaken and resent, and this is thrown
    /// only once that budget is spent. When the peer signed a reply to the request for a session
    /// this side no longer holds, the request may have run, so it is thrown at once and the
    /// request is not resent: treat its outcome as unknown.
    case sessionExpired
    /// The peer is not the one expected. Raised only when a caller named the peer up front, which
    /// is the case worth failing loudly for.
    case unexpectedPeer
    /// The caller's query holds a `%` that is not a two-digit escape, so no URL can carry it as
    /// signed. Raised before anything is sent.
    case invalidQuery(String)

    /// The server's own short reason for an ``unauthenticatedReply(status:body:request:)``, when
    /// its body gave one (a JSON `message`, `description` or `error`, or short plain text).
    public var serverReason: String? {
        guard case .unauthenticatedReply(_, let body, _) = self else { return nil }
        return ErrorDetail.serverReason(body)
    }

    public var errorDescription: String? {
        switch self {
        case .sessionExpired:
            "Couldn't reconnect to the server. Try again."
        case .responseNotAuthenticated:
            "The server's reply could not be verified."
        case .unauthenticatedReply(let status, _, let request):
            Self.refusalText(status: status, host: request?.host, reason: serverReason)
        case .handshakeFailed:
            "Couldn't authenticate with the server. Try again."
        case .requestMismatch:
            "The server answered a different request."
        case .transportFailed:
            "Couldn't reach the server. Try again."
        case .notImplemented:
            "This operation is not available."
        case .unexpectedPeer:
            "Connected to an unexpected server."
        case .invalidQuery:
            "The request could not be sent: its query is malformed."
        }
    }

    /// `request` is context for the log and does not take part in `==`, so an error built from
    /// a status and body alone still compares as before.
    public static func == (lhs: AuthTransportError, rhs: AuthTransportError) -> Bool {
        switch (lhs, rhs) {
        case (.notImplemented(let a), .notImplemented(let b)),
             (.handshakeFailed(let a), .handshakeFailed(let b)),
             (.responseNotAuthenticated(let a), .responseNotAuthenticated(let b)),
             (.transportFailed(let a), .transportFailed(let b)),
             (.invalidQuery(let a), .invalidQuery(let b)):
            return a == b
        case (.unauthenticatedReply(let s1, let b1, _), .unauthenticatedReply(let s2, let b2, _)):
            return s1 == s2 && b1 == b2
        case (.requestMismatch, .requestMismatch), (.sessionExpired, .sessionExpired),
             (.unexpectedPeer, .unexpectedPeer):
            return true
        default:
            return false
        }
    }

    static func refusalText(status: Int, host: String?, reason: String?) -> String {
        let server = host.map { "The server at \($0)" } ?? "The server"
        let verb = status >= 500 ? "could not handle" : "refused"
        if let reason {
            return "\(server) \(verb) the request (HTTP \(status)): \(reason)"
        }
        return status >= 500
            ? "\(server) \(verb) the request (HTTP \(status)). Try again later."
            : "\(server) \(verb) the request (HTTP \(status))."
    }
}

extension AuthTransportError: CustomDebugStringConvertible {
    /// The full detail for the log: the call, its status and the start of the body.
    public var debugDescription: String {
        switch self {
        case .unauthenticatedReply(let status, let body, let request):
            let call = request.map {
                "\($0.method) \(ErrorDetail.hostPath(host: $0.host, path: $0.path))"
            } ?? "unknown request"
            return "AuthTransportError.unauthenticatedReply: \(call) answered HTTP \(status) "
                + "with no auth frame; body: \(ErrorDetail.bodyPreview(body))"
        case .notImplemented(let detail): return "AuthTransportError.notImplemented: \(detail)"
        case .handshakeFailed(let detail): return "AuthTransportError.handshakeFailed: \(detail)"
        case .responseNotAuthenticated(let detail):
            return "AuthTransportError.responseNotAuthenticated: \(detail)"
        case .requestMismatch: return "AuthTransportError.requestMismatch"
        case .transportFailed(let detail): return "AuthTransportError.transportFailed: \(detail)"
        case .sessionExpired: return "AuthTransportError.sessionExpired"
        case .unexpectedPeer: return "AuthTransportError.unexpectedPeer"
        case .invalidQuery(let query):
            return "AuthTransportError.invalidQuery: \(query.count) characters"
        }
    }
}
