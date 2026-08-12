import Foundation
import BSVAuth
import BSVKeys

/// One authenticated conversation with one peer.
///
/// An actor because a session is mutable shared state with a strict order: the handshake happens
/// once, and every later request depends on it having finished. Two requests racing on a fresh
/// session must not both start a handshake — one authenticates and the other waits.
///
/// The sequence, which is the whole of BRC-103 over HTTP:
///
/// 1. Send an initial request to `/.well-known/auth` naming our identity and a nonce.
/// 2. The peer replies with its identity, its nonce, and a signature over ours.
/// 3. Feed that to the authenticator, which verifies the signature and opens the session.
/// 4. Wrap each real request in a signed general message and send it to its own path.
/// 5. Verify the reply is signed for our request before returning a single byte of it.
///
/// Step 5 is the one worth stating plainly: a response that does not authenticate is discarded,
/// never returned with a warning. A caller cannot be expected to check.
public actor AuthenticatedSession: AuthenticatedTransport {
    private let baseURL: URL
    private let transport: any HTTPTransport
    private let authenticator: PeerAuthenticator
    private let expectedPeer: PublicKey?

    private var sessionID: AuthSessionID?
    /// Set while a handshake is running, so a second caller waits for the first rather than
    /// starting its own.
    private var handshake: Task<AuthSessionID, Error>?

    public init(
        baseURL: URL,
        wallet: any AuthenticationWallet,
        transport: any HTTPTransport = URLSessionHTTPTransport(),
        expectedPeer: PublicKey? = nil
    ) {
        self.baseURL = baseURL
        self.transport = transport
        self.authenticator = PeerAuthenticator(wallet: wallet)
        self.expectedPeer = expectedPeer
    }

    // MARK: - Sending

    public func send(
        method: String, path: String, query: String? = nil,
        headers: [String: String] = [:], body: [UInt8]? = nil
    ) async throws -> AuthenticatedResponse {
        do {
            return try await attemptSend(
                method: method, path: path, query: query, headers: headers, body: body
            )
        } catch AuthTransportError.sessionExpired {
            // The SDK evicts a session at its message limit. One controlled re-handshake recovers
            // rather than failing a call the peer would have answered. A second failure is real.
            forgetSession()
            return try await attemptSend(
                method: method, path: path, query: query, headers: headers, body: body
            )
        }
    }

    private func attemptSend(
        method: String, path: String, query: String?,
        headers: [String: String], body: [UInt8]?
    ) async throws -> AuthenticatedResponse {
        let session = try await establishedSession()
        let requestID = randomRequestID()

        let inner = try BRC104Request(
            requestID: requestID, method: method, path: path, query: query,
            headers: headers.map { BRC104Header(name: $0.key, value: $0.value) }, body: body
        )
        let payload = try BRC104Codec.encode(inner)

        let message: AuthMessage
        do {
            guard case .send(let produced) = try await authenticator.makeGeneralMessage(
                payload: payload, using: session
            ) else {
                throw AuthTransportError.handshakeFailed(
                    "the authenticator produced no message to send"
                )
            }
            message = produced
        } catch let error where isMissingSession(error) {
            throw AuthTransportError.sessionExpired
        }

        let frame = try BRC104HTTPFrameCodec.encodeRequest(message)
        let response = try await transport.send(
            HTTPRequest(
                method: frame.method,
                url: url(forPath: frame.path, query: frame.query),
                headers: Dictionary(
                    frame.headers.map { ($0.name, $0.value) }, uniquingKeysWith: { _, last in last }
                ),
                body: frame.body
            )
        )

        return try await unwrap(response, expecting: requestID)
    }

    private func forgetSession() {
        sessionID = nil
    }

    /// True when the authenticator refused because the session is gone rather than because the
    /// request was bad. The distinction decides whether a re-handshake can recover.
    private nonisolated func isMissingSession(_ error: Error) -> Bool {
        "\(error)".localizedCaseInsensitiveContains("session")
    }

    // MARK: - Handshake

    /// Returns the open session, running the handshake if there is not one yet.
    ///
    /// The in-flight task is held so concurrent callers join the same handshake. Without it, the
    /// first two requests on a cold session would each open one, and the peer would see two
    /// identities where there is one.
    private func establishedSession() async throws -> AuthSessionID {
        if let sessionID { return sessionID }
        if let handshake { return try await handshake.value }

        let task = Task { try await performHandshake() }
        handshake = task
        defer { handshake = nil }

        let session = try await task.value
        sessionID = session
        return session
    }

    private func performHandshake() async throws -> AuthSessionID {
        let (session, actions) = try await authenticator.beginAuthentication(with: expectedPeer)
        guard case .send(let request) = actions.first else {
            throw AuthTransportError.handshakeFailed("the authenticator opened no request")
        }

        let response = try await transport.send(
            HTTPRequest(
                method: "POST",
                url: url(forPath: BRC104HTTPHeaderName.handshakePath, query: nil),
                headers: ["Content-Type": "application/json"],
                body: try AuthMessageCodec.encode(request)
            )
        )
        guard (200..<300).contains(response.statusCode) else {
            throw AuthTransportError.handshakeFailed("the peer answered \(response.statusCode)")
        }

        let reply: AuthMessage
        do {
            reply = try AuthMessageCodec.decode(response.body)
        } catch {
            throw AuthTransportError.handshakeFailed("the peer's reply could not be read")
        }
        // Verifying the reply is the authenticator's job, and it throws when the signature does
        // not cover our nonce. Reaching the next line means the peer holds the key it claims.
        _ = try await authenticator.receive(reply)

        guard await authenticator.session(session) != nil else {
            throw AuthTransportError.handshakeFailed("the peer's reply did not open a session")
        }
        return session
    }

    // MARK: - Unwrapping

    /// Turns a signed reply back into the response the caller asked for.
    ///
    /// Anything that is not a delivered message for this exact request is refused. A peer that
    /// returns an unsigned body, or a body for a different request, has failed — and returning it
    /// anyway would defeat the point of every step above.
    private func unwrap(
        _ response: HTTPResponse, expecting requestID: [UInt8]
    ) async throws -> AuthenticatedResponse {
        let frame = try BRC104HTTPResponseFrame(
            status: response.statusCode,
            headers: response.headers.map { BRC104Header(name: $0.key, value: $0.value) },
            body: response.body
        )

        let message: AuthMessage
        do {
            message = try BRC104HTTPFrameCodec.decodeResponse(frame, expectedRequestID: requestID)
        } catch {
            // The underlying reason travels with it. "Not authenticated" alone cannot be acted
            // on; knowing which header or field failed can.
            throw AuthTransportError.responseNotAuthenticated(
                "the reply carried no valid auth frame: \(error)"
            )
        }

        let actions = try await authenticator.receive(message)
        guard case .deliver(let delivered)? = actions.first(where: {
            if case .deliver = $0 { return true }
            return false
        }) else {
            throw AuthTransportError.responseNotAuthenticated("the reply delivered no payload")
        }

        let inner = try BRC104Codec.decodeResponse(delivered.payload)
        try BRC104Codec.requireCorrelation(requestID: requestID, response: inner)

        return AuthenticatedResponse(
            statusCode: inner.status,
            headers: Dictionary(
                inner.headers.map { ($0.name, $0.value) }, uniquingKeysWith: { _, last in last }
            ),
            body: inner.body ?? []
        )
    }

    // MARK: - Helpers

    /// Builds the URL to send a frame to, without losing what the frame said.
    ///
    /// Built through `URLComponents` rather than `appendingPathComponent` because BRC-104 is
    /// precise about both halves and `URL` quietly is not: a path of `/` leaves `URL.path` empty,
    /// and `URL.query` drops the leading `?` the frame requires. Either loss makes a peer reject
    /// a frame that was correct when we built it.
    private func url(forPath path: String, query: String?) -> URL {
        guard var parts = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            return baseURL
        }
        // The frame's path is the whole request path from the host root, so it replaces the base
        // URL's path rather than extending it. Appending produced `https://host/api/api` when the
        // endpoint already had a path and the caller passed the same one.
        parts.path = path.hasPrefix("/") ? path : "/" + path
        if let query, !query.isEmpty {
            // The frame carries the `?`; `URLComponents` writes its own.
            parts.query = query.hasPrefix("?") ? String(query.dropFirst()) : query
        }
        return parts.url ?? baseURL
    }

    /// Thirty-two bytes, which is the length the framing requires.
    ///
    /// `SystemRandomNumberGenerator`, which is what `UInt8.random` uses, is cryptographically
    /// secure on every platform this package supports.
    private func randomRequestID() -> [UInt8] {
        (0..<32).map { _ in UInt8.random(in: .min ... .max) }
    }
}
