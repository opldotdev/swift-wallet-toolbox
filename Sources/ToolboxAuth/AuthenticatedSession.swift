import Foundation
import BSVAuth
import BSVCore
import BSVKeys
import ToolboxCore

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
    let baseURL: URL
    private let transport: any HTTPTransport
    private let authenticator: PeerAuthenticator
    private let expectedPeer: PublicKey?
    /// The wallet the session signs with. BRC-105 compares a payer's identity with it.
    let wallet: any AuthenticationWallet

    private var sessionID: AuthSessionID?
    /// Set while a handshake is running, so a second caller waits for the first rather than
    /// starting its own.
    private var handshake: Task<AuthSessionID, Error>?
    /// Held across the HTTP round-trip so a 401 retry cannot close the authenticator under a
    /// sibling still waiting for its reply. AuthFetch deletes the peer; Swift must not do that
    /// while another receive is in flight.
    private var sending = false
    private var sendWaiters: [CheckedContinuation<Void, Never>] = []

    /// AuthFetch sets `retryCounter ??= 3` after a stale session, then decrements before
    /// each recovery attempt. That is three recoveries after the first failure.
    static let sessionRecoveryRetries = 3

    /// TS `getBodyPreview` keeps the first 1024 bytes of an unauthenticated reply.
    static let unauthenticatedBodyPreviewBytes = 1024

    public init(
        baseURL: URL,
        wallet: any AuthenticationWallet,
        transport: any HTTPTransport = URLSessionHTTPTransport(),
        expectedPeer: PublicKey? = nil
    ) {
        self.init(
            baseURL: baseURL, wallet: wallet, transport: transport, expectedPeer: expectedPeer,
            authenticatorLimits: .standard
        )
    }

    /// `authenticatorLimits` bound the BRC-103 messages this side signs and reads. Tests use it
    /// to set a payload limit below `BRC104Limits.standard`'s, which the public initializer
    /// never does.
    init(
        baseURL: URL,
        wallet: any AuthenticationWallet,
        transport: any HTTPTransport,
        expectedPeer: PublicKey?,
        authenticatorLimits: AuthLimits
    ) {
        self.baseURL = baseURL
        self.transport = transport
        self.authenticator = PeerAuthenticator(wallet: wallet, limits: authenticatorLimits)
        self.expectedPeer = expectedPeer
        self.wallet = wallet
    }

    // MARK: - Sending

    public func send(
        method: String, path: String, query: String? = nil,
        headers: [String: String] = [:], body: [UInt8]? = nil
    ) async throws -> AuthenticatedResponse {
        do {
            return try await sendTrackingDelivery(
                method: method, path: path, query: query, headers: headers, body: body
            )
        } catch let error as RequestMayHaveRun {
            throw error.underlying
        }
    }

    /// ``send(method:path:query:headers:body:)``, but a failure after the request may have reached
    /// the peer's application comes wrapped in ``RequestMayHaveRun``. Any other error means the
    /// peer provably did not run the request, so a caller that must not run it twice may resend.
    func sendTrackingDelivery(
        method: String, path: String, query: String?,
        headers: [String: String], body: [UInt8]?
    ) async throws -> AuthenticatedResponse {
        await acquireSend()
        defer { releaseSend() }
        var remaining = Self.sessionRecoveryRetries
        while true {
            do {
                return try await attemptSend(
                    method: method, path: path, query: query, headers: headers, body: body
                )
            } catch is SignedReplySessionLost {
                // The peer signed a reply to this request, so it ran the request. Sending it again
                // could apply a non-idempotent call twice; the outcome is unknown to the caller.
                // AuthFetch resends here; this does not. The next send re-handshakes.
                await forgetSession()
                Self.log(
                    "\(Self.describe(requestContext(method: method, path: path))): the peer signed a "
                        + "reply for a session this side no longer holds; not resent, outcome unknown"
                )
                throw RequestMayHaveRun(underlying: AuthTransportError.sessionExpired)
            } catch AuthTransportError.sessionExpired {
                // AuthFetch retries `Session not found for nonce` and unsigned 401. Both reach
                // here only from before the peer ran the request. The send lock stays held so a sibling cannot receive against the
                // session we are about to drop.
                guard remaining > 0 else {
                    Self.log(
                        "\(Self.describe(requestContext(method: method, path: path))): the session "
                            + "expired again after \(Self.sessionRecoveryRetries) re-handshakes"
                    )
                    throw AuthTransportError.sessionExpired
                }
                remaining -= 1
                await forgetSession()
            }
        }
    }

    private func attemptSend(
        method: String, path: String, query: String?,
        headers: [String: String], body: [UInt8]?
    ) async throws -> AuthenticatedResponse {
        let query = try Self.wireQuery(query)
        let session = try await establishedSession()
        let requestID = randomRequestID()

        let inner = try BRC104Request(
            requestID: requestID, method: method, path: path, query: query,
            headers: headers.map { BRC104Header(name: $0.key, value: $0.value) }, body: body
        )
        let payload: [UInt8]
        do {
            payload = try BRC104Codec.encode(inner)
        } catch {
            Self.log(
                "\(Self.describe(requestContext(method: method, path: path))): the request could "
                    + "not be framed (\(body?.count ?? 0) body bytes): \(ErrorDetail.describe(error))"
            )
            throw error
        }

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
        } catch is CancellationError {
            throw CancellationError()
        } catch let error where isRecoverablePreSendSessionError(error) {
            // `makeGeneralMessage` throws `resourceLimit` both for a payload over the limit and
            // for a session that spent its message budget; only the second closes the session.
            // A new handshake cannot shrink the request, and AuthFetch does not retry a payload
            // refusal either, so the caller gets it. With the public initializer the codec above
            // refuses an oversized payload first, since both limits are
            // `AuthLimits.defaultPayloadBytes`; this guards against the two limits differing.
            if error as? AuthError == .resourceLimit, await authenticator.session(session) != nil {
                Self.log(
                    "\(Self.describe(requestContext(method: method, path: path))): the request "
                        + "(\(payload.count) bytes signed) is over the authenticated payload limit"
                )
                throw error
            }
            throw AuthTransportError.sessionExpired
        }

        let frame = try BRC104HTTPFrameCodec.encodeRequest(message)
        let context = requestContext(method: method, path: path)
        let response: HTTPResponse
        do {
            response = try await transport.send(
                HTTPRequest(
                    method: frame.method,
                    url: url(forPath: frame.path, query: frame.query),
                    headers: Dictionary(
                        frame.headers.map { ($0.name, $0.value) }, uniquingKeysWith: { _, last in last }
                    ),
                    body: frame.body
                )
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            Self.log("\(Self.describe(context)) did not get a reply: \(ErrorDetail.describe(error))")
            throw Self.neverLeft(error) ? error : RequestMayHaveRun(underlying: error)
        }

        do {
            return try await unwrap(response, expecting: requestID, for: context)
        } catch AuthTransportError.sessionExpired {
            // An unsigned 401: the peer's auth refused the request before its application ran.
            throw AuthTransportError.sessionExpired
        } catch let error as AuthTransportError {
            // An unsigned 4xx is a gate in front of the peer's auth refusing it; any other status
            // (a proxy's 502 or 504, a server error) may come after the application ran.
            if case .unauthenticatedReply(let status, _, _) = error, (400..<500).contains(status) {
                throw error
            }
            throw RequestMayHaveRun(underlying: error)
        } catch let error as SignedReplySessionLost {
            throw error
        } catch {
            throw RequestMayHaveRun(underlying: error)
        }
    }

    /// True for a transport failure that happens before any byte of the request is sent: the
    /// host could not be found or reached, there is no network, or TLS refused the connection.
    /// A connection lost or timed out later leaves open whether the peer ran the request.
    static func neverLeft(_ error: any Error) -> Bool {
        guard let error = error as? URLError else { return false }
        switch error.code {
        case .badURL, .unsupportedURL, .cannotFindHost, .cannotConnectToHost, .dnsLookupFailed,
             .notConnectedToInternet, .internationalRoamingOff, .callIsActive, .dataNotAllowed,
             .secureConnectionFailed, .serverCertificateHasBadDate, .serverCertificateUntrusted,
             .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid,
             .clientCertificateRejected, .clientCertificateRequired,
             .appTransportSecurityRequiresSecureConnection:
            return true
        default:
            return false
        }
    }

    /// The identity key of the peer this session is authenticated with, running the handshake
    /// if there is no session yet.
    func peerIdentityKey() async throws -> PublicKey {
        await acquireSend()
        defer { releaseSend() }
        let session = try await establishedSession()
        guard let peer = await authenticator.session(session)?.peer else {
            throw Self.logged(.handshakeFailed("the authenticated session names no peer"))
        }
        return peer
    }

    /// The call as the log and ``AuthTransportError/unauthenticatedReply(status:body:request:)``
    /// name it. The query is left out: it can carry a token.
    private nonisolated func requestContext(method: String, path: String) -> AuthRequestContext {
        AuthRequestContext(
            method: method,
            host: baseURL.host.map { host in baseURL.port.map { "\(host):\($0)" } ?? host } ?? "?",
            path: path.hasPrefix("/") ? path : "/" + path
        )
    }

    private static func describe(_ context: AuthRequestContext) -> String {
        "\(context.method) \(ErrorDetail.hostPath(host: context.host, path: context.path))"
    }

    private static func log(_ message: String) {
        ToolboxLog.error("ToolboxAuth", message)
    }

    private func forgetSession() async {
        if let id = sessionID {
            sessionID = nil
            await authenticator.close(id)
        } else {
            sessionID = nil
        }
    }

    /// True when the authenticator refused before any application request was sent, because the
    /// local session is gone, not because the request was bad. String-matching is not enough:
    /// `AuthError.notAuthenticated` describes itself as `notAuthenticated`, not `session`.
    private nonisolated func isRecoverablePreSendSessionError(_ error: Error) -> Bool {
        guard let authError = error as? AuthError else { return false }
        switch authError {
        case .notAuthenticated, .sessionNotFound, .resourceLimit:
            return true
        default:
            return false
        }
    }

    /// Leaves the cached session ID in place so the next send observes a stale authenticator.
    func testingCloseAuthenticatorSession() async {
        if let sessionID {
            await authenticator.close(sessionID)
        }
    }

    // MARK: - Handshake

    /// Returns the open session, running the handshake if there is not one yet.
    ///
    /// The in-flight task is held so concurrent callers join the same handshake. Without it, the
    /// first two requests on a cold session would each open one, and the peer would see two
    /// identities where there is one.
    private func establishedSession() async throws -> AuthSessionID {
        if let sessionID, let snapshot = await authenticator.session(sessionID),
            snapshot.state == .authenticated
        {
            return sessionID
        }
        sessionID = nil
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
            throw Self.logged(.handshakeFailed("the authenticator opened no request"))
        }
        let handshakeCall = Self.describe(
            requestContext(method: "POST", path: BRC104HTTPHeaderName.handshakePath)
        )

        do {
            let response = try await transport.send(
                HTTPRequest(
                    method: "POST",
                    url: url(forPath: BRC104HTTPHeaderName.handshakePath, query: nil),
                    headers: ["Content-Type": "application/json"],
                    body: try AuthMessageCodec.encode(request)
                )
            )
            // Handshake bodies are logged by length only: they are auth frames.
            guard (200..<300).contains(response.statusCode) else {
                throw Self.logged(.handshakeFailed(
                    "\(handshakeCall) answered HTTP \(response.statusCode) "
                        + "(\(response.body.count) bytes)"
                ))
            }

            let reply: AuthMessage
            do {
                reply = try AuthMessageCodec.decode(response.body)
            } catch {
                throw Self.logged(.handshakeFailed(
                    "\(handshakeCall) answered HTTP \(response.statusCode) with a reply that could "
                        + "not be read (\(response.body.count) bytes): \(ErrorDetail.describe(error))"
                ))
            }
            // Verifying the reply is the authenticator's job, and it throws when the signature does
            // not cover our nonce. Reaching the next line means the peer holds the key it claims.
            let handshakeActions: [AuthPeerAction]
            do {
                handshakeActions = try await authenticator.receive(reply)
            } catch AuthError.sessionNotFound {
                throw AuthTransportError.sessionExpired
            }
            // A peer with a certificate policy sends it in its reply. AuthFetch answers it from
            // the wallet's certificates and sends nothing when it holds none that fit
            // (`AuthFetch.ts:496-511`). This session signs with an `AuthenticationWallet`, which
            // holds no certificates, so it sends nothing too. A TypeScript `Peer` with a nonempty
            // certifier policy then verifies each general message and holds it for up to 30
            // seconds waiting for certificates (`Peer.ts:1321-1328`, `Peer.ts:286-308`), so the
            // caller sees the request stall and fail or time out, not a prompt refusal. This log
            // line is the clue to that cause.
            if handshakeActions.contains(where: {
                if case .certificateRequest = $0 { return true }
                return false
            }) {
                Self.log(
                    "\(handshakeCall): the peer asked for certificates; this session has none to "
                        + "send, so a peer that requires them may hold each request up to 30 s "
                        + "and let it stall or time out"
                )
            }

            guard await authenticator.session(session) != nil else {
                throw Self.logged(.handshakeFailed(
                    "\(handshakeCall): the peer's reply did not open a session"
                ))
            }
            return session
        } catch {
            if !(error is AuthTransportError), !(error is CancellationError) {
                Self.log("\(handshakeCall) failed: \(ErrorDetail.describe(error))")
            }
            await authenticator.close(session)
            throw error
        }
    }

    // MARK: - Unwrapping

    /// Turns a signed reply back into the response the caller asked for.
    ///
    /// Anything that is not a delivered message for this exact request is refused. A peer that
    /// returns an unsigned body, or a body for a different request, has failed — and returning it
    /// anyway would defeat the point of every step above.
    private func unwrap(
        _ response: HTTPResponse, expecting requestID: [UInt8], for context: AuthRequestContext
    ) async throws -> AuthenticatedResponse {
        // A 401 with no auth frame is the peer saying the session is gone before the
        // application method ran. AuthFetch retries that case. A 200 with no auth frame
        // is an unsigned application reply and is not retried.
        if response.statusCode == 401, response.header(BRC104HTTPHeaderName.version) == nil {
            throw AuthTransportError.sessionExpired
        }
        // Any other error status with no auth frame is a refusal from in front of the peer's auth
        // (a gate, a proxy). TS reports its status and body preview; returning neither would
        // leave the caller naming the wrong cause.
        if !(200..<300).contains(response.statusCode),
           response.header(BRC104HTTPHeaderName.version) == nil {
            throw Self.logged(.unauthenticatedReply(
                status: response.statusCode,
                body: Array(response.body.prefix(Self.unauthenticatedBodyPreviewBytes)),
                request: context
            ))
        }

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
            throw Self.logged(.responseNotAuthenticated(
                "\(Self.describe(context)) answered HTTP \(response.statusCode) with no valid auth "
                    + "frame: \(ErrorDetail.describe(error))"
            ))
        }

        let actions: [AuthPeerAction]
        do {
            actions = try await authenticator.receive(message)
        } catch AuthError.sessionNotFound {
            // Unlike an unsigned 401, this reply is the peer's answer to the request.
            throw SignedReplySessionLost()
        }
        guard case .deliver(let delivered)? = actions.first(where: {
            if case .deliver = $0 { return true }
            return false
        }) else {
            throw Self.logged(.responseNotAuthenticated(
                "\(Self.describe(context)): the reply delivered no payload"
            ))
        }

        let inner: BRC104Response
        do {
            inner = try BRC104Codec.decodeResponse(delivered.payload)
            try BRC104Codec.requireCorrelation(requestID: requestID, response: inner)
        } catch {
            Self.log(
                "\(Self.describe(context)): the signed reply could not be read as the response to "
                    + "this request: \(ErrorDetail.describe(error))"
            )
            throw error
        }

        var headers = Dictionary(
            inner.headers.map { ($0.name, $0.value) }, uniquingKeysWith: { _, last in last }
        )
        // AuthFetch adds the identity that signed the reply back as a header
        // (`AuthFetch.ts:211`), over anything the peer sent under that name. BRC-105 reads the
        // payee from it.
        headers[BRC104HTTPHeaderName.identityKey] = Hex.encode(delivered.peer.compressedBytes)
        return AuthenticatedResponse(statusCode: inner.status, headers: headers, body: inner.body ?? [])
    }

    // MARK: - Helpers

    /// Builds the URL to send a frame to, without losing what the frame said.
    ///
    /// Built through `URLComponents` rather than `appendingPathComponent` because BRC-104 is
    /// precise about both halves and `URL` quietly is not: a path of `/` leaves `URL.path` empty,
    /// and `URL.query` drops the leading `?` the frame requires. Either loss makes a peer reject
    /// a frame that was correct when we built it.
    func url(forPath path: String, query: String?) -> URL {
        guard var parts = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            return baseURL
        }
        // The frame's path is the whole request path from the host root, so it replaces the base
        // URL's path rather than extending it. Appending produced `https://host/api/api` when the
        // endpoint already had a path and the caller passed the same one.
        parts.path = path.hasPrefix("/") ? path : "/" + path
        if let query, !query.isEmpty {
            // The frame carries the `?`; `URLComponents` writes its own. The query is the frame's,
            // already in wire form (`wireQuery`), so it goes out as `percentEncodedQuery`: setting
            // `query` would encode its `%` again and the peer would verify a different query.
            parts.percentEncodedQuery = query.hasPrefix("?") ? String(query.dropFirst()) : query
        }
        return parts.url ?? baseURL
    }

    /// The caller's query in the one form that is both signed and sent, as AuthFetch signs
    /// `url.search`: a query already in wire form is unchanged, anything left unencoded (a space,
    /// `[`, non-ASCII) is percent-encoded, and a `%` that is not a two-digit escape is refused,
    /// since no URL can carry it and `percentEncodedQuery` would trap on it.
    static func wireQuery(_ query: String?) throws -> String? {
        guard let query, !query.isEmpty else { return query }
        let raw = query.hasPrefix("?") ? String(query.dropFirst()) : query
        // A bare `?` is an empty search to a TS peer, so it is signed as none.
        if raw.isEmpty { return nil }
        guard let encoded = raw.addingPercentEncoding(withAllowedCharacters: wireQueryCharacters) else {
            throw AuthTransportError.invalidQuery(query)
        }
        let bytes = Array(encoded.utf8)
        var index = 0
        while index < bytes.count {
            if bytes[index] == UInt8(ascii: "%") {
                guard index + 2 < bytes.count, isHexDigit(bytes[index + 1]), isHexDigit(bytes[index + 2]) else {
                    throw AuthTransportError.invalidQuery(query)
                }
                index += 3
            } else {
                index += 1
            }
        }
        return "?" + encoded
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
            || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
            || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(byte)
    }

    /// The characters a query may carry on the wire as they are: those a URL query allows, and
    /// `%` because the caller has already done the encoding, less `'`, which a WHATWG `URL` (what
    /// a TS peer verifies against) rewrites to `%27`.
    private static let wireQueryCharacters = CharacterSet.urlQueryAllowed.union(["%"]).subtracting(["'"])

    /// Thirty-two bytes, which is the length the framing requires.
    ///
    /// `SystemRandomNumberGenerator`, which is what `UInt8.random` uses, is cryptographically
    /// secure on every platform this package supports.
    private func randomRequestID() -> [UInt8] {
        (0..<32).map { _ in UInt8.random(in: .min ... .max) }
    }

    /// Logs an error at the place it is raised and returns it to be thrown.
    private static func logged(_ error: AuthTransportError) -> AuthTransportError {
        log(ErrorDetail.describe(error))
        return error
    }

    /// A signed reply arrived for a session this side no longer holds. The peer has run the
    /// request, so `send` surfaces ``AuthTransportError/sessionExpired`` without resending it.
    private struct SignedReplySessionLost: Error {}

    /// A send failed after the request was handed to the transport, in a way that leaves open
    /// whether the peer's application ran it: a lost or unreadable reply, or a signed reply for a
    /// session this side no longer holds. `underlying` is what ``send(method:path:query:headers:body:)``
    /// throws for it.
    struct RequestMayHaveRun: Error {
        let underlying: any Error
    }

    private func acquireSend() async {
        if sending {
            await withCheckedContinuation { sendWaiters.append($0) }
        }
        sending = true
    }

    private func releaseSend() {
        if sendWaiters.isEmpty {
            sending = false
        } else {
            sendWaiters.removeFirst().resume()
        }
    }
}
