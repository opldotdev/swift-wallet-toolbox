import Foundation
import BSVAuth
import BSVKeys
import BSVWallet
@testable import ToolboxAuth

/// What ``TestPeer``'s responder answers an application request with. Its headers are signed with
/// the reply, so only names BRC-104 signs (`x-bsv-*` other than `x-bsv-auth*`, `authorization`)
/// may be used.
struct TestPeerReply: Sendable {
    var status: Int
    var headers: [String: String] = [:]
    var body: [UInt8]? = nil
}

/// A server built from the same SDK pieces, driven over a fake transport.
actor TestPeer: HTTPTransport {
    let authenticator: PeerAuthenticator
    /// What the peer answers with, so a test can make it return a specific body.
    var responseBody: [UInt8]
    var responseStatus: Int
    /// Every path the peer was asked for, so a test can assert the handshake happened once.
    private(set) var pathsSeen: [String] = []
    /// Every query the peer received on the wire, encoded as sent.
    private(set) var queriesSeen: [String?] = []
    /// Set to refuse the handshake.
    var refuseHandshake = false
    /// After a session is open, answer later application requests with an unsigned body.
    var unsignedReplies = false
    /// The status of those unsigned replies.
    var unsignedStatus = 200
    /// Answers each application request in place of `responseStatus` and `responseBody`, with
    /// signed headers of its own. A throw is a transport failure: no reply reaches the client,
    /// though the request was read.
    var responder: (@Sendable (BRC104Request) async throws -> TestPeerReply)?
    /// Every application request the peer read, as the client signed it.
    private(set) var requestsSeen: [BRC104Request] = []
    /// Count of application replies to send as an unsigned 401, matching a peer
    /// that has dropped the session before applying the method.
    var unauthorizedRemaining = 0
    /// Count of application replies whose `yourNonce` does not match the open session. The
    /// peer has run the request; AuthFetch resends on the `Session not found for nonce` this
    /// raises, and the session must not.
    var unknownSessionNonceRemaining = 0
    private var generalDepth = 0
    private(set) var maxGeneralDepth = 0

    init(key: PrivateKey, responseBody: [UInt8] = Array("{\"ok\":true}".utf8),
         responseStatus: Int = 200,
         certificatesToRequest: AuthRequestedCertificateSet? = nil) {
        self.authenticator = PeerAuthenticator(
            wallet: ProtoWallet(rootKey: key), certificatesToRequest: certificatesToRequest
        )
        self.responseBody = responseBody
        self.responseStatus = responseStatus
    }

    func setRefusingHandshake(_ refusing: Bool) { refuseHandshake = refusing }
    func setResponseStatus(_ status: Int) { responseStatus = status }
    func setUnsignedReplies(_ unsigned: Bool, status: Int = 200) {
        unsignedReplies = unsigned
        unsignedStatus = status
    }
    func setResponder(_ responder: (@Sendable (BRC104Request) async throws -> TestPeerReply)?) {
        self.responder = responder
    }
    func setUnauthorizedRemaining(_ count: Int) { unauthorizedRemaining = count }
    func setUnknownSessionNonceRemaining(_ count: Int) { unknownSessionNonceRemaining = count }
    func peakGeneralDepth() -> Int { maxGeneralDepth }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        pathsSeen.append(request.url.path)
        queriesSeen.append(request.url.query)
        if request.url.path.hasSuffix(BRC104HTTPHeaderName.handshakePath) {
            return try await handshake(request)
        }
        return try await general(request)
    }

    private func handshake(_ request: HTTPRequest) async throws -> HTTPResponse {
        if refuseHandshake {
            return HTTPResponse(statusCode: 401, body: [])
        }
        let incoming = try AuthMessageCodec.decode(request.body ?? [])
        let actions = try await authenticator.receive(incoming)
        guard case .send(let reply)? = actions.first else {
            return HTTPResponse(statusCode: 500, body: [])
        }
        return HTTPResponse(statusCode: 200, body: try AuthMessageCodec.encode(reply))
    }

    private func general(_ request: HTTPRequest) async throws -> HTTPResponse {
        generalDepth += 1
        maxGeneralDepth = max(maxGeneralDepth, generalDepth)
        defer { generalDepth -= 1 }
        await Task.yield()
        if unauthorizedRemaining > 0 {
            unauthorizedRemaining -= 1
            return HTTPResponse(statusCode: 401, body: Array("unauthorized".utf8))
        }
        if unsignedReplies {
            return HTTPResponse(statusCode: unsignedStatus, body: Array("{\"result\":42}".utf8))
        }
        let frame = try BRC104HTTPRequestFrame(
            method: request.method,
            path: request.url.path,
            query: request.url.query.map { "?" + $0 },
            headers: request.headers.map { BRC104Header(name: $0.key, value: $0.value) },
            body: request.body
        )
        let message = try BRC104HTTPFrameCodec.decodeRequest(frame)
        let actions = try await authenticator.receive(message)
        guard case .deliver(let delivered)? = actions.first(where: {
            if case .deliver = $0 { return true }
            return false
        }) else {
            return HTTPResponse(statusCode: 500, body: [])
        }

        let inner = try BRC104Codec.decodeRequest(delivered.payload)
        requestsSeen.append(inner)
        let answer = try await responder?(inner)
            ?? TestPeerReply(status: responseStatus, body: responseBody)
        let reply = try BRC104Response(
            requestID: inner.requestID, status: answer.status,
            headers: answer.headers.map { BRC104Header(name: $0.key, value: $0.value) },
            body: answer.body
        )
        guard case .send(let signed) = try await authenticator.makeGeneralMessage(
            payload: try BRC104Codec.encode(reply), using: delivered.sessionID
        ) else {
            return HTTPResponse(statusCode: 500, body: [])
        }
        let responseFrame = try BRC104HTTPFrameCodec.encodeResponse(signed)
        var headers = Dictionary(
            responseFrame.headers.map { ($0.name, $0.value) },
            uniquingKeysWith: { _, last in last }
        )
        if unknownSessionNonceRemaining > 0 {
            unknownSessionNonceRemaining -= 1
            headers[BRC104HTTPHeaderName.yourNonce] = String(repeating: "A", count: 64)
        }
        return HTTPResponse(
            statusCode: responseFrame.status,
            headers: headers,
            body: responseFrame.body ?? []
        )
    }
}
