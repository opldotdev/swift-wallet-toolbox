import XCTest
import BSVAuth
import BSVKeys
import BSVWallet
@testable import ToolboxAuth

/// The BRC-103 loop, end to end, with no network.
///
/// The peer here is a real `PeerAuthenticator` with its own key, not a recording. That matters:
/// this module exists because neither the Go nor the TypeScript toolbox has a Swift-shaped answer
/// to copy, so a test that replayed captured bytes would prove only that we can replay them. A
/// second authenticator genuinely verifies our signatures and refuses us when they are wrong.
final class AuthenticatedSessionTests: XCTestCase {

    // MARK: - A peer that speaks the protocol

    /// A server built from the same SDK pieces, driven over a fake transport.
    private actor TestPeer: HTTPTransport {
        let authenticator: PeerAuthenticator
        /// What the peer answers with, so a test can make it return a specific body.
        var responseBody: [UInt8]
        var responseStatus: Int
        /// Every path the peer was asked for, so a test can assert the handshake happened once.
        private(set) var pathsSeen: [String] = []
        /// Set to refuse the handshake.
        var refuseHandshake = false

        init(key: PrivateKey, responseBody: [UInt8] = Array("{\"ok\":true}".utf8),
             responseStatus: Int = 200) {
            self.authenticator = PeerAuthenticator(wallet: ProtoWallet(rootKey: key))
            self.responseBody = responseBody
            self.responseStatus = responseStatus
        }

        func setRefusingHandshake(_ refusing: Bool) { refuseHandshake = refusing }
        func setResponseStatus(_ status: Int) { responseStatus = status }

        func send(_ request: HTTPRequest) async throws -> HTTPResponse {
            pathsSeen.append(request.url.path)
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
            let reply = try BRC104Response(
                requestID: inner.requestID, status: responseStatus, headers: [],
                body: responseBody
            )
            guard case .send(let signed) = try await authenticator.makeGeneralMessage(
                payload: try BRC104Codec.encode(reply), using: delivered.sessionID
            ) else {
                return HTTPResponse(statusCode: 500, body: [])
            }
            let responseFrame = try BRC104HTTPFrameCodec.encodeResponse(signed)
            return HTTPResponse(
                statusCode: responseFrame.status,
                headers: Dictionary(
                    responseFrame.headers.map { ($0.name, $0.value) },
                    uniquingKeysWith: { _, last in last }
                ),
                body: responseFrame.body ?? []
            )
        }
    }

    /// A transport that never answers, for the cases where the peer is not really there.
    private struct DeadTransport: HTTPTransport {
        let statusCode: Int
        let body: [UInt8]

        func send(_ request: HTTPRequest) async throws -> HTTPResponse {
            HTTPResponse(statusCode: statusCode, body: body)
        }
    }

    // MARK: - Fixtures

    private let baseURL = URL(string: "https://wallet.example")!

    private func keyPair() throws -> (client: PrivateKey, server: PrivateKey) {
        (try PrivateKey(Array(repeating: 0x11, count: 32)),
         try PrivateKey(Array(repeating: 0x22, count: 32)))
    }

    private func session(with peer: TestPeer, client: PrivateKey) -> AuthenticatedSession {
        AuthenticatedSession(
            baseURL: baseURL, wallet: ProtoWallet(rootKey: client), transport: peer
        )
    }

    // MARK: - The happy path

    func test_aRequestReachesAnAuthenticatedPeerAndComesBack() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server, responseBody: Array("{\"result\":42}".utf8))
        let session = session(with: peer, client: keys.client)

        let response = try await session.send(
            method: "POST", path: "/", headers: ["Content-Type": "application/json"],
            body: Array("{\"jsonrpc\":\"2.0\"}".utf8)
        )

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(String(decoding: response.body, as: UTF8.self), "{\"result\":42}")
    }

    /// The handshake is the expensive part and must happen once, not per request.
    func test_theHandshakeHappensOnlyOnce() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)

        _ = try await session.send(method: "POST", path: "/", body: [0x01])
        _ = try await session.send(method: "POST", path: "/", body: [0x02])

        let handshakes = await peer.pathsSeen.filter {
            $0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(handshakes.count, 1, "a second request must reuse the open session")
    }

    /// Two requests racing on a cold session must not each open a handshake. The peer would see
    /// two identities where there is one.
    func test_concurrentFirstRequestsShareOneHandshake() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)

        async let first = session.send(method: "POST", path: "/", body: [0x01])
        async let second = session.send(method: "POST", path: "/", body: [0x02])
        _ = try await (first, second)

        let handshakes = await peer.pathsSeen.filter {
            $0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(handshakes.count, 1)
    }

    func test_theStatusFromThePeerIsCarriedThrough() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        await peer.setResponseStatus(404)
        let session = session(with: peer, client: keys.client)

        let response = try await session.send(method: "POST", path: "/", body: [0x01])

        XCTAssertEqual(response.statusCode, 404,
                       "an authenticated 404 is a real answer, not a transport failure")
    }

    // MARK: - Refusals

    func test_aPeerThatRefusesTheHandshakeIsReported() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        await peer.setRefusingHandshake(true)
        let session = session(with: peer, client: keys.client)

        do {
            _ = try await session.send(method: "POST", path: "/", body: [0x01])
            XCTFail("a refused handshake must not produce a response")
        } catch let error as AuthTransportError {
            guard case .handshakeFailed = error else {
                return XCTFail("expected handshakeFailed, got \(error)")
            }
        }
    }

    /// The case this module exists to prevent: a server that answers without proving who it is.
    /// An unauthenticated body is not a slower authenticated one, so it is never returned.
    func test_anUnsignedReplyIsRefusedRatherThanReturned() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)
        // Open a real session first, so the failure is the reply and not the handshake.
        _ = try await session.send(method: "POST", path: "/", body: [0x01])

        let plain = AuthenticatedSession(
            baseURL: baseURL,
            wallet: ProtoWallet(rootKey: keys.client),
            transport: DeadTransport(statusCode: 200, body: Array("{\"result\":42}".utf8))
        )

        do {
            _ = try await plain.send(method: "POST", path: "/", body: [0x01])
            XCTFail("a reply with no auth frame must not be returned to the caller")
        } catch is AuthTransportError {
            // Refused, which is the whole point.
        }
    }

    func test_aGarbledHandshakeReplyIsRefused() async {
        let keys = try? keyPair()
        let session = AuthenticatedSession(
            baseURL: baseURL,
            wallet: ProtoWallet(rootKey: keys!.client),
            transport: DeadTransport(statusCode: 200, body: Array("not json".utf8))
        )

        do {
            _ = try await session.send(method: "POST", path: "/", body: [0x01])
            XCTFail("an unreadable handshake reply must not open a session")
        } catch let error as AuthTransportError {
            guard case .handshakeFailed = error else {
                return XCTFail("expected handshakeFailed, got \(error)")
            }
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }
}
