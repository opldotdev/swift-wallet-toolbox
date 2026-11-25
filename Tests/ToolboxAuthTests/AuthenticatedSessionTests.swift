import Foundation
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

    /// The frame signs the query as the caller wrote it, already percent-encoded, as AuthFetch
    /// signs `url.search`. The URL must carry the same bytes, or the peer verifies a different
    /// query and refuses the request. Base64 values (`+`, `/`, `=`) are the case that matters.
    func test_aPercentEncodedQueryGoesOutExactlyAsSigned() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)
        let query = "?tokenId=abc_0&derivationPrefix=a%2Bb%2Fc%3D%3D&x=1"

        let response = try await session.send(method: "POST", path: "/enable", query: query)

        XCTAssertEqual(response.statusCode, 200)
        let seen = await peer.queriesSeen.last ?? nil
        XCTAssertEqual(seen, String(query.dropFirst()))
    }

    /// A query with characters the caller left unencoded is signed in the same encoded form it
    /// is sent in, so the peer still verifies it.
    func test_anUnencodedQueryIsSignedAsItIsSent() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)

        let response = try await session.send(method: "GET", path: "/list", query: "?q=a b[1]&k=%2B&n='x'")

        XCTAssertEqual(response.statusCode, 200)
        let seen = await peer.queriesSeen.last ?? nil
        XCTAssertEqual(seen, "q=a%20b%5B1%5D&k=%2B&n=%27x%27")
    }

    /// A `%` that is not an escape cannot be put on a URL; it is refused before any request.
    func test_aMalformedEscapeIsRefusedBeforeSending() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)

        for query in ["?a=%", "?a=%zz", "?a=%2", "?a=100%&b=1"] {
            do {
                _ = try await session.send(method: "GET", path: "/list", query: query)
                XCTFail("sent \(query)")
            } catch {
                XCTAssertEqual(error as? AuthTransportError, .invalidQuery(query))
            }
        }
        let paths = await peer.pathsSeen
        XCTAssertEqual(paths, [])
    }

    /// A peer with a certificate policy puts it in its handshake reply, as `Peer.ts:867-876` does.
    /// AuthFetch answers from the wallet's certificates and sends nothing when none fit; this
    /// session holds none, so the handshake must still open and the request go through.
    func test_aPeerThatAsksForCertificatesStillAuthenticates() async throws {
        let keys = try keyPair()
        let certifier = try PrivateKey(Array(repeating: 0x33, count: 32)).publicKey
        let policy = try AuthRequestedCertificateSet(
            certifiers: [certifier],
            certificateTypes: [
                try CertificateTypeID(Array(repeating: 0x01, count: 32)): [
                    try CertificateFieldName("name")
                ]
            ]
        )
        let peer = TestPeer(key: keys.server, certificatesToRequest: policy)
        let session = session(with: peer, client: keys.client)

        let response = try await session.send(method: "POST", path: "/", body: [0x01])

        XCTAssertEqual(response.statusCode, 200)
        let handshakes = await peer.pathsSeen.filter {
            $0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(handshakes.count, 1)
    }

    /// A request over the BRC-104 payload limit is refused once, not treated as a lost session:
    /// a new handshake cannot make it smaller, and AuthFetch does not retry it either. With the
    /// default limits the codec refuses it before the authenticator sees it.
    func test_anOversizedRequestIsRefusedWithoutRehandshaking() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)

        do {
            _ = try await session.send(
                method: "POST", path: "/",
                body: Array(repeating: 0x61, count: AuthLimits.defaultPayloadBytes + 1)
            )
            XCTFail("an oversized request was sent")
        } catch {
            XCTAssertEqual(error as? BRC104Error, .resourceLimit)
        }
        let paths = await peer.pathsSeen
        XCTAssertEqual(paths, [BRC104HTTPHeaderName.handshakePath])

        let response = try await session.send(method: "POST", path: "/", body: [0x01])
        XCTAssertEqual(response.statusCode, 200)
        let handshakes = await peer.pathsSeen.filter {
            $0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(handshakes.count, 1, "the open session must survive the refusal")
    }

    /// When the authenticator's payload limit is below the codec's, `makeGeneralMessage` throws
    /// `resourceLimit` with the session still open. That is a refusal of this request, not a
    /// spent session, so it reaches the caller after one handshake and the session is reused.
    func test_anAuthenticatorPayloadRefusalIsNotTreatedAsALostSession() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = AuthenticatedSession(
            baseURL: baseURL, wallet: ProtoWallet(rootKey: keys.client), transport: peer,
            expectedPeer: nil, authenticatorLimits: try AuthLimits(maximumPayloadBytes: 1024)
        )

        do {
            _ = try await session.send(
                method: "POST", path: "/", body: Array(repeating: 0x61, count: 2048)
            )
            XCTFail("a request over the authenticator's limit was sent")
        } catch {
            XCTAssertEqual(error as? AuthError, .resourceLimit)
        }
        let paths = await peer.pathsSeen
        XCTAssertEqual(paths, [BRC104HTTPHeaderName.handshakePath])

        let response = try await session.send(method: "POST", path: "/", body: [0x01])
        XCTAssertEqual(response.statusCode, 200)
        let handshakes = await peer.pathsSeen.filter {
            $0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(handshakes.count, 1, "the open session must survive the refusal")
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

    // MARK: - Stale-session recovery

    func test_aStaleAuthenticatorSessionRehandshakesOnce() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)

        _ = try await session.send(method: "POST", path: "/one", body: [0x01])
        await session.testingCloseAuthenticatorSession()
        let response = try await session.send(method: "POST", path: "/two", body: [0x02])

        XCTAssertEqual(response.statusCode, 200)
        let paths = await peer.pathsSeen
        let handshakes = paths.filter { $0.hasSuffix(BRC104HTTPHeaderName.handshakePath) }
        let application = paths.filter { !$0.hasSuffix(BRC104HTTPHeaderName.handshakePath) }
        XCTAssertEqual(handshakes.count, 2)
        XCTAssertEqual(application, ["/one", "/two"])
    }

    func test_concurrentRecoveryAfterEvictionSharesOneHandshake() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)

        _ = try await session.send(method: "POST", path: "/one", body: [0x01])
        await session.testingCloseAuthenticatorSession()

        async let first = session.send(method: "POST", path: "/two", body: [0x02])
        async let second = session.send(method: "POST", path: "/three", body: [0x03])
        _ = try await (first, second)

        let handshakes = await peer.pathsSeen.filter {
            $0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(handshakes.count, 2)
    }

    func test_anUnsignedReplyAfterALiveSessionIsNotRetried() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)
        _ = try await session.send(method: "POST", path: "/one", body: [0x01])
        await peer.setUnsignedReplies(true)

        do {
            _ = try await session.send(method: "POST", path: "/two", body: [0x02])
            XCTFail("an unsigned application reply must not be returned")
        } catch let error as AuthTransportError {
            guard case .responseNotAuthenticated = error else {
                return XCTFail("expected responseNotAuthenticated, got \(error)")
            }
        }

        let handshakes = await peer.pathsSeen.filter {
            $0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(handshakes.count, 1, "an unsigned reply must not start a new session")
        let application = await peer.pathsSeen.filter {
            !$0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(application, ["/one", "/two"])
    }

    func test_aSignedReplyForAnUnknownSessionNonceIsNotResent() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)
        _ = try await session.send(method: "POST", path: "/one", body: [0x01])
        await peer.setUnknownSessionNonceRemaining(1)

        do {
            _ = try await session.send(method: "POST", path: "/two", body: [0x02])
            XCTFail("a signed reply for a lost session must surface, not be retried")
        } catch {
            XCTAssertEqual(error as? AuthTransportError, .sessionExpired)
        }
        let afterFailure = await peer.pathsSeen
        XCTAssertEqual(
            afterFailure.filter { !$0.hasSuffix(BRC104HTTPHeaderName.handshakePath) },
            ["/one", "/two"], "the peer ran /two once and must not be asked to run it again"
        )
        XCTAssertEqual(afterFailure.filter { $0.hasSuffix(BRC104HTTPHeaderName.handshakePath) }.count, 1)

        // The lost session is dropped, so the next request re-handshakes and goes through.
        let response = try await session.send(method: "POST", path: "/three", body: [0x03])

        XCTAssertEqual(response.statusCode, 200)
        let paths = await peer.pathsSeen
        XCTAssertEqual(paths.filter { $0.hasSuffix(BRC104HTTPHeaderName.handshakePath) }.count, 2)
        XCTAssertEqual(
            paths.filter { !$0.hasSuffix(BRC104HTTPHeaderName.handshakePath) },
            ["/one", "/two", "/three"]
        )
    }

    func test_concurrentSendsDoNotOverlapTheHTTPRoundTrip() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)

        async let first = session.send(method: "POST", path: "/one", body: [0x01])
        async let second = session.send(method: "POST", path: "/two", body: [0x02])
        _ = try await (first, second)

        let depth = await peer.peakGeneralDepth()
        XCTAssertEqual(depth, 1)
    }

    func test_anUnauthorizedReplyWithoutAnAuthFrameRehandshakesOnce() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)
        _ = try await session.send(method: "POST", path: "/one", body: [0x01])
        await peer.setUnauthorizedRemaining(1)

        let response = try await session.send(method: "POST", path: "/two", body: [0x02])

        XCTAssertEqual(response.statusCode, 200)
        let handshakes = await peer.pathsSeen.filter {
            $0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(handshakes.count, 2)
        let application = await peer.pathsSeen.filter {
            !$0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(application, ["/one", "/two", "/two"])
    }

    func test_authFetchBudgetRecoversThreeStaleReplies() async throws {
        XCTAssertEqual(AuthenticatedSession.sessionRecoveryRetries, 3)
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)
        _ = try await session.send(method: "POST", path: "/one", body: [0x01])
        await peer.setUnauthorizedRemaining(3)

        let response = try await session.send(method: "POST", path: "/two", body: [0x02])

        XCTAssertEqual(response.statusCode, 200)
        let application = await peer.pathsSeen.filter {
            !$0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(application, ["/one", "/two", "/two", "/two", "/two"])
    }

    func test_authFetchBudgetStopsAfterThreeRecoveries() async throws {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        let session = session(with: peer, client: keys.client)
        _ = try await session.send(method: "POST", path: "/one", body: [0x01])
        await peer.setUnauthorizedRemaining(4)

        do {
            _ = try await session.send(method: "POST", path: "/two", body: [0x02])
            XCTFail("a fourth consecutive stale reply must surface")
        } catch let error as AuthTransportError {
            guard case .sessionExpired = error else {
                return XCTFail("expected sessionExpired, got \(error)")
            }
        }

        let application = await peer.pathsSeen.filter {
            !$0.hasSuffix(BRC104HTTPHeaderName.handshakePath)
        }
        XCTAssertEqual(application, ["/one", "/two", "/two", "/two", "/two"])
    }

    func test_cancellationIsNotTreatedAsAStaleSession() async throws {
        let keys = try keyPair()
        let session = AuthenticatedSession(
            baseURL: baseURL,
            wallet: ProtoWallet(rootKey: keys.client),
            transport: CancellingTransport()
        )
        let task = Task {
            try await session.send(method: "POST", path: "/", body: [0x01])
        }
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("a cancelled send must not return a response")
        } catch is CancellationError {
            // Fail-closed. Recovery must not swallow cancellation into a retry.
        } catch let error as AuthTransportError {
            guard case .handshakeFailed = error else {
                return XCTFail("cancellation must not become a session retry, got \(error)")
            }
        }
    }
}

private struct CancellingTransport: HTTPTransport {
    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        throw CancellationError()
    }
}

/// The handshake reaches the peer; every application request is refused by a gate in front of
/// it, as the 1Sat host's account gate refuses `/sendMessage` before its auth runs.
private struct GatedTransport: HTTPTransport {
    let handshake: @Sendable (HTTPRequest) async throws -> HTTPResponse
    let status: Int
    let body: [UInt8]

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        if request.url.path.hasSuffix(BRC104HTTPHeaderName.handshakePath) {
            return try await handshake(request)
        }
        return HTTPResponse(statusCode: status, headers: ["Content-Type": "application/json"], body: body)
    }
}

extension AuthenticatedSessionTests {
    private func gatedSession(status: Int, body: [UInt8]) throws -> AuthenticatedSession {
        let keys = try keyPair()
        let peer = TestPeer(key: keys.server)
        return AuthenticatedSession(
            baseURL: baseURL, wallet: ProtoWallet(rootKey: keys.client),
            transport: GatedTransport(handshake: { try await peer.send($0) }, status: status, body: body)
        )
    }

    func test_anUnsignedErrorStatusCarriesTheStatusAndBody() async throws {
        let body = Array(#"{"status":"error","code":"ERR_ACCOUNT_REQUIRED"}"#.utf8)
        let session = try gatedSession(status: 403, body: body)

        do {
            _ = try await session.send(method: "POST", path: "/sendMessage", body: [0x01])
            XCTFail("an unsigned refusal must not be returned as a response")
        } catch let error as AuthTransportError {
            XCTAssertEqual(error, .unauthenticatedReply(status: 403, body: body))
            guard case .unauthenticatedReply(_, _, let request) = error else {
                return XCTFail("expected unauthenticatedReply, got \(error)")
            }
            XCTAssertEqual(request?.method, "POST")
            XCTAssertEqual(request?.host, baseURL.host)
            XCTAssertEqual(request?.path, "/sendMessage")
            // The user text names the host and the server's code, and nothing of the body else.
            let text = error.localizedDescription
            XCTAssertTrue(text.contains(baseURL.host ?? "?"), text)
            XCTAssertTrue(text.contains("ERR_ACCOUNT_REQUIRED"), text)
            XCTAssertTrue(String(reflecting: error).contains("POST"), String(reflecting: error))
        }
    }

    func test_anUnsignedErrorBodyIsCappedAtThePreviewLength() async throws {
        let session = try gatedSession(status: 502, body: [UInt8](repeating: 0x41, count: 4096))

        do {
            _ = try await session.send(method: "POST", path: "/", body: [0x01])
            XCTFail("an unsigned refusal must not be returned as a response")
        } catch let error as AuthTransportError {
            guard case .unauthenticatedReply(let status, let preview, _) = error else {
                return XCTFail("expected unauthenticatedReply, got \(error)")
            }
            XCTAssertEqual(status, 502)
            XCTAssertEqual(preview.count, AuthenticatedSession.unauthenticatedBodyPreviewBytes)
        }
    }
}
