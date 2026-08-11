import XCTest
import BSVKeys
import BSVWallet
@testable import ToolboxAuth

/// The handshake against a real storage server.
///
/// Every other test here talks to a peer built from the same SDK, which proves the two halves
/// agree and nothing about whether a server written by somebody else agrees with either. This one
/// crosses the network.
///
/// Skipped unless `TEST_RUNNER_LIVE_STORAGE_URL` is set, so a CI run stays offline and a broken
/// server never fails somebody's unrelated build:
///
///     TEST_RUNNER_LIVE_STORAGE_URL=https://wallet.1sat.app swift test \
///       --filter LiveHandshakeTests
///
/// It performs the handshake and stops. It never calls a storage method, so it reads nothing and
/// writes nothing — the identity it presents is a throwaway key generated for the run.
final class LiveHandshakeTests: XCTestCase {

    private func liveURL() throws -> URL {
        let value = ProcessInfo.processInfo.environment["TEST_RUNNER_LIVE_STORAGE_URL"]
        try XCTSkipIf(value == nil, "set TEST_RUNNER_LIVE_STORAGE_URL to run against a real server")
        return try XCTUnwrap(URL(string: value!))
    }

    /// Reaching the end means a server we did not write verified our signature, and we verified
    /// its reply. That is the whole of BRC-103 and the thing nothing else can prove.
    func test_aRealServerCompletesTheHandshake() async throws {
        let url = try liveURL()
        let session = AuthenticatedSession(
            baseURL: url,
            wallet: ProtoWallet(rootKey: try PrivateKey((0..<32).map { _ in
                UInt8.random(in: .min ... .max)
            }))
        )

        // `send` opens the session on its first call. A 401 or 404 in the response is a fine
        // outcome — it means the envelope was accepted and the server answered inside it. What
        // must not happen is an authentication failure.
        do {
            let response = try await session.send(
                method: "POST", path: "/",
                headers: ["Content-Type": "application/json"],
                body: Array(#"{"jsonrpc":"2.0","method":"makeAvailable","params":[],"id":1}"#.utf8)
            )
            XCTAssertGreaterThan(response.statusCode, 0)
        } catch let error as AuthTransportError {
            XCTFail("the live server did not authenticate: \(error)")
        } catch {
            throw XCTSkip("the live server was unreachable: \(error)")
        }
    }
}
