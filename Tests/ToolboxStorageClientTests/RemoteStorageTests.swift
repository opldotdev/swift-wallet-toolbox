import XCTest
import BSVKeys
import BSVWallet
@testable import ToolboxStorageClient

/// Constructing a remote client, and the guards on how it may be pointed.
final class RemoteStorageTests: XCTestCase {

    private func wallet() throws -> ProtoWallet {
        ProtoWallet(rootKey: try PrivateKey([UInt8](repeating: 1, count: 32)))
    }

    /// BRC-103 proves the peer holds *a* key, not the right one. Over plain HTTP an intermediary
    /// completes the handshake with its own key, so a plain-HTTP endpoint is refused by default.
    func test_aPlainHTTPEndpointIsRefused() throws {
        let http = URL(string: "http://wallet.example")!

        XCTAssertThrowsError(try RemoteStorage.client(at: http, wallet: try wallet())) {
            XCTAssertEqual($0 as? RemoteStorageError, .insecureEndpoint("http://wallet.example"))
        }
    }

    func test_httpsIsAccepted() throws {
        let https = URL(string: "https://wallet.example")!

        XCTAssertNoThrow(try RemoteStorage.client(at: https, wallet: try wallet()))
    }

    /// A local test server can opt in, deliberately and visibly.
    func test_insecureTransportCanBeAllowedExplicitly() throws {
        let http = URL(string: "http://localhost:8080")!

        XCTAssertNoThrow(
            try RemoteStorage.client(at: http, wallet: try wallet(), allowInsecureTransport: true)
        )
    }
}
