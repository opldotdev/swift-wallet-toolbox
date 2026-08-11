import XCTest
import BSVKeys
import BSVWallet
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// The whole stack against a real storage server.
///
/// Handshake, authenticated framing, JSON-RPC envelope and record decoding, in one call. Every
/// layer is tested on its own elsewhere; this is the one that proves they compose.
///
/// Skipped unless `TEST_RUNNER_LIVE_STORAGE_URL` is set, so CI stays offline:
///
///     TEST_RUNNER_LIVE_STORAGE_URL=https://wallet.1sat.app swift test --filter LiveStorageTests
///
/// It reads settings and stops. `makeAvailable` is the one call that asks the store to describe
/// itself rather than to do anything, so a run leaves nothing behind worth cleaning up.
final class LiveStorageTests: XCTestCase {

    private func liveEndpoint() throws -> URL {
        let value = ProcessInfo.processInfo.environment["TEST_RUNNER_LIVE_STORAGE_URL"]
        try XCTSkipIf(value == nil, "set TEST_RUNNER_LIVE_STORAGE_URL to run against a real server")
        return try XCTUnwrap(URL(string: value!))
    }

    /// A fresh identity per run, returned with its key so the caller can name itself to storage.
    private func throwawayWallet() throws -> (wallet: ProtoWallet, identityKey: String) {
        let root = try PrivateKey((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let identityKey = root.publicKey.compressedBytes
            .map { String(format: "%02x", $0) }.joined()
        return (ProtoWallet(rootKey: root), identityKey)
    }

    func test_aRealStoreDescribesItself() async throws {
        let endpoint = try liveEndpoint()
        let (wallet, identityKey) = try throwawayWallet()

        let client = RemoteStorage.client(at: endpoint, wallet: wallet)
        let settings = try await client.makeAvailable(AuthID(identityKey: identityKey))

        XCTAssertFalse(settings.storageIdentityKey.isEmpty)
        XCTAssertFalse(settings.storageName.isEmpty)
        XCTAssertEqual(settings.chain, ToolboxStorage.Chain.main)

        let available = await client.isAvailable
        XCTAssertTrue(available)
    }
}
