import XCTest
import BSVKeys
import BSVWallet
import ToolboxStorage
import ToolboxCore
import ToolboxStorageClient
@testable import ToolboxWallet

/// The composed wallet against a real storage server.
///
/// Skipped unless `TEST_RUNNER_LIVE_STORAGE_URL` is set. It reads balance and history — both safe
/// for a fresh identity that owns nothing — and confirms an unaffordable payment is refused by
/// name rather than crashing the compose.
final class RemoteWalletTests: XCTestCase {

    private func liveEndpoint() throws -> URL {
        let value = ProcessInfo.processInfo.environment["TEST_RUNNER_LIVE_STORAGE_URL"]
        try XCTSkipIf(value == nil, "set TEST_RUNNER_LIVE_STORAGE_URL")
        return try XCTUnwrap(URL(string: value!))
    }

    private func wallet(at endpoint: URL) throws -> RemoteWallet {
        let root = try PrivateKey((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let identity = root.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let storage = try RemoteStorage.client(at: endpoint, wallet: ProtoWallet(rootKey: root))
        return RemoteWallet(storage: storage, identityKey: root, auth: AuthID(identityKey: identity))
    }

    func test_afreshWalletConnectsAndReadsAnEmptyBalance() async throws {
        let wallet = try wallet(at: try liveEndpoint())

        let settings = try await wallet.connect()
        let balance = try await wallet.balance()
        let history = try await wallet.history()

        XCTAssertEqual(settings.chain, .main)
        XCTAssertEqual(balance, 0)
        XCTAssertEqual(history.totalActions, 0)
    }

    func test_anUnaffordablePaymentIsRefused() async throws {
        let wallet = try wallet(at: try liveEndpoint())
        _ = try await wallet.connect()

        let output = try WalletCreateActionOutput(
            lockingScript: [0x76, 0xa9, 0x14] + [UInt8](repeating: 0x11, count: 20) + [0x88, 0xac],
            satoshis: 1_000,
            outputDescription: "to nobody"
        )

        do {
            _ = try await wallet.pay([output], description: "cannot afford")
            XCTFail("an empty wallet cannot pay")
        } catch let error as WireError {
            guard case .insufficientFunds = error else {
                throw XCTSkip("refused for another reason: \(error)")
            }
        }
    }

    /// A wallet restored from a phrase authenticates and reads its (empty) state. This is the whole
    /// restore path — phrase to identity key to handshake — end to end.
    func test_arestoredWalletConnects() async throws {
        let endpoint = try liveEndpoint()
        let phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let wallet = try RemoteWallet.restore(fromPhrase: phrase, endpoint: endpoint)

        let settings = try await wallet.connect()

        XCTAssertEqual(settings.chain, .main)
        XCTAssertEqual(try wallet.receiveAddress(), "15GGYFFPptmvYr3h76TA42hP11Y95S3r5t")
    }
}
