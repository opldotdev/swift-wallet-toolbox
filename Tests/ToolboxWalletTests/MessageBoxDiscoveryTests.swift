import XCTest
import Foundation
import BSVKeys
import BSVOverlay
import BSVScript
import BSVTransaction
import ToolboxStorage
@testable import ToolboxWallet

private struct AdvertisementResolver: OverlayLookupResolving {
    let answer: LookupAnswer
    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer {
        XCTAssertEqual(question.service.rawValue, "ls_messagebox")
        return answer
    }
}

final class MessageBoxDiscoveryTests: XCTestCase, @unchecked Sendable {
    private func key(_ value: UInt8) throws -> PublicKey {
        try PrivateKey(Array(repeating: 0, count: 31) + [value]).publicKey
    }
    private func advertisement(host: String, identity: PublicKey) throws -> OutputListItem {
        let script = try PushDrop.lockingScript(fields: [identity.compressedBytes, Array(host.utf8)],
            publicKey: key(1), lockPosition: .beforeCompatibility)
        let transaction = Transaction(version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: script)], lockTime: 0)
        let beef = try BEEF(version: .v2, merklePaths: [], transactions: [.raw(transaction)], limits: StorageLimits.beef)
        return try OutputListItem(beef: beef.serialized(limits: StorageLimits.beef), outputIndex: 0)
    }
    func test_typescriptPushDropAdvertisementOverridesConfiguredFallback() async throws {
        let recipient = try key(2)
        let item = try advertisement(host: "https://recipient.example/mb", identity: recipient)
        let resolver = AdvertisementResolver(answer: try LookupAnswer(outputList: [item]))
        let host = try await MessageBoxDiscovery(resolver: resolver).host(for: recipient,
            fallback: URL(string: "https://default.example")!)
        XCTAssertEqual(host.absoluteString, "https://recipient.example/mb")
    }
    func test_unsafeOrWrongIdentityAdvertisementFallsBack() async throws {
        let recipient = try key(2)
        for item in [try advertisement(host: "http://unsafe.example", identity: recipient),
            try advertisement(host: "https://wrong.example", identity: key(3))] {
            let resolver = AdvertisementResolver(answer: try LookupAnswer(outputList: [item]))
            let host = try await MessageBoxDiscovery(resolver: resolver).host(for: recipient,
                fallback: URL(string: "https://default.example")!)
            XCTAssertEqual(host.host, "default.example")
        }
    }

    func test_privateAndReservedOverlayHostsAreRejectedWithoutRestrictingExplicitHTTPSConfiguration() throws {
        for host in ["localhost", "service.local", "service.internal", "service.test", "service.invalid",
            "0.0.0.0", "127.0.0.1", "127.1", "2130706433", "0x7f000001", "10.0.0.4",
            "100.64.0.1", "169.254.1.1", "172.16.0.1", "192.168.1.1", "198.18.0.1",
            "[::1]", "[0:0:0:0:0:0:0:1]", "[fc00::1]", "[fe80::1]", "[::ffff:127.0.0.1]",
            "message.example.com"] {
            XCTAssertNil(MessageBoxHost.advertised("https://\(host)"), host)
        }
        XCTAssertEqual(try MessageBoxHost.configured(" https://localhost:8080/api/// ").absoluteString,
            "https://localhost:8080/api")
        XCTAssertEqual(MessageBoxHost.advertised("https://message.example.org/api/")?.absoluteString,
            "https://message.example.org/api")
    }
}
