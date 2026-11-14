import XCTest
import Foundation
import BSVKeys
import BSVOverlay
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxStorage
@testable import ToolboxWallet

private struct AdvertisementResolver: OverlayLookupResolving {
    let answer: LookupAnswer
    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer {
        XCTAssertEqual(question.service.rawValue, "ls_messagebox")
        return answer
    }
}

/// Records which hosts the resolver asks, and answers every lookup with no outputs.
private actor RecordingFacilitator: LookupFacilitator {
    var services: [String] = []
    var hosts: [String] = []
    func lookup(question: LookupQuestion, at host: OverlayHost) async throws -> LookupAnswer {
        services.append(question.service.rawValue)
        hosts.append(host.rawValue)
        return try LookupAnswer(outputList: [])
    }
}

final class MessageBoxDiscoveryTests: XCTestCase, @unchecked Sendable {
    private func key(_ value: UInt8) throws -> PublicKey {
        try PrivateKey(Array(repeating: 0, count: 31) + [value]).publicKey
    }
    private func item(_ script: Script) throws -> OutputListItem {
        let transaction = Transaction(version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: script)], lockTime: 0)
        let beef = try BEEF(version: .v2, merklePaths: [], transactions: [.raw(transaction)], limits: StorageLimits.beef)
        return try OutputListItem(beef: beef.serialized(limits: StorageLimits.beef), outputIndex: 0)
    }
    /// The advertisement TS `anointHost` makes, signed by the key `signer` names.
    private func advertisement(host: String, signer: UInt8) async throws -> OutputListItem {
        let wallet = ProtoWallet(rootKey: try PrivateKey(Array(repeating: 0, count: 31) + [signer]))
        return try item(try await MessageBoxAdvertiser.lockingScript(host: URL(string: host)!, wallet: wallet))
    }
    /// The two-field form with no signature, for a host `anointHost` would refuse.
    private func unsigned(host: String, identity: PublicKey) throws -> OutputListItem {
        try item(PushDrop.lockingScript(fields: [identity.compressedBytes, Array(host.utf8)],
            publicKey: key(1), lockPosition: .beforeCompatibility))
    }
    func test_typescriptPushDropAdvertisementOverridesConfiguredFallback() async throws {
        let recipient = try key(2)
        let item = try await advertisement(host: "https://recipient.example/mb", signer: 2)
        let resolver = AdvertisementResolver(answer: try LookupAnswer(outputList: [item]))
        let host = try await MessageBoxDiscovery(resolver: resolver).host(for: recipient,
            fallback: URL(string: "https://default.example")!)
        XCTAssertEqual(host.absoluteString, "https://recipient.example/mb")
    }
    func test_unsafeOrWrongIdentityAdvertisementFallsBack() async throws {
        let recipient = try key(2)
        for item in [try unsigned(host: "http://unsafe.example", identity: recipient),
            try await advertisement(host: "https://wrong.example", signer: 3)] {
            let resolver = AdvertisementResolver(answer: try LookupAnswer(outputList: [item]))
            let host = try await MessageBoxDiscovery(resolver: resolver).host(for: recipient,
                fallback: URL(string: "https://default.example")!)
            XCTAssertEqual(host.host, "default.example")
        }
    }

    /// As TS 2.7.0: an advertisement the recipient did not sign is skipped, whether it carries no
    /// signature or the recipient's signature over another host.
    func test_anAdvertisementTheRecipientDidNotSignIsSkipped() async throws {
        let recipient = try key(2)
        let signed = try await MessageBoxAdvertiser.lockingScript(host: URL(string: "https://recipient.example")!,
            wallet: ProtoWallet(rootKey: PrivateKey(Array(repeating: 0, count: 31) + [2])))
        let decoded = try PushDrop.decode(signed, lockPosition: .beforeCompatibility)
        let tampered = try item(PushDrop.lockingScript(
            fields: [recipient.compressedBytes, Array("https://attacker.example".utf8), decoded.fields[2]],
            publicKey: decoded.publicKey, lockPosition: .beforeCompatibility))
        let noSignature = try unsigned(host: "https://attacker.example", identity: recipient)
        let genuine = try item(signed)
        let resolver = AdvertisementResolver(answer: try LookupAnswer(outputList: [tampered, noSignature, genuine]))
        let host = try await MessageBoxDiscovery(resolver: resolver).host(for: recipient,
            fallback: URL(string: "https://default.example")!)
        XCTAssertEqual(host.absoluteString, "https://recipient.example")

        let forgedOnly = AdvertisementResolver(answer: try LookupAnswer(outputList: [tampered, noSignature]))
        let fallback = try await MessageBoxDiscovery(resolver: forgedOnly).host(for: recipient,
            fallback: URL(string: "https://default.example")!)
        XCTAssertEqual(fallback.host, "default.example")
    }

    func test_trackersMatchTypeScriptNetworkPresets() {
        XCTAssertEqual(MessageBoxDiscovery.slapTrackers(for: .mainnet), ["https://overlay-us-1.bsvb.tech",
            "https://overlay-eu-1.bsvb.tech", "https://overlay-ap-1.bsvb.tech", "https://users.bapp.dev"])
        XCTAssertEqual(MessageBoxDiscovery.slapTrackers(for: .testnet), ["https://testnet-users.bapp.dev"])
        XCTAssertNoThrow(try MessageBoxDiscovery())
        XCTAssertNoThrow(try MessageBoxDiscovery(network: .testnet))
    }

    func test_testnetDiscoveryAsksOnlyTestnetTrackersThenFallsBack() async throws {
        let facilitator = RecordingFacilitator()
        let host = try await MessageBoxDiscovery(network: .testnet, facilitator: facilitator)
            .host(for: key(2), fallback: URL(string: "https://default.example")!)
        XCTAssertEqual(host.host, "default.example")
        let hosts = await facilitator.hosts, services = await facilitator.services
        XCTAssertFalse(hosts.isEmpty)
        XCTAssertEqual(Set(hosts), ["https://testnet-users.bapp.dev"])
        XCTAssertEqual(Set(services), ["ls_slap"])
    }

    func test_mainnetDiscoveryAsksOnlyMainnetTrackers() async throws {
        let facilitator = RecordingFacilitator()
        _ = try await MessageBoxDiscovery(network: .mainnet, facilitator: facilitator)
            .host(for: key(2), fallback: URL(string: "https://default.example")!)
        let hosts = await facilitator.hosts
        XCTAssertEqual(Set(hosts), Set(MessageBoxDiscovery.mainnetSLAPTrackers))
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
