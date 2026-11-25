import Foundation
import XCTest
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// Following the user's `activeStorage` record from the configured store to the one it names.
///
/// Mirrors TS `WalletStorageManager.makeAvailable`, which takes as active the store whose user
/// record names itself, and `setActive`, which rewrites the old store's record to name the new.
final class ActiveStorageResolverTests: XCTestCase {

    /// One store: its own identity key, and the key its user record names as active.
    private actor StoreTransport: AuthenticatedTransport {
        let storageIdentityKey: String
        let activeStorage: String?
        let reachable: Bool
        private(set) var methods: [String] = []

        init(key: String, activeStorage: String?, reachable: Bool = true) {
            storageIdentityKey = key
            self.activeStorage = activeStorage
            self.reachable = reachable
        }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            guard reachable else { throw URLError(.cannotConnectToHost) }
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
            let name = request["method"]?.stringValue ?? ""
            let id = request["id"]?.intValue ?? 0
            methods.append(name)
            let result: String
            switch name {
            case "makeAvailable":
                result = #"{"storageIdentityKey":"\#(storageIdentityKey)","storageName":"store \#(storageIdentityKey)","chain":"main"}"#
            case "findOrInsertUser":
                let active = activeStorage.map { #""\#($0)""# } ?? "null"
                result = #"{"user":{"userId":7,"identityKey":"02aa","activeStorage":\#(active)},"isNew":false}"#
            default:
                result = "null"
            }
            return AuthenticatedResponse(
                statusCode: 200, headers: [:],
                body: Array(#"{"jsonrpc":"2.0","id":\#(id),"result":\#(result)}"#.utf8)
            )
        }
    }

    /// Stores by address, and the addresses a resolve connected to.
    private actor Network {
        private let stores: [URL: StoreTransport]
        private(set) var connected: [URL] = []

        init(_ stores: [URL: StoreTransport]) { self.stores = stores }

        func connect(_ url: URL) throws -> StorageClient {
            connected.append(url)
            guard let transport = stores[url] else { throw URLError(.badURL) }
            return StorageClient(endpoint: url, transport: transport)
        }
    }

    private let a = URL(string: "https://a.example/")!
    private let b = URL(string: "https://b.example/")!
    private let c = URL(string: "https://c.example/")!
    private let identityKey = "02aa"

    private func resolve(
        _ network: Network, from start: StoreTransport, at url: URL, candidates: [URL]
    ) async throws -> ActiveStorageResolution {
        try await ActiveStorageResolver.resolve(
            from: StorageClient(endpoint: url, transport: start),
            candidates: candidates,
            identityKey: identityKey,
            connect: { try await network.connect($0) }
        )
    }

    private func activeEndpoint(_ resolution: ActiveStorageResolution) -> URL? {
        if case .active(let client) = resolution { return client.endpoint }
        return nil
    }

    private func movedKey(_ resolution: ActiveStorageResolution) -> String? {
        if case .moved(let key, _) = resolution { return key }
        return nil
    }

    private func isUnsettled(_ resolution: ActiveStorageResolution) -> Bool {
        if case .unsettled = resolution { return true }
        return false
    }

    func test_unmovedStoreIsActiveWithoutTryingCandidates() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "0a")
        let network = Network([b: StoreTransport(key: "0b", activeStorage: "0b")])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b])

        XCTAssertEqual(activeEndpoint(resolution), a)
        let connected = await network.connected
        XCTAssertEqual(connected, [])
        let methods = await start.methods
        XCTAssertEqual(methods, ["makeAvailable", "findOrInsertUser"])
    }

    func test_recordNamingNoStoreLeavesTheStoreThatWasRead() async throws {
        let start = StoreTransport(key: "0a", activeStorage: nil)
        let network = Network([:])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b])

        XCTAssertEqual(activeEndpoint(resolution), a)
        let connected = await network.connected
        XCTAssertEqual(connected, [])
    }

    func test_followsTheRecordToTheCandidateItNames() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "0c")
        let network = Network([
            b: StoreTransport(key: "0b", activeStorage: "0b"),
            c: StoreTransport(key: "0c", activeStorage: "0c"),
        ])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b, c])

        XCTAssertEqual(activeEndpoint(resolution), c)
    }

    func test_followsMoreThanOneMove() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "0b")
        let network = Network([
            b: StoreTransport(key: "0b", activeStorage: "0c"),
            c: StoreTransport(key: "0c", activeStorage: "0c"),
        ])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b, c])

        XCTAssertEqual(activeEndpoint(resolution), c)
        // Each candidate is connected once, however many hops look at it.
        let connected = await network.connected
        XCTAssertEqual(connected, [b, c])
    }

    func test_moveToAnUnknownStoreIsReportedNotWrittenTo() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "0d")
        let other = StoreTransport(key: "0b", activeStorage: "0b")
        let network = Network([b: other])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b])

        guard case .moved(let key, let unreachable) = resolution else {
            return XCTFail("\(resolution)")
        }
        XCTAssertEqual(key, "0d")
        XCTAssertEqual(unreachable, [])
        // A candidate that isn't the moved-to store is only asked who it is: no user record is
        // read or inserted there.
        let methods = await other.methods
        XCTAssertEqual(methods, ["makeAvailable"])
    }

    func test_unreachableCandidateIsListedWhenTheMoveIsNotFound() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "0c")
        let network = Network([
            c: StoreTransport(key: "0c", activeStorage: "0c", reachable: false),
        ])

        let resolution = try await resolve(network, from: start, at: a, candidates: [c])

        guard case .moved(let key, let unreachable) = resolution else {
            return XCTFail("\(resolution)")
        }
        XCTAssertEqual(key, "0c")
        XCTAssertEqual(unreachable, [c])
    }

    func test_emptyRecordNamesNoStore() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "")
        let network = Network([:])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b])

        XCTAssertEqual(activeEndpoint(resolution), a)
        let connected = await network.connected
        XCTAssertEqual(connected, [])
    }

    func test_followedStoreThatNamesNoStoreIsUnsettled() async throws {
        // The configured store names B, but B's record names nothing, so B takes no writes and
        // must not be accepted as the wallet's store.
        let start = StoreTransport(key: "0a", activeStorage: "0b")
        let network = Network([b: StoreTransport(key: "0b", activeStorage: nil)])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b])

        XCTAssertTrue(isUnsettled(resolution), "\(resolution)")
    }

    func test_sameAddressWrittenTwoWaysIsConnectedOnce() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "0d")
        let network = Network([b: StoreTransport(key: "0b", activeStorage: "0b")])
        let bWithoutSlash = URL(string: "https://B.example")!

        _ = try await resolve(network, from: start, at: a, candidates: [b, bWithoutSlash])

        let connected = await network.connected
        XCTAssertEqual(connected, [b])
    }

    func test_cancelledOpenIsNotReportedAsAMove() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "0c")
        do {
            _ = try await ActiveStorageResolver.resolve(
                from: StorageClient(endpoint: a, transport: start),
                candidates: [c],
                identityKey: identityKey,
                connect: { _ in throw CancellationError() }
            )
            XCTFail("a cancelled open resolved")
        } catch is CancellationError {}
    }

    func test_unreachableCandidateIsSkipped() async throws {
        let start = StoreTransport(key: "0a", activeStorage: "0c")
        let network = Network([
            b: StoreTransport(key: "0b", activeStorage: "0b", reachable: false),
            c: StoreTransport(key: "0c", activeStorage: "0c"),
        ])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b, c])

        XCTAssertEqual(activeEndpoint(resolution), c)
    }

    func test_unreadableStartThrows() async {
        let start = StoreTransport(key: "0a", activeStorage: "0a", reachable: false)
        let network = Network([:])

        do {
            _ = try await resolve(network, from: start, at: a, candidates: [b])
            XCTFail("resolved from a store that could not be read")
        } catch {}
    }

    func test_recordsNamingEachOtherAreReportedAsMoved() async throws {
        // A switch that stopped halfway: neither store names itself.
        let start = StoreTransport(key: "0a", activeStorage: "0b")
        let network = Network([
            a: StoreTransport(key: "0a", activeStorage: "0b"),
            b: StoreTransport(key: "0b", activeStorage: "0a"),
        ])

        let resolution = try await resolve(network, from: start, at: a, candidates: [a, b])

        XCTAssertTrue(isUnsettled(resolution), "\(resolution)")
    }

    func test_newStoreThatNamesItselfIsNotTheWalletsStore() async throws {
        // A fresh store creates a record naming itself, but the configured store's record names
        // another: an entered address is only followed when the records lead there.
        let start = StoreTransport(key: "0a", activeStorage: "0d")
        let fresh = StoreTransport(key: "0b", activeStorage: "0b")
        let network = Network([b: fresh])

        let resolution = try await resolve(network, from: start, at: a, candidates: [b])

        XCTAssertEqual(movedKey(resolution), "0d")
        XCTAssertNil(activeEndpoint(resolution))
    }

    func test_endpointKeyIgnoresTrailingSlashAndHostCase() {
        XCTAssertEqual(
            ActiveStorageResolver.endpointKey(URL(string: "https://Wallet.1sat.app/")!),
            ActiveStorageResolver.endpointKey(URL(string: "https://wallet.1sat.app")!)
        )
        XCTAssertNotEqual(
            ActiveStorageResolver.endpointKey(URL(string: "https://wallet.1sat.app/a")!),
            ActiveStorageResolver.endpointKey(URL(string: "https://wallet.1sat.app/b")!)
        )
    }
}
