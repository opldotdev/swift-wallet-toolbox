import XCTest
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// Writes reach only the user's active storage.
///
/// Mirrors the TypeScript `WalletStorageManager`, whose writers call `getAuth(true)` and throw
/// `WERR_NOT_ACTIVE` unless the store's `storageIdentityKey` is the user's `activeStorage`. A
/// backup store holding the same keys must not be written to directly, or the two diverge.
final class ActiveStorageTests: XCTestCase {

    /// Answers by method name. `activeStorage` is what the user record names, and can change
    /// between calls the way it does when another wallet switches its active store.
    private actor RoutedTransport: AuthenticatedTransport {
        var activeStorage: String
        private(set) var methods: [String] = []

        init(activeStorage: String) { self.activeStorage = activeStorage }

        func setActiveStorage(_ key: String) { activeStorage = key }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
            let name = request["method"]?.stringValue ?? ""
            methods.append(name)
            if let reply = ActiveStorageFixture.reply(to: body, activeStorage: activeStorage) {
                return reply
            }
            // Every other call succeeds with a result no decoder will mistake for real data; the
            // tests only ask whether the call reached the wire.
            let id = request["id"]?.intValue ?? 0
            return AuthenticatedResponse(
                statusCode: 200, headers: [:],
                body: Array(#"{"jsonrpc":"2.0","id":\#(id),"result":null}"#.utf8)
            )
        }
    }

    private let endpoint = URL(string: "https://wallet.1sat.app/")!
    private let auth = AuthID(identityKey: "02aa", userID: 7)
    private let otherStore = "03cc"

    private func client(_ transport: RoutedTransport) -> StorageClient {
        StorageClient(endpoint: endpoint, transport: transport)
    }

    /// One parameter list per gated method: the auth object first, as on the wire.
    private var authParameter: JSONValue {
        .object(["identityKey": .string(auth.identityKey), "userId": .number(7)])
    }

    func test_writerListMatchesTheReferenceManager() {
        XCTAssertEqual(StorageClient.writerMethods, [
            "abortAction", "createAction", "internalizeAction", "processAction",
            "relinquishCertificate", "relinquishOutput", "insertCertificateAuth",
            "prepareNoSendExpiry", "activateNoSendExpiry", "armNoSendExpiry",
            "beginActionBatch", "extendActionBatch", "renewActionBatch",
            "commitActionBatch", "abortActionBatch",
        ])
    }

    func test_activeStorePassesWritesAndReadsTheUserOnce() async throws {
        let transport = RoutedTransport(activeStorage: ActiveStorageFixture.storageIdentityKey)
        let client = client(transport)

        _ = try await client.call("abortAction", [authParameter, .object(["reference": .string("r")])])
        _ = try await client.call("relinquishOutput", [authParameter, .object([:])])

        let methods = await transport.methods
        XCTAssertEqual(methods, ["makeAvailable", "findOrInsertUser", "abortAction", "relinquishOutput"])
        let isActive = await client.isActive
        XCTAssertEqual(isActive, true)
        let active = await client.activeStorageIdentityKey
        XCTAssertEqual(active, ActiveStorageFixture.storageIdentityKey)
    }

    func test_backupStoreRefusesEveryWriterAndNoneReachTheWire() async throws {
        let transport = RoutedTransport(activeStorage: otherStore)
        let client = client(transport)

        for method in StorageClient.writerMethods.sorted() {
            do {
                _ = try await client.call(method, [authParameter, .object([:])])
                XCTFail("\(method) wrote to a store that is not the active one")
            } catch let error as WireError {
                guard case .notActive = error else {
                    return XCTFail("\(method) threw \(error), not WERR_NOT_ACTIVE")
                }
                XCTAssertEqual(error.wireName, "WERR_NOT_ACTIVE")
            }
        }

        let methods = await transport.methods
        XCTAssertTrue(Set(methods).isDisjoint(with: StorageClient.writerMethods), "\(methods)")
        let isActive = await client.isActive
        XCTAssertEqual(isActive, false)
    }

    func test_backupStoreStillServesReaders() async throws {
        let transport = RoutedTransport(activeStorage: otherStore)
        let client = client(transport)

        for method in ["listActions", "listOutputs", "listCertificates", "getCapabilities"] {
            _ = try await client.call(method, [authParameter, .object([:])])
        }

        let methods = await transport.methods
        XCTAssertEqual(methods, ["listActions", "listOutputs", "listCertificates", "getCapabilities"])
    }

    func test_typedWriterIsRefusedOnABackupStore() async throws {
        let transport = RoutedTransport(activeStorage: otherStore)
        let client = client(transport)

        do {
            _ = try await client.abortAction(auth, WalletAbortActionRequest(reference: try WalletBase64Data(base64: "cmVm")))
            XCTFail("abortAction reached a backup store")
        } catch WireError.notActive(let message) {
            XCTAssertTrue(message.contains("active storage"), message)
        }
        let methods = await transport.methods
        XCTAssertFalse(methods.contains("abortAction"))
    }

    func test_makingThisStoreActiveElsewhereTakesEffectOnTheNextWrite() async throws {
        let transport = RoutedTransport(activeStorage: otherStore)
        let client = client(transport)

        do {
            _ = try await client.call("createAction", [authParameter, .object([:])])
            XCTFail("createAction reached a backup store")
        } catch WireError.notActive {}

        // The other wallet makes this store active. No relaunch: the refusal is read again.
        await transport.setActiveStorage(ActiveStorageFixture.storageIdentityKey)
        _ = try await client.call("createAction", [authParameter, .object([:])])

        let methods = await transport.methods
        XCTAssertEqual(methods, [
            "makeAvailable", "findOrInsertUser", "findOrInsertUser", "createAction",
        ])
        let isActive = await client.isActive
        XCTAssertEqual(isActive, true)
    }

    func test_findOrInsertUserSendsTheIdentityKeyAndReadsTheRecord() async throws {
        let transport = RoutedTransport(activeStorage: otherStore)
        let client = client(transport)

        let user = try await client.findOrInsertUser("02aa")

        XCTAssertEqual(user, StorageUser(userId: 7, identityKey: "02aa", activeStorage: otherStore))
    }
}
