import XCTest
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// The JSON-RPC layer.
///
/// The transport is faked so that every failure a real server can produce — a typed error, a
/// truncated body, a reply in some other protocol — is reproducible without one. Authentication is
/// already proved elsewhere; what is under test here is the envelope.
final class StorageClientTests: XCTestCase {

    /// Records what was sent and answers with whatever the test set.
    private actor FakeTransport: AuthenticatedTransport {
        private(set) var bodiesSent: [[UInt8]] = []
        private var answers: [AuthenticatedResponse]

        init(answering answers: [AuthenticatedResponse]) {
            self.answers = answers
        }

        init(json: String, statusCode: Int = 200) {
            self.answers = [
                AuthenticatedResponse(
                    statusCode: statusCode, headers: [:], body: Array(json.utf8)
                )
            ]
        }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            bodiesSent.append(body ?? [])
            guard !answers.isEmpty else {
                return AuthenticatedResponse(statusCode: 500, headers: [:], body: [])
            }
            let answer = answers.removeFirst()
            return withEnvelope(answer, echoing: body)
        }

        /// A real server stamps `jsonrpc` and echoes the request `id`. The fixtures carry only the
        /// meaningful part (result or error), so the double adds the envelope the client now
        /// requires — including the id it read from the request.
        private func withEnvelope(
            _ answer: AuthenticatedResponse, echoing requestBody: [UInt8]?
        ) -> AuthenticatedResponse {
            guard var object = (try? JSONDecoder().decode(
                JSONValue.self, from: Data(answer.body)
            ))?.objectValue else {
                return answer
            }
            let id = (try? JSONDecoder().decode(
                JSONValue.self, from: Data(requestBody ?? [])
            ))?["id"] ?? .number(1)
            object["jsonrpc"] = .string("2.0")
            object["id"] = id
            let body = (try? JSONEncoder().encode(JSONValue.object(object))).map(Array.init) ?? []
            return AuthenticatedResponse(
                statusCode: answer.statusCode, headers: answer.headers, body: body
            )
        }

        /// The request bodies, decoded, so a test can assert the envelope rather than a string.
        func sentEnvelopes() throws -> [JSONValue] {
            try bodiesSent.map { try JSONDecoder().decode(JSONValue.self, from: Data($0)) }
        }
    }

    private let endpoint = URL(string: "https://wallet.1sat.app/")!
    private let auth = AuthID(identityKey: "02aa", userID: 7)

    // MARK: - The envelope

    func test_aCallSendsAJSONRPCEnvelope() async throws {
        let transport = FakeTransport(json: #"{"result": 42}"#)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        _ = try await client.call("listOutputs", [.object(auth.jsonObject)])

        let envelope = try await transport.sentEnvelopes()[0]
        XCTAssertEqual(envelope["jsonrpc"]?.stringValue, "2.0")
        XCTAssertEqual(envelope["method"]?.stringValue, "listOutputs")
        XCTAssertEqual(envelope["id"]?.intValue, 1)
    }

    /// The first parameter is always the caller's identity. Storage decides which records to hand
    /// back from it, so a call that dropped it would read somebody else's wallet or nobody's.
    func test_theFirstParameterIsTheCallerIdentity() async throws {
        let transport = FakeTransport(json: #"{"result": null}"#)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        _ = try await client.call("listActions", [.object(auth.jsonObject), .number(5)])

        let params = try await transport.sentEnvelopes()[0]["params"]?.arrayValue
        XCTAssertEqual(params?.first?["identityKey"]?.stringValue, "02aa")
        XCTAssertEqual(params?.first?["userId"]?.intValue, 7)
        XCTAssertEqual(params?.count, 2, "positional parameters keep their order and count")
    }

    /// Identifiers must not repeat within a connection, or a reply cannot be matched to its call.
    func test_eachCallTakesTheNextIdentifier() async throws {
        let transport = FakeTransport(answering: (0..<3).map { _ in
            AuthenticatedResponse(statusCode: 200, headers: [:], body: Array(#"{"result":1}"#.utf8))
        })
        let client = StorageClient(endpoint: endpoint, transport: transport)

        for _ in 0..<3 { _ = try await client.call("ping", []) }

        let ids = try await transport.sentEnvelopes().compactMap { $0["id"]?.intValue }
        XCTAssertEqual(ids, [1, 2, 3])
    }

    func test_theResultIsReturned() async throws {
        let transport = FakeTransport(json: #"{"result": {"spendable": true, "satoshis": 1200}}"#)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        let result = try await client.call("findOutputs", [])

        XCTAssertEqual(result["spendable"]?.boolValue, true)
        XCTAssertEqual(result["satoshis"]?.intValue, 1200)
    }

    /// JSON-RPC allows a null result, and it is not the same as a missing one.
    func test_aNullResultIsAnAnswer() async throws {
        let transport = FakeTransport(json: #"{"result": null}"#)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        let result = try await client.call("merklePath", [])

        XCTAssertEqual(result, .null)
    }

    // MARK: - Failures

    /// The reason `WireError` exists: an application must be able to tell this from a server
    /// fault, and only the name distinguishes them.
    func test_aServerErrorIsRaisedWithItsOwnName() async throws {
        let transport = FakeTransport(json: """
            {"error": {"name": "WERR_INSUFFICIENT_FUNDS", "message": "need 500 more"}}
            """)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        do {
            _ = try await client.call("createAction", [])
            XCTFail("a reported failure must not return a result")
        } catch let error as WireError {
            XCTAssertEqual(error, .insufficientFunds("need 500 more"))
        }
    }

    /// A malformed server could send both. Preferring the result would turn a reported failure
    /// into a silent success, which for a wallet means a payment that did not happen.
    func test_anErrorMemberWinsOverAResultMember() async throws {
        let transport = FakeTransport(json: """
            {"result": {"txid": "ab"}, "error": {"name": "WERR_UNAUTHORIZED", "message": "no"}}
            """)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        do {
            _ = try await client.call("processAction", [])
            XCTFail("a response carrying an error must not be treated as a success")
        } catch let error as WireError {
            XCTAssertEqual(error, .unauthorized("no"))
        }
    }

    func test_aBodyThatIsNotJSONIsReported() async throws {
        let transport = FakeTransport(json: "<html>gateway timeout</html>")
        let client = StorageClient(endpoint: endpoint, transport: transport)

        do {
            _ = try await client.call("listOutputs", [])
            XCTFail("an unreadable body is not a result")
        } catch let error as StorageClientError {
            XCTAssertEqual(error, .unreadableResponse(method: "listOutputs"))
        }
    }

    /// An HTTP failure with no error member is worth reporting as itself. Calling it a parse
    /// problem would send somebody looking in the wrong place.
    func test_anHTTPFailureIsReportedAsOne() async throws {
        let transport = FakeTransport(json: "{}", statusCode: 503)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        do {
            _ = try await client.call("listOutputs", [])
            XCTFail("a 503 with no result is not a result")
        } catch let error as StorageClientError {
            XCTAssertEqual(error, .httpFailure(method: "listOutputs", statusCode: 503))
        }
    }

    // MARK: - Availability

    func test_theClientIsUnavailableUntilSettingsAreRead() async throws {
        let transport = FakeTransport(json: """
            {"result": {"storageIdentityKey": "02bb", "storageName": "1sat", "chain": "main"}}
            """)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        let before = await client.isAvailable
        let settings = try await client.makeAvailable(auth)
        let after = await client.isAvailable

        XCTAssertFalse(before)
        XCTAssertTrue(after)
        XCTAssertEqual(settings.storageIdentityKey, "02bb")
        XCTAssertEqual(settings.chain, .main)
    }

    /// Settings are read once. A second call must not spend a network round trip.
    func test_settingsAreReadOnlyOnce() async throws {
        let transport = FakeTransport(json: """
            {"result": {"storageIdentityKey": "02bb", "storageName": "1sat", "chain": "main"}}
            """)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        _ = try await client.makeAvailable(auth)
        _ = try await client.makeAvailable(auth)

        let calls = await transport.bodiesSent.count
        XCTAssertEqual(calls, 1)
    }

    /// A chain name we do not recognise is refused rather than guessed. Guessing here would point
    /// a mainnet wallet at testnet records.
    func test_anUnknownChainIsRefused() async throws {
        let transport = FakeTransport(json: """
            {"result": {"storageIdentityKey": "02bb", "storageName": "1sat", "chain": "regtest"}}
            """)
        let client = StorageClient(endpoint: endpoint, transport: transport)

        do {
            _ = try await client.makeAvailable(auth)
            XCTFail("an unrecognised chain must not be accepted")
        } catch let error as StorageClientError {
            XCTAssertEqual(error, .unreadableResponse(method: "makeAvailable"))
        }
    }

    func test_aClientIsNotAStorageProvider() {
        let client = StorageClient(
            endpoint: endpoint, transport: FakeTransport(json: "{}")
        )

        XCTAssertFalse(client.isStorageProvider, "it forwards to storage, it does not own records")
    }
}
