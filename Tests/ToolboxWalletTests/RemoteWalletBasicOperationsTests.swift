import XCTest
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
import ToolboxStorageClient
@testable import ToolboxWallet

/// The first storage-backed, non-spending BRC-100 capability slice on `RemoteWallet`.
final class RemoteWalletBasicOperationsTests: XCTestCase {
    private actor FakeTransport: AuthenticatedTransport {
        private var answers: [String]
        private(set) var bodies: [[UInt8]] = []

        init(_ answers: [String]) {
            self.answers = answers
        }

        func send(
            method: String,
            path: String,
            query: String?,
            headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            let requestBody = body ?? []
            bodies.append(requestBody)
            guard !answers.isEmpty else {
                return AuthenticatedResponse(statusCode: 500, headers: [:], body: [])
            }

            let answer = answers.removeFirst()
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(requestBody))
            var response = try JSONDecoder().decode(
                JSONValue.self, from: Data(answer.utf8)
            ).objectValue ?? [:]
            response["jsonrpc"] = .string("2.0")
            response["id"] = request["id"] ?? .number(1)
            return AuthenticatedResponse(
                statusCode: 200,
                headers: [:],
                body: Array(try JSONEncoder().encode(JSONValue.object(response)))
            )
        }

        func envelopes() throws -> [JSONValue] {
            try bodies.map { try JSONDecoder().decode(JSONValue.self, from: Data($0)) }
        }
    }

    private func wallet(
        answers: [String] = []
    ) throws -> (RemoteWallet, FakeTransport) {
        let transport = FakeTransport(answers)
        let storage = StorageClient(
            endpoint: URL(string: "https://storage.example/")!,
            transport: transport
        )
        let key = try PrivateKey([UInt8](repeating: 1, count: 32))
        let wallet = RemoteWallet(
            storage: storage,
            identityKey: key,
            auth: AuthID(identityKey: "02aa", userID: 7)
        )
        return (wallet, transport)
    }

    func test_outputAndAuthenticationProtocolConformancesAreAvailable() throws {
        func acceptsOutputs<T: WalletOutputOperations>(_ wallet: T) {}
        func acceptsAuthentication<T: WalletAuthenticationOperations>(_ wallet: T) {}
        let (wallet, _) = try wallet()

        acceptsOutputs(wallet)
        acceptsAuthentication(wallet)
    }

    func test_abortActionReturnsStoragesActualDecision() async throws {
        let (wallet, transport) = try wallet(
            answers: [#"{"result":{"aborted":false}}"#]
        )
        let reference = try WalletBase64Data([1, 2, 3])

        let result = try await wallet.abortAction(
            WalletAbortActionRequest(reference: reference)
        )

        XCTAssertFalse(result.aborted)
        let params = try await transport.envelopes()[0]["params"]?.arrayValue
        XCTAssertEqual(params?[1]["reference"]?.stringValue, "AQID")
    }

    func test_listOutputsReturnsTheStorageResult() async throws {
        let (wallet, transport) = try wallet(answers: ["""
            {"result":{"totalOutputs":1,"outputs":[{
              "outpoint":"0000000000000000000000000000000000000000000000000000000000000001.2",
              "satoshis":42,"spendable":true,"lockingScript":"51",
              "customInstructions":"open","tags":["kind:test"],"labels":["received"]
            }]}}
            """])

        let result = try await wallet.listOutputs(
            try WalletListOutputsRequest(
                basket: "application basket",
                tags: ["kind:test"],
                include: .lockingScripts,
                includeCustomInstructions: true,
                includeTags: true,
                includeLabels: true
            )
        )

        XCTAssertEqual(result.totalOutputs, 1)
        XCTAssertEqual(result.outputs[0].satoshis, 42)
        XCTAssertEqual(result.outputs[0].lockingScript, [0x51])
        XCTAssertEqual(result.outputs[0].customInstructions, "open")
        XCTAssertEqual(result.outputs[0].tags, ["kind:test"])
        let arguments = try await transport.envelopes()[0]["params"]?.arrayValue?[1]
        XCTAssertEqual(arguments?["basket"]?.stringValue, "application basket")
    }

    func test_relinquishOutputMapsSuccessfulStorageUpdateToBRC100Result() async throws {
        let (wallet, transport) = try wallet(answers: [#"{"result":1}"#])
        let output = try Outpoint(
            "0000000000000000000000000000000000000000000000000000000000000001.2"
        )

        let result = try await wallet.relinquishOutput(
            try WalletRelinquishOutputRequest(basket: "application basket", output: output)
        )

        XCTAssertTrue(result.relinquished)
        let arguments = try await transport.envelopes()[0]["params"]?.arrayValue?[1]
        XCTAssertEqual(arguments?["basket"]?.stringValue, "application basket")
        XCTAssertEqual(arguments?["output"]?.stringValue, output.description)
    }

    func test_authenticationQueriesAreImmediateForAConfiguredRemoteWallet() async throws {
        let (wallet, transport) = try wallet()

        let current = try await wallet.isAuthenticated(WalletIsAuthenticatedRequest())
        let waited = try await wallet.waitForAuthentication(
            WalletWaitForAuthenticationRequest()
        )

        XCTAssertTrue(current.authenticated)
        XCTAssertTrue(waited.authenticated)
        let envelopes = try await transport.envelopes()
        XCTAssertTrue(envelopes.isEmpty)
    }

    func test_networkComesFromRemoteStorageSettings() async throws {
        let (wallet, _) = try wallet(answers: ["""
            {"result":{
              "storageIdentityKey":"02bb","storageName":"test storage","chain":"test"
            }}
            """])

        let result = try await wallet.getNetwork(WalletGetNetworkRequest())

        XCTAssertEqual(result.network, .testnet)
    }

    func test_versionMatchesTheLiveInteroperableWalletIdentifier() async throws {
        let (wallet, transport) = try wallet()

        let result = try await wallet.getVersion(WalletGetVersionRequest())

        XCTAssertEqual(result.version, "wallet-brc100-1.0.0")
        let envelopes = try await transport.envelopes()
        XCTAssertTrue(envelopes.isEmpty)
    }
}
