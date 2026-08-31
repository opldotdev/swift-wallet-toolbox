import XCTest
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
import ToolboxStorageClient
import ToolboxServices
@testable import ToolboxWallet

/// The first storage-backed, non-spending BRC-100 capability slice on `RemoteWallet`.
final class RemoteWalletBasicOperationsTests: XCTestCase {
    private enum FakeChainError: Error, Equatable, Sendable {
        case unavailable
    }

    private actor FakeChainInformation: ChainInformationService {
        let height: UInt32
        let returnedHeader: ChainBlockHeader
        let failHeight: Bool
        private(set) var requestedHeights: [UInt32] = []

        init(height: UInt32, returnedHeader: ChainBlockHeader, failHeight: Bool = false) {
            self.height = height
            self.returnedHeader = returnedHeader
            self.failHeight = failHeight
        }

        func currentHeight() async throws -> UInt32 {
            if failHeight { throw FakeChainError.unavailable }
            return height
        }

        func header(atHeight height: UInt32) async throws -> ChainBlockHeader {
            requestedHeights.append(height)
            return returnedHeader
        }

        func requests() -> [UInt32] { requestedHeights }
    }

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
        answers: [String] = [],
        chainInformation: (any ChainInformationService)? = nil
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
            auth: AuthID(identityKey: "02aa", userID: 7),
            chainInformation: chainInformation
        )
        return (wallet, transport)
    }

    func test_outputAndAuthenticationProtocolConformancesAreAvailable() throws {
        func acceptsOutputs<T: WalletOutputOperations>(_ wallet: T) {}
        func acceptsAuthentication<T: WalletAuthenticationOperations>(_ wallet: T) {}
        func acceptsChainInformation<T: WalletChainInformation>(_ wallet: T) {}
        let (wallet, _) = try wallet()

        acceptsOutputs(wallet)
        acceptsAuthentication(wallet)
        acceptsChainInformation(wallet)
    }

    func test_chainInformationForwardsHeightAndExactHeaderBytes() async throws {
        let bytes = [UInt8](repeating: 0, count: 80)
        let header = try ChainBlockHeader(height: 42, serializedBytes: bytes)
        let service = FakeChainInformation(height: 900_001, returnedHeader: header)
        let (wallet, transport) = try wallet(chainInformation: service)

        let height = try await wallet.getHeight(WalletGetHeightRequest())
        let result = try await wallet.getHeaderForHeight(WalletGetHeaderRequest(height: 42))
        let requests = await service.requests()
        let envelopes = try await transport.envelopes()

        XCTAssertEqual(height.height, 900_001)
        XCTAssertEqual(result.header, bytes)
        XCTAssertEqual(requests, [42])
        XCTAssertTrue(envelopes.isEmpty)
    }

    func test_chainInformationRequiresAnInjectedService() async throws {
        let (wallet, _) = try wallet()

        do {
            _ = try await wallet.getHeight(WalletGetHeightRequest())
            XCTFail("expected a missing-service error")
        } catch let error as WalletError {
            XCTAssertEqual(error, .chainInformationServiceUnavailable)
        }
    }

    func test_chainInformationRejectsProviderHeightMismatch() async throws {
        let header = try ChainBlockHeader(
            height: 41,
            serializedBytes: [UInt8](repeating: 0, count: 80)
        )
        let service = FakeChainInformation(height: 42, returnedHeader: header)
        let (wallet, _) = try wallet(chainInformation: service)

        do {
            _ = try await wallet.getHeaderForHeight(WalletGetHeaderRequest(height: 42))
            XCTFail("expected a height-mismatch error")
        } catch let error as WalletError {
            XCTAssertEqual(error, .chainHeaderHeightMismatch(requested: 42, returned: 41))
        }
    }

    func test_chainInformationRejectsSummaryOnlyHeader() async throws {
        let summary = ChainBlockHeader(
            height: 42,
            hash: String(repeating: "11", count: 32),
            merkleRoot: [UInt8](repeating: 2, count: 32)
        )
        let service = FakeChainInformation(height: 42, returnedHeader: summary)
        let (wallet, _) = try wallet(chainInformation: service)

        do {
            _ = try await wallet.getHeaderForHeight(WalletGetHeaderRequest(height: 42))
            XCTFail("expected a canonical-header error")
        } catch let error as WalletError {
            XCTAssertEqual(error, .chainHeaderBytesUnavailable(height: 42))
        }
    }

    func test_chainInformationForwardsProviderErrors() async throws {
        let header = try ChainBlockHeader(
            height: 0,
            serializedBytes: [UInt8](repeating: 0, count: 80)
        )
        let service = FakeChainInformation(
            height: 0,
            returnedHeader: header,
            failHeight: true
        )
        let (wallet, _) = try wallet(chainInformation: service)

        do {
            _ = try await wallet.getHeight(WalletGetHeightRequest())
            XCTFail("expected the provider error")
        } catch let error as FakeChainError {
            XCTAssertEqual(error, .unavailable)
        }
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

    func test_listActionsForwardsAndBlocksStorageCustomInstructions() async throws {
        let txid = String(repeating: "77", count: 32)
        let (wallet, transport) = try wallet(answers: ["""
            {"result":{"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":12,"status":"completed",
              "isOutgoing":false,"description":"received","labels":["income"],
              "version":1,"lockTime":0,"inputs":[],"outputs":[{
                "satoshis":12,"lockingScript":"51","spendable":true,
                "customInstructions":"storage-only secret","tags":["kind:test"],
                "outputIndex":0,"outputDescription":"received output","basket":"apps"
              }]
            }]}}
            """])
        let request = try WalletListActionsRequest(
            labels: ["income"],
            labelQueryMode: .all,
            includeLabels: true,
            includeInputs: true,
            includeOutputs: true,
            includeOutputLockingScripts: true
        )

        let result = try await wallet.listActions(request)

        XCTAssertEqual(result.totalActions, 1)
        XCTAssertEqual(result.actions[0].labels, ["income"])
        XCTAssertEqual(result.actions[0].inputs, [])
        XCTAssertEqual(result.actions[0].outputs?[0].lockingScript, [0x51])
        XCTAssertNil(
            result.actions[0].outputs?[0].customInstructions,
            "the live TypeScript wallet strips storage-private instructions"
        )
        let arguments = try await transport.envelopes()[0]["params"]?.arrayValue?[1]
        XCTAssertEqual(arguments?["labels"]?.arrayValue?.compactMap(\.stringValue), ["income"])
        XCTAssertEqual(arguments?["labelQueryMode"]?.stringValue, "all")
        XCTAssertEqual(arguments?["includeOutputs"]?.boolValue, true)
        XCTAssertEqual(arguments?["includeOutputLockingScripts"]?.boolValue, true)
    }

    func test_historyUsesTheSameSafeListActionsBoundary() async throws {
        let txid = String(repeating: "88", count: 32)
        let (wallet, _) = try wallet(answers: ["""
            {"result":{"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":1,"status":"completed",
              "isOutgoing":false,"description":"history","version":1,"lockTime":0,
              "outputs":[{"satoshis":1,"spendable":true,
                "customInstructions":"storage-only secret","tags":[],"outputIndex":0,
                "outputDescription":"output","basket":"apps"}]
            }]}}
            """])

        let result = try await wallet.history()

        XCTAssertNil(result.actions[0].outputs?[0].customInstructions)
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
