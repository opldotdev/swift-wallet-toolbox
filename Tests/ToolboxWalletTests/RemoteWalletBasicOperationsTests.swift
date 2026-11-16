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
            let scriptsSettings = answers.first?.contains("storageIdentityKey") ?? false
            if let reply = ActiveStorageFixture.reply(
                to: body, answeringSettings: !scriptsSettings
            ) { return reply }
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

    /// BRC-112, as TS `Wallet.validateListOutputsArgs` (`test/Wallet/list/listOutputs.brc112.test.ts`):
    /// `balance default` asks storage for the default basket with the wallet-balance tag, and the
    /// answer is the satoshi sum with no outputs. The sum can pass `UInt32.max`.
    func test_aBalanceBasketAsksStorageForTheBasketsBalance() async throws {
        let (wallet, transport) = try wallet(answers: [#"{"result":{"totalOutputs":5000000000,"outputs":[]}}"#])

        let result = try await wallet.listOutputs(try WalletListOutputsRequest(basket: "balance default"))

        XCTAssertEqual(result.totalOutputs, 5_000_000_000)
        XCTAssertEqual(result.outputs, [])
        let arguments = try await transport.envelopes()[0]["params"]?.arrayValue?[1]
        XCTAssertEqual(arguments?["basket"]?.stringValue, "default")
        XCTAssertEqual(arguments?["tags"]?.arrayValue?.compactMap(\.stringValue), [ListOutputsSpecOp.walletBalance])
    }

    /// The prefix is read after the SDK's trim and lowercase, and the caller's tags come first.
    func test_aBalanceBasketIsReadAsTheSDKNormalizesItAndKeepsTheCallersTags() async throws {
        let (wallet, transport) = try wallet(answers: [#"{"result":{"totalOutputs":7,"outputs":[]}}"#])

        _ = try await wallet.listOutputs(try WalletListOutputsRequest(
            basket: "  Balance Tickets ", tags: ["kind:test"], tagQueryMode: .all
        ))

        let arguments = try await transport.envelopes()[0]["params"]?.arrayValue?[1]
        XCTAssertEqual(arguments?["basket"]?.stringValue, "tickets")
        XCTAssertEqual(arguments?["tags"]?.arrayValue?.compactMap(\.stringValue),
                       ["kind:test", ListOutputsSpecOp.walletBalance])
        XCTAssertEqual(arguments?["tagQueryMode"]?.stringValue, "all")
    }

    /// The prefix is matched on UTF-8 bytes, as TS `startsWith` matches code units: a combining
    /// mark right after `balance ` joins the space into one character, which `hasPrefix` would miss.
    func test_aBalancePrefixFollowedByACombiningMarkIsStillABalanceRequest() async throws {
        let (wallet, transport) = try wallet(answers: [#"{"result":{"totalOutputs":9,"outputs":[]}}"#])

        let result = try await wallet.listOutputs(try WalletListOutputsRequest(basket: "balance \u{301}tickets"))

        XCTAssertEqual(result.totalOutputs, 9)
        let arguments = try await transport.envelopes()[0]["params"]?.arrayValue?[1]
        XCTAssertEqual(arguments?["basket"]?.stringValue?.unicodeScalars.map(\.value),
                       "\u{301}tickets".unicodeScalars.map(\.value))
        XCTAssertEqual(arguments?["tags"]?.arrayValue?.compactMap(\.stringValue), [ListOutputsSpecOp.walletBalance])
    }

    /// `balance p <module> <basket>` is refused before storage is asked, with the TS wording.
    /// Whitespace after `balance ` does not get round it: storage trims the basket it receives,
    /// so the remainder is trimmed before the check (stricter than TS, which answers 0).
    func test_aBalanceOfAModuleBasketIsRefused() async throws {
        let (wallet, transport) = try wallet()
        let baskets = [
            "balance p color abc", "balance p color balance abc", "balance p btms",
            "balance  p color abc", "balance \tp color abc", "balance \u{00A0}p color abc", "Balance P Color ABC",
            "balance p \u{301}color abc",
        ]
        for basket in baskets {
            do {
                _ = try await wallet.listOutputs(try WalletListOutputsRequest(basket: basket))
                XCTFail("\(basket) was accepted")
            } catch let WireError.invalidParameter(name, message) {
                XCTAssertEqual(name, "basket")
                XCTAssertEqual(message, "not a BRC-99 module basket: BRC-112 rejects `balance p <module> <basket>`; "
                    + "use `p <module> balance <basket>` if the module offers it.")
            }
        }
        let sent = try await transport.envelopes()
        XCTAssertTrue(sent.isEmpty)
    }

    /// Extra whitespace after the prefix is trimmed, as storage would trim it: `balance  default`
    /// is the default basket's balance (TS looks up the literal ` default` and answers 0).
    func test_whitespaceAfterTheBalancePrefixIsTrimmed() async throws {
        let (wallet, transport) = try wallet(answers: [#"{"result":{"totalOutputs":3,"outputs":[]}}"#])

        _ = try await wallet.listOutputs(try WalletListOutputsRequest(basket: "balance  default"))

        let arguments = try await transport.envelopes()[0]["params"]?.arrayValue?[1]
        XCTAssertEqual(arguments?["basket"]?.stringValue, "default")
        XCTAssertEqual(arguments?["tags"]?.arrayValue?.compactMap(\.stringValue), [ListOutputsSpecOp.walletBalance])
    }

    /// Every other member of the request reaches storage as the caller set it.
    func test_aBalanceRequestKeepsTheCallersOtherArguments() async throws {
        let (wallet, transport) = try wallet(answers: [#"{"result":{"totalOutputs":0,"outputs":[]}}"#])

        _ = try await wallet.listOutputs(try WalletListOutputsRequest(
            basket: "balance tickets", include: .entireTransactions, includeCustomInstructions: true,
            includeTags: true, includeLabels: true, pagination: try WalletPagination(limit: 25, offset: 50),
            seekPermission: false
        ))

        let arguments = try await transport.envelopes()[0]["params"]?.arrayValue?[1]
        XCTAssertEqual(arguments?["includeTransactions"]?.boolValue, true)
        XCTAssertEqual(arguments?["includeLockingScripts"]?.boolValue, false)
        XCTAssertEqual(arguments?["includeCustomInstructions"]?.boolValue, true)
        XCTAssertEqual(arguments?["includeTags"]?.boolValue, true)
        XCTAssertEqual(arguments?["includeLabels"]?.boolValue, true)
        XCTAssertEqual(arguments?["limit"]?.intValue, 25)
        XCTAssertEqual(arguments?["offset"]?.intValue, 50)
        XCTAssertEqual(arguments?["seekPermission"]?.boolValue, false)
        XCTAssertEqual(arguments?["tagQueryMode"]?.stringValue, "any")
    }

    /// A caller may send the most tags a request allows; the balance tag is added on top, as TS
    /// appends it after validation.
    func test_aBalanceRequestWithTheMostTagsStillBuilds() async throws {
        let (wallet, transport) = try wallet(answers: [#"{"result":{"totalOutputs":0,"outputs":[]}}"#])
        let tags = (0..<WalletABILimits.standard.maximumTagCount).map { "t\($0)" }

        _ = try await wallet.listOutputs(try WalletListOutputsRequest(basket: "balance tickets", tags: tags))

        let sent = try await transport.envelopes()[0]["params"]?.arrayValue?[1]["tags"]?.arrayValue?
            .compactMap(\.stringValue)
        XCTAssertEqual(sent, tags + [ListOutputsSpecOp.walletBalance])
    }

    /// The 300-byte bound is on the whole `balance <basket>` string, as TS validates the basket
    /// before cutting the prefix.
    func test_theBasketBoundCoversTheWholeBalanceBasket() async throws {
        let (wallet, transport) = try wallet(answers: [#"{"result":{"totalOutputs":0,"outputs":[]}}"#])
        let longest = "balance " + String(repeating: "a", count: 292)
        _ = try await wallet.listOutputs(try WalletListOutputsRequest(basket: longest))
        let sentBasket = try await transport.envelopes()[0]["params"]?.arrayValue?[1]["basket"]?.stringValue
        XCTAssertEqual(sentBasket, String(repeating: "a", count: 292))

        do {
            _ = try await wallet.listOutputs(try WalletListOutputsRequest(basket: longest + "a"))
            XCTFail("a 301-byte basket was accepted")
        } catch let WireError.invalidParameter(name, message) {
            XCTAssertEqual(name, "basket")
            XCTAssertEqual(message, "no more than 300 length.")
        }
        let sentCount = try await transport.envelopes().count
        XCTAssertEqual(sentCount, 1)
    }

    /// The balance tag goes last even when the caller already sent it or another special-operation
    /// tag; storage acts on the first special-operation tag it finds (TS `resolveTagSpecOp`).
    func test_theBalanceTagIsAppendedAfterTheCallersSpecialOperationTags() async throws {
        let (wallet, transport) = try wallet(answers: [
            #"{"result":{"totalOutputs":0,"outputs":[]}}"#, #"{"result":{"totalOutputs":0,"outputs":[]}}"#,
        ])
        _ = try await wallet.listOutputs(try WalletListOutputsRequest(
            basket: "balance tickets", tags: [ListOutputsSpecOp.walletBalance]))
        _ = try await wallet.listOutputs(try WalletListOutputsRequest(
            basket: "balance tickets", tags: [ListOutputsSpecOp.basketPrefixOutputs, "color"]))

        let sent = try await transport.envelopes().map {
            $0["params"]?.arrayValue?[1]["tags"]?.arrayValue?.compactMap(\.stringValue)
        }
        XCTAssertEqual(sent[0], [ListOutputsSpecOp.walletBalance, ListOutputsSpecOp.walletBalance])
        XCTAssertEqual(sent[1], [ListOutputsSpecOp.basketPrefixOutputs, "color", ListOutputsSpecOp.walletBalance])
    }

    /// Only a basket that starts with `balance ` is a balance request. A module's own
    /// `p <module> balance <basket>` and look-alikes go to storage without the balance tag, and
    /// storage normalizes them as it does any basket.
    func test_otherBasketsAreNotBalanceRequests() async throws {
        let baskets = ["p color balance abc", "balancer", "balance", "my balance default", " Tickets ", "Balancer"]
        let (wallet, transport) = try wallet(answers: baskets.map { _ in #"{"result":{"totalOutputs":0,"outputs":[]}}"# })
        for basket in baskets {
            _ = try await wallet.listOutputs(try WalletListOutputsRequest(basket: basket))
        }
        let sent = try await transport.envelopes().map { $0["params"]?.arrayValue?[1] }
        XCTAssertEqual(sent.map { $0?["basket"]?.stringValue },
                       ["p color balance abc", "balancer", "balance", "my balance default", "tickets", "balancer"])
        XCTAssertTrue(sent.allSatisfy { $0?["tags"]?.arrayValue?.isEmpty == true })
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

    // MARK: - balance

    /// A page of `count` outputs of `satoshis` each, against `total` matching outputs.
    private func outputsPage(count: Int, satoshis: Int, total: Int, txidByte: String) -> String {
        let txid = String(repeating: txidByte, count: 32)
        let outputs = (0..<count).map {
            #"{"outpoint":"\#(txid).\#($0)","satoshis":\#(satoshis),"spendable":true}"#
        }.joined(separator: ",")
        return #"{"result":{"totalOutputs":\#(total),"outputs":[\#(outputs)]}}"#
    }

    /// Storage answers a listing without a limit with ten rows, so `balance` asks for the largest
    /// page and keeps reading until it has `totalOutputs`.
    func test_balanceReadsEveryPageOfTheBasket() async throws {
        let pageSize = Int(WalletABILimits.maximumProtocolPageSize)
        let (wallet, transport) = try wallet(answers: [
            outputsPage(count: pageSize, satoshis: 1, total: pageSize + 2, txidByte: "aa"),
            outputsPage(count: 2, satoshis: 5, total: pageSize + 2, txidByte: "bb"),
        ])

        let balance = try await wallet.balance()

        XCTAssertEqual(balance, Int64(pageSize) + 10)
        let envelopes = try await transport.envelopes()
        XCTAssertEqual(envelopes.count, 2)
        let pages = envelopes.compactMap { $0["params"]?.arrayValue?[1] }
        XCTAssertEqual(pages.map { $0["basket"] }, [.string("default"), .string("default")])
        XCTAssertEqual(pages.map { $0["limit"] }, [.number(Double(pageSize)), .number(Double(pageSize))])
        XCTAssertEqual(pages.map { $0["offset"] }, [.number(0), .number(Double(pageSize))])
    }

    func test_balanceStopsAfterOneShortPage() async throws {
        let (wallet, transport) = try wallet(answers: [
            outputsPage(count: 3, satoshis: 7, total: 3, txidByte: "cc"),
        ])

        let balance = try await wallet.balance(basket: "Savings ")

        XCTAssertEqual(balance, 21)
        let envelopes = try await transport.envelopes()
        XCTAssertEqual(envelopes.count, 1)
        XCTAssertEqual(envelopes.first?["params"]?.arrayValue?[1]["basket"], .string("savings"))
    }
}
