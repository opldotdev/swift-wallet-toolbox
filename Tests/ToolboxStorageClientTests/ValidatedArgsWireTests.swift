import XCTest
import BSVCore
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// The storage calls that carry validated arguments, byte for byte against the reference.
///
/// Storage does not validate these again: it reads `outpoint.txid`, the derived flags and the
/// filled-in defaults exactly as sent. Each fixture is the `JSON.stringify` text the TypeScript
/// client sends for the same request, written out from `@bsv/sdk` `validationHelpers.ts`
/// (`validateCreateActionArgs`, `validateCreateActionInput`, `validateCreateActionOutput`,
/// `validateCreateActionOptions`, `validateListOutputsArgs`, `validateListActionsArgs`,
/// `validateListCertificatesArgs`), the signer's `removeUnlockScripts`, and
/// `StorageClientBase.createAction`. Object members are in those literals' order.
final class ValidatedArgsWireTests: XCTestCase {

    private actor RecordingTransport: AuthenticatedTransport {
        private let result: String
        private(set) var bodies: [String] = []

        init(result: String) { self.result = result }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            let bytes = body ?? []
            bodies.append(String(decoding: bytes, as: UTF8.self))
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(bytes))
            let response = JSONValue.object([
                "jsonrpc": .string("2.0"),
                "id": request["id"] ?? .number(1),
                "result": try JSONDecoder().decode(JSONValue.self, from: Data(result.utf8)),
            ])
            return AuthenticatedResponse(
                statusCode: 200, headers: [:], body: Array(try JSONEncoder().encode(response))
            )
        }
    }

    private let a = String(repeating: "aa", count: 32)
    private let b = String(repeating: "bb", count: 32)
    private let c = String(repeating: "cc", count: 32)
    private let auth = AuthID(identityKey: "02aa", userID: 7)

    /// Two caller inputs (one declaring a length, one carrying a script), one output with an
    /// unnormalised basket and tag, an unnormalised label, and every option collection non-empty.
    private func fixtureRequest() throws -> WalletCreateActionRequest {
        try WalletCreateActionRequest(
            description: "Fixture payment",
            inputs: [
                try WalletCreateActionInput(
                    outpoint: try Outpoint("\(a).1"),
                    inputDescription: "spend the ordinal",
                    unlockingScriptLength: 73
                ),
                try WalletCreateActionInput(
                    outpoint: try Outpoint("\(a).2"),
                    inputDescription: "spend with a script",
                    unlockingScript: [0x51, 0x52],
                    sequenceNumber: 7
                ),
            ],
            outputs: [
                try WalletCreateActionOutput(
                    lockingScript: [0x76, 0xa9], satoshis: 1_000, outputDescription: "to someone",
                    basket: " Ordinals ", customInstructions: "keep", tags: ["Tag A"]
                ),
            ],
            labels: ["Fixture"],
            options: try WalletCreateActionOptions(
                knownTransactionIDs: [try TransactionID(displayHex: c)],
                noSend: true,
                noSendChange: [try Outpoint("\(b).3")],
                randomizeOutputs: false
            )
        )
    }

    /// `validateCreateActionArgs` + `removeUnlockScripts`, with `signAndProcess: false` (this
    /// wallet always signs) and the `includeAllSourceTransactions` the `Wallet` writes over it.
    private var fixtureArguments: String {
        #"{"description":"Fixture payment","inputs":[{"outpoint":{"txid":"\#(a)","vout":1},"inputDescription":"spend the ordinal","unlockingScriptLength":73,"sequenceNumber":4294967295},{"outpoint":{"txid":"\#(a)","vout":2},"inputDescription":"spend with a script","unlockingScriptLength":2,"sequenceNumber":7}],"outputs":[{"lockingScript":"76a9","satoshis":1000,"outputDescription":"to someone","basket":"ordinals","customInstructions":"keep","tags":["tag a"]}],"lockTime":0,"version":1,"labels":["fixture"],"options":{"signAndProcess":false,"acceptDelayedBroadcast":true,"knownTxids":["\#(c)"],"returnTXIDOnly":false,"noSend":true,"noSendChange":[{"txid":"\#(b)","vout":3}],"sendWith":[],"randomizeOutputs":false},"isSendWith":false,"isDelayed":true,"isNoSend":true,"isNewTx":true,"isRemixChange":false,"isSignAction":true,"includeAllSourceTransactions":true,"isTestWerrReviewActions":false}"#
    }

    // MARK: - createAction

    func test_createActionArgumentsMatchTheReferenceFixture() throws {
        let arguments = try StorageClient.createActionWireArguments(
            for: try fixtureRequest(), includeAllSourceTransactions: true
        )
        XCTAssertEqual(arguments.serialized(), fixtureArguments)
    }

    func test_createActionRequestBodyMatchesTheReferenceFixture() async throws {
        let transport = RecordingTransport(
            result: #"{"reference":"cmVm","version":1,"lockTime":0,"inputs":[],"outputs":[]}"#
        )
        let client = StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
        _ = try await client.createAction(auth, try fixtureRequest(), includeAllSourceTransactions: true)

        let bodies = await transport.bodies
        XCTAssertEqual(bodies.count, 1)
        XCTAssertEqual(
            bodies.first,
            #"{"jsonrpc":"2.0","method":"createAction","params":[{"identityKey":"02aa","userId":7},\#(fixtureArguments)],"id":1}"#
        )
    }

    /// `StorageClientBase.createAction` drops `inputBEEF` when there are no caller inputs.
    func test_createActionDropsInputBEEFWithoutCallerInputs() throws {
        let source = Transaction(
            version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: try Script(bytes: [0x51], maximumByteCount: 10))],
            lockTime: 0
        )
        let beef = try BEEF(merklePaths: [], transactions: [.raw(source)], limits: StorageLimits.beef)
        let request = try WalletCreateActionRequest(
            description: "no caller inputs",
            inputBEEF: beef,
            outputs: [try WalletCreateActionOutput(lockingScript: [0x51], satoshis: 1, outputDescription: "an output")]
        )

        XCTAssertNil(try StorageClient.createActionWireArguments(for: request)["inputBEEF"])
        // The validated arguments still carry it; BRC-177 sends those unchanged.
        XCTAssertNotNil(try StorageClient.validatedArguments(for: request)["inputBEEF"])
        XCTAssertNotNil(try StorageClient.noSendExpiryTarget(try WalletCreateActionRequest(
            description: "protected action",
            inputBEEF: beef,
            outputs: [try WalletCreateActionOutput(lockingScript: [0x51], satoshis: 1, outputDescription: "an output")],
            labels: ["p nosend expiry seconds 60"],
            options: try WalletCreateActionOptions(noSend: true)
        ))["inputBEEF"])
    }

    func test_createActionWithInputsKeepsInputBEEF() throws {
        let source = Transaction(
            version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: try Script(bytes: [0x51], maximumByteCount: 10))],
            lockTime: 0
        )
        let beef = try BEEF(merklePaths: [], transactions: [.raw(source)], limits: StorageLimits.beef)
        let txid = try source.transactionID(limits: StorageLimits.transaction)
        let request = try WalletCreateActionRequest(
            description: "spend a foreign coin",
            inputBEEF: beef,
            inputs: [try WalletCreateActionInput(
                outpoint: Outpoint(transactionID: txid, outputIndex: 0),
                inputDescription: "foreign coin", unlockingScriptLength: 1
            )]
        )
        let arguments = try StorageClient.createActionWireArguments(for: request)
        XCTAssertEqual(arguments["inputBEEF"], OrderedJSON.bytes(try beef.serialized(limits: StorageLimits.beef)))
        XCTAssertEqual(
            arguments.members?.map(\.key),
            [
                "description", "inputBEEF", "inputs", "outputs", "lockTime", "version", "labels",
                "options", "isSendWith", "isDelayed", "isNoSend", "isNewTx", "isRemixChange",
                "isSignAction", "includeAllSourceTransactions", "isTestWerrReviewActions",
            ]
        )
    }

    /// `isRemixChange = !isSendWith && no inputs && no outputs`, and it makes the action new.
    func test_derivedFlagsFollowTheValidator() throws {
        let remix = try StorageClient.validatedArguments(
            for: try WalletCreateActionRequest(description: "remix change")
        )
        XCTAssertEqual(remix["isRemixChange"], .bool(true))
        XCTAssertEqual(remix["isNewTx"], .bool(true))
        XCTAssertEqual(remix["isSignAction"], .bool(true))

        let review = try StorageClient.validatedArguments(for: try WalletCreateActionRequest(
            description: "review test",
            outputs: [try WalletCreateActionOutput(lockingScript: [0x51], satoshis: 1, outputDescription: "an output")],
            labels: [ActionBatchWire.throwReviewActionsLabel.uppercased()]
        ))
        XCTAssertEqual(review["isTestWerrReviewActions"], .bool(true))
        XCTAssertEqual(review["isRemixChange"], .bool(false))
    }

    /// `validateCreateActionArgs` for a request with no inputs and no outputs: `isRemixChange`
    /// and `isNewTx`, so storage funds a transaction that only moves change, as the reference
    /// wallet asks it to. The public call and an action batch's first action send the same flags.
    func test_anEmptyCreateActionGoesOutAsARemixOnTheCallAndTheBatchPath() async throws {
        let request = try WalletCreateActionRequest(description: "remix change")
        let transport = RecordingTransport(
            result: #"{"reference":"cmVm","version":1,"lockTime":0,"inputs":[],"outputs":[]}"#
        )
        let client = StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
        _ = try await client.createAction(auth, request)

        let bodies = await transport.bodies
        XCTAssertEqual(
            bodies.first,
            #"{"jsonrpc":"2.0","method":"createAction","params":[{"identityKey":"02aa","userId":7},{"description":"remix change","inputs":[],"outputs":[],"lockTime":0,"version":1,"labels":[],"options":{"signAndProcess":false,"acceptDelayedBroadcast":true,"knownTxids":[],"returnTXIDOnly":false,"noSend":false,"noSendChange":[],"sendWith":[],"randomizeOutputs":true},"isSendWith":false,"isDelayed":true,"isNoSend":false,"isNewTx":true,"isRemixChange":true,"isSignAction":true,"includeAllSourceTransactions":false,"isTestWerrReviewActions":false}],"id":1}"#
        )

        let begin = try StorageClient.beginArguments(
            ActionBatchBeginRequest(batchId: "id", firstAction: request, compact: true)
        )
        let first = try XCTUnwrap(begin["firstAction"])
        XCTAssertEqual(first["isRemixChange"], .bool(true))
        XCTAssertEqual(first["isNewTx"], .bool(true))
        XCTAssertEqual(first["isSignAction"], .bool(true))
        XCTAssertEqual(first["isSendWith"], .bool(false))
    }

    /// `sendWith` alone is no new transaction: `isSendWith`, and neither `isNewTx`, `isRemixChange`
    /// nor `isSignAction`, which the validator derives from `isNewTx`.
    func test_aSendWithOnlyRequestIsNotANewTransaction() throws {
        let request = try WalletCreateActionRequest(
            description: "send the staged batch",
            options: try WalletCreateActionOptions(sendWith: [try TransactionID(displayHex: c)])
        )
        let arguments = try StorageClient.createActionWireArguments(for: request)
        XCTAssertEqual(arguments["isSendWith"], .bool(true))
        XCTAssertEqual(arguments["isNewTx"], .bool(false))
        XCTAssertEqual(arguments["isRemixChange"], .bool(false))
        XCTAssertEqual(arguments["isSignAction"], .bool(false))
        XCTAssertEqual(arguments["options"]?["sendWith"], .strings([c]))

        let begin = try StorageClient.beginArguments(
            ActionBatchBeginRequest(batchId: "id", firstAction: request, compact: false)
        )
        XCTAssertEqual(begin["firstAction"]?["isNewTx"], .bool(false))
        XCTAssertEqual(begin["firstAction"]?["isSignAction"], .bool(false))
    }

    // MARK: - Identifiers

    /// `validateIdentifier`: trimmed as `String.prototype.trim` trims, lowercased, then 1 to 300
    /// UTF-8 bytes, or `WERR_INVALID_PARAMETER` naming the parameter.
    func test_identifiersAreTrimmedLoweredAndBoundedAsTheValidatorBoundsThem() throws {
        XCTAssertEqual(try ActionBatchWire.identifier(" Ordinals\n", name: "basket"), "ordinals")
        XCTAssertEqual(try ActionBatchWire.identifier("\u{FEFF}Tag A\u{FEFF}", name: "tag"), "tag a")
        // NEXT LINE is not white space to JavaScript's trim, so it stays.
        XCTAssertEqual(try ActionBatchWire.identifier("\u{85}x", name: "tag"), "\u{85}x")
        XCTAssertEqual(try ActionBatchWire.identifier(String(repeating: "A", count: 300), name: "label"),
                       String(repeating: "a", count: 300))

        XCTAssertThrowsError(try ActionBatchWire.identifier(" \t\n ", name: "label")) {
            XCTAssertEqual($0 as? WireError, .invalidParameter(name: "label", message: "at least 1 length."))
        }
        XCTAssertThrowsError(try ActionBatchWire.identifier(String(repeating: "a", count: 301), name: "tag")) {
            XCTAssertEqual($0 as? WireError, .invalidParameter(name: "tag", message: "no more than 300 length."))
        }
        // Bytes, not characters: 151 two-byte characters are 302 bytes.
        XCTAssertThrowsError(try ActionBatchWire.identifier(String(repeating: "é", count: 151), name: "basket")) {
            XCTAssertEqual($0 as? WireError, .invalidParameter(name: "basket", message: "no more than 300 length."))
        }
    }

    /// A whitespace-only basket, tag or label is refused before anything is sent, rather than
    /// reaching storage as `""`.
    func test_aBlankIdentifierIsRefusedBeforeAnyCall() async throws {
        let transport = RecordingTransport(result: "{}")
        let client = StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
        let output = { (basket: String?, tags: [String]) in
            try WalletCreateActionOutput(
                lockingScript: [0x51], satoshis: 1, outputDescription: "an output", basket: basket, tags: tags
            )
        }
        let cases: [(WalletCreateActionRequest, String)] = [
            (try WalletCreateActionRequest(description: "blank label", outputs: [try output(nil, [])], labels: ["  "]), "label"),
            (try WalletCreateActionRequest(description: "blank basket", outputs: [try output(" ", [])]), "basket"),
            (try WalletCreateActionRequest(description: "blank tag", outputs: [try output("ok", ["\t"])]), "tag"),
        ]
        for (request, name) in cases {
            do {
                _ = try await client.createAction(auth, request)
                XCTFail("\(name) should be refused")
            } catch let error as WireError {
                XCTAssertEqual(error, .invalidParameter(name: name, message: "at least 1 length."))
            }
        }
        do {
            _ = try await client.listOutputs(auth, try WalletListOutputsRequest(basket: " "))
            XCTFail("a blank basket should be refused")
        } catch let error as WireError {
            XCTAssertEqual(error, .invalidParameter(name: "basket", message: "at least 1 length."))
        }
        let bodies = await transport.bodies
        XCTAssertTrue(bodies.isEmpty)
    }

    // MARK: - internalizeAction

    /// `validateInternalizeActionArgs`: labels as `validateLabel`, and each basket insertion as
    /// `validateBasketInsertion`, basket and tags trimmed and lowercased.
    func test_internalizeNormalisesTheBasketTagsAndLabels() async throws {
        let tx = Transaction(
            version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: try Script(bytes: [0x51], maximumByteCount: 10))],
            lockTime: 0
        )
        let beef = try BEEF(merklePaths: [], transactions: [.raw(tx)], limits: StorageLimits.beef)
        let atomic = try AtomicBEEF(
            subjectTransactionID: try tx.transactionID(limits: StorageLimits.transaction),
            beef: beef, limits: StorageLimits.beef
        )
        let request = try WalletInternalizeActionRequest(
            transaction: atomic, description: "incoming token", labels: [" Inbound "],
            outputs: [WalletInternalizeOutput(
                outputIndex: 0,
                remittance: .basketInsertion(try WalletBasketInsertion(
                    basket: " Tokens ", customInstructions: "Keep Case", tags: ["Origin ", "TYPE:Image/PNG"]
                ))
            )]
        )
        let transport = RecordingTransport(result: #"{"accepted":true}"#)
        let client = StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
        _ = try await client.internalizeAction(auth, request)

        let bodies = await transport.bodies
        let envelope = try JSONDecoder().decode(JSONValue.self, from: Data(try XCTUnwrap(bodies.first).utf8))
        let args = try XCTUnwrap(envelope["params"]?.arrayValue?[1])
        XCTAssertEqual(args["labels"], .array([.string("inbound")]))
        let insertion = try XCTUnwrap(args["outputs"]?.arrayValue?.first?["insertionRemittance"])
        XCTAssertEqual(insertion["basket"], .string("tokens"))
        XCTAssertEqual(insertion["tags"], .array([.string("origin"), .string("type:image/png")]))
        XCTAssertEqual(insertion["customInstructions"], .string("Keep Case"))

        do {
            _ = try await client.internalizeAction(auth, try WalletInternalizeActionRequest(
                transaction: atomic, description: "incoming token",
                outputs: [WalletInternalizeOutput(
                    outputIndex: 0, remittance: .basketInsertion(try WalletBasketInsertion(basket: "  "))
                )]
            ))
            XCTFail("a blank basket should be refused")
        } catch let error as WireError {
            XCTAssertEqual(error, .invalidParameter(name: "basket", message: "at least 1 length."))
        }
        let after = await transport.bodies
        XCTAssertEqual(after.count, 1)
    }

    // MARK: - The list calls

    func test_listOutputsFillsTheValidatorDefaults() async throws {
        let transport = RecordingTransport(result: #"{"totalOutputs":0,"outputs":[]}"#)
        let client = StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
        _ = try await client.listOutputs(auth, try WalletListOutputsRequest(basket: " Default "))

        let bodies = await transport.bodies
        XCTAssertEqual(
            bodies.first,
            #"{"jsonrpc":"2.0","method":"listOutputs","params":[{"identityKey":"02aa","userId":7},{"basket":"default","tags":[],"tagQueryMode":"any","includeLockingScripts":false,"includeTransactions":false,"includeCustomInstructions":false,"includeTags":false,"includeLabels":false,"limit":10,"offset":0,"seekPermission":true,"knownTxids":[]}],"id":1}"#
        )
    }

    func test_listOutputsForwardsExplicitValues() throws {
        let arguments = try StorageClient.listOutputsArguments(try WalletListOutputsRequest(
            basket: "bap", tags: ["A", "b "], tagQueryMode: .all, include: .entireTransactions,
            includeCustomInstructions: true, includeTags: true, includeLabels: true,
            pagination: try WalletPagination(limit: 250, offset: 500), seekPermission: false
        ))
        XCTAssertEqual(
            arguments.serialized(),
            #"{"basket":"bap","tags":["a","b"],"tagQueryMode":"all","includeLockingScripts":false,"includeTransactions":true,"includeCustomInstructions":true,"includeTags":true,"includeLabels":true,"limit":250,"offset":500,"seekPermission":false,"knownTxids":[]}"#
        )
    }

    func test_listActionsFillsTheValidatorDefaults() throws {
        let arguments = try StorageClient.listActionsArguments(try WalletListActionsRequest(labels: ["Income "]))
        XCTAssertEqual(
            arguments.serialized(),
            #"{"labels":["income"],"labelQueryMode":"any","includeLabels":false,"includeInputs":false,"includeInputSourceLockingScripts":false,"includeInputUnlockingScripts":false,"includeOutputs":false,"includeOutputLockingScripts":false,"limit":10,"offset":0,"seekPermission":true}"#
        )
    }

    func test_listCertificatesFillsTheValidatorDefaults() throws {
        let arguments = try StorageClient.listCertificatesArguments(
            try WalletListCertificatesRequest(certifiers: [], types: [])
        )
        XCTAssertEqual(arguments, .object([
            "certifiers": .array([]),
            "types": .array([]),
            "limit": .number(10),
            "offset": .number(0),
            "privileged": .bool(false),
        ]))
    }
}
