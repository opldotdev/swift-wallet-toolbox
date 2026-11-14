import XCTest
import BSVCore
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// The action-batch calls as storage receives them, in the shape `StorageClientBase.js` of
/// `@bsv/wallet-toolbox` 2.15.3 sends, and their results as the reference server returns them.
final class ActionBatchWireTests: XCTestCase {

    private actor RecordingTransport: AuthenticatedTransport {
        /// Each reply is a `result` value, or an `error` value when `isError` is set.
        private var replies: [(json: String, isError: Bool)]
        private(set) var bodies: [[UInt8]] = []

        init(_ replies: [(json: String, isError: Bool)]) { self.replies = replies }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            if let reply = ActiveStorageFixture.reply(to: body) { return reply }
            let bytes = body ?? []
            bodies.append(bytes)
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(bytes))
            let reply = replies.isEmpty ? ("null", false) : replies.removeFirst()
            let value = try JSONDecoder().decode(JSONValue.self, from: Data(reply.0.utf8))
            let response = JSONValue.object([
                "jsonrpc": .string("2.0"),
                "id": request["id"] ?? .number(1),
                reply.1 ? "error" : "result": value,
            ])
            return AuthenticatedResponse(
                statusCode: 200, headers: [:], body: Array(try JSONEncoder().encode(response))
            )
        }
    }

    private let auth = AuthID(identityKey: "02" + String(repeating: "11", count: 32), userID: 5)
    private let txid = String(repeating: "ab", count: 32)

    private func client(_ transport: RecordingTransport) -> StorageClient {
        StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
    }

    private func params(_ transport: RecordingTransport, _ index: Int = 0) async throws -> [OrderedJSON] {
        let bodies = await transport.bodies
        let envelope = try OrderedJSON.parse(bodies[index])
        XCTAssertEqual(envelope.members?.map(\.key), ["jsonrpc", "method", "params", "id"])
        return try XCTUnwrap(envelope["params"]?.arrayValue)
    }

    private func method(_ transport: RecordingTransport, _ index: Int = 0) async throws -> String? {
        let bodies = await transport.bodies
        return try OrderedJSON.parse(bodies[index])["method"]?.stringValue
    }

    private let authJSON = #"{"identityKey":"02\#(String(repeating: "11", count: 32))","userId":5}"#

    private func row(outputId: Int = 7, vout: Int = 1) -> String {
        """
        {"outputId":\(outputId),"userId":5,"transactionId":3,"basketId":1,"spendable":true,
         "change":true,"outputDescription":"","vout":\(vout),"satoshis":1000,"providedBy":"storage",
         "purpose":"change","type":"P2PKH","txid":"\(txid)","derivationPrefix":"cHJl",
         "derivationSuffix":"c3Vm","lockingScript":[118,169],"sourceTransaction":[1,0,0,0,0,0,0,0,0,0]}
        """
    }

    // MARK: - Capabilities

    func test_capabilitiesAreReadFromGetCapabilities() async throws {
        let transport = RecordingTransport([(#"""
            {"actionBatch":{"version":1,"maxInlineBytes":4194304,"maxBlobBytes":16777216,
             "maxConcurrentUploads":4,"leaseMs":60000,"hardLifetimeMs":600000,"compactBegin":true,
             "manifestVersion":2,"commitByDigest":true,"resume":false,"maxReservedOutputs":8}}
            """#, false), (#"{}"#, false), (#"{"actionBatch":{"version":2}}"#, false)])
        let storage = client(transport)

        let capabilities = try await XCTUnwrapAsync(await storage.actionBatchCapabilities())
        XCTAssertEqual(capabilities.maxInlineBytes, 4_194_304)
        XCTAssertEqual(capabilities.leaseMs, 60_000)
        XCTAssertEqual(capabilities.manifestVersion, 2)
        XCTAssertTrue(capabilities.compactBegin)
        let params = try await params(transport)
        XCTAssertEqual(params, [])
        let method = try await method(transport)
        XCTAssertEqual(method, "getCapabilities")

        let none = try await storage.actionBatchCapabilities()
        XCTAssertNil(none, "no actionBatch member")
        let unknown = try await storage.actionBatchCapabilities()
        XCTAssertNil(unknown, "only version 1 is negotiated")
    }

    // MARK: - Begin

    func test_beginSendsTheFirstActionCompactWithObjectOutpoints() async throws {
        let transport = RecordingTransport([("""
            {"batchId":"YmF0Y2g=","expiresAt":"2027-01-15T08:00:00.000Z",
             "hardExpiresAt":"2027-01-15T08:10:00Z",
             "changeBasket":{"basketId":1,"name":"default","numberOfDesiredUTXOs":32,"minimumDesiredUTXOValue":1000},
             "feeModel":{"model":"sat/kb","value":1.5},"commissionSatoshis":0,
             "availableChangeCount":3,"reservedOutputs":[\(row())],"explicitOutputs":[],
             "inputBeef":[2,0,190,239,0,0]}
            """, false)])
        let request = try WalletCreateActionRequest(
            description: "anchor",
            inputs: [try WalletCreateActionInput(
                outpoint: Outpoint(transactionID: try TransactionID(displayHex: txid), outputIndex: 2),
                inputDescription: "spend", unlockingScript: [0x51]
            )],
            outputs: [try WalletCreateActionOutput(
                lockingScript: [0x51, 0x52], satoshis: 2, outputDescription: "o", basket: "b", tags: ["t"]
            )],
            labels: ["l"],
            options: try WalletCreateActionOptions(acceptDelayedBroadcast: false, noSend: true)
        )

        let begin = try await client(transport).beginActionBatch(
            auth, ActionBatchBeginRequest(batchId: "YmF0Y2g=", firstAction: request, compact: true)
        )

        XCTAssertEqual(begin.feeModel.value, 1.5)
        XCTAssertEqual(begin.changeBasket.name, "default")
        XCTAssertEqual(begin.reservedOutputs.first?.outpoint.description, "\(txid).1")
        XCTAssertEqual(begin.reservedOutputs.first?.lockingScript, [118, 169])
        XCTAssertEqual(begin.reservedOutputs.first?.sourceTransaction?.count, 10)
        XCTAssertEqual(begin.inputBeef, [2, 0, 190, 239, 0, 0])
        XCTAssertEqual(begin.hardExpiresAt.timeIntervalSince(begin.expiresAt), 600)

        let params = try await params(transport)
        XCTAssertEqual(params.count, 2)
        XCTAssertEqual(params[0].serialized(), authJSON)
        let arguments = params[1]
        XCTAssertEqual(arguments.members?.map(\.key), ["batchId", "firstAction", "firstActionOutputScriptLengths"])
        XCTAssertEqual(arguments["firstActionOutputScriptLengths"], .array([.integer(2)]))
        let first = try XCTUnwrap(arguments["firstAction"])
        XCTAssertEqual(first.members?.map(\.key), [
            "description", "inputs", "outputs", "lockTime", "version", "labels", "options",
            "isSendWith", "isDelayed", "isNoSend", "isNewTx", "isRemixChange", "isSignAction",
            "includeAllSourceTransactions", "isTestWerrReviewActions",
        ])
        XCTAssertEqual(
            first["inputs"]?.serialized(),
            #"[{"outpoint":{"txid":"\#(txid)","vout":2},"inputDescription":"spend","unlockingScriptLength":1,"sequenceNumber":4294967295}]"#
        )
        XCTAssertEqual(
            first["outputs"]?.serialized(),
            #"[{"lockingScript":"","satoshis":2,"outputDescription":"o","basket":"b","tags":["t"]}]"#
        )
        XCTAssertEqual(
            first["options"]?.serialized(),
            #"{"signAndProcess":false,"acceptDelayedBroadcast":false,"knownTxids":[],"returnTXIDOnly":false,"noSend":true,"noSendChange":[],"sendWith":[],"randomizeOutputs":true}"#
        )
        XCTAssertEqual(first["isNoSend"], .bool(true))
        XCTAssertEqual(first["isDelayed"], .bool(false))
        XCTAssertEqual(first["isSignAction"], .bool(true))
    }

    func test_aFullBeginCarriesScriptsAndTheInputBEEF() throws {
        let request = try WalletCreateActionRequest(
            description: "anchor",
            inputBEEF: try BEEF(version: .v2, merklePaths: [], transactions: [], limits: StorageLimits.beef),
            outputs: [try WalletCreateActionOutput(lockingScript: [0x51], satoshis: 2, outputDescription: "o")],
            options: try WalletCreateActionOptions(noSend: true)
        )
        let arguments = try StorageClient.beginArguments(
            ActionBatchBeginRequest(batchId: "id", firstAction: request, compact: false)
        )
        XCTAssertEqual(arguments.members?.map(\.key), ["batchId", "firstAction"])
        XCTAssertEqual(arguments["firstAction"]?["inputBEEF"], .bytes([2, 0, 190, 239, 0, 0]))
        XCTAssertEqual(arguments["firstAction"]?["outputs"]?.arrayValue?.first?["lockingScript"], .string("51"))
        XCTAssertEqual(arguments["firstAction"]?["isDelayed"], .bool(true), "acceptDelayedBroadcast defaults to true")
    }

    // MARK: - Extend, renew, abort

    func test_extendRenewAndAbortParams() async throws {
        let transport = RecordingTransport([
            ("""
            {"expiresAt":"2027-01-15T08:01:00.000Z","reservedOutputs":[\(row(outputId: 8, vout: 3))],
             "explicitOutputs":[]}
            """, false),
            (#"{"expiresAt":"2027-01-15T08:02:00.000Z"}"#, false),
            (#"{"aborted":true}"#, false),
        ])
        let storage = client(transport)

        let extended = try await storage.extendActionBatch(auth, ActionBatchExtendRequest(
            batchId: "YmF0Y2g=", targetSatoshis: 1_234, requestedOutputs: 8,
            explicitOutpoints: [Outpoint(transactionID: try TransactionID(displayHex: txid), outputIndex: 4)],
            includeSourceTransactions: true
        ))
        XCTAssertEqual(extended.reservedOutputs.map(\.outputId), [8])
        XCTAssertNil(extended.inputBeef)
        let renewed = try await storage.renewActionBatch(auth, batchId: "YmF0Y2g=")
        XCTAssertEqual(renewed.timeIntervalSince(extended.expiresAt), 60)
        let aborted = try await storage.abortActionBatch(auth, batchId: "YmF0Y2g=")
        XCTAssertTrue(aborted)

        let extend = try await params(transport, 0)
        XCTAssertEqual(
            extend[1].serialized(),
            #"{"batchId":"YmF0Y2g=","targetSatoshis":1234,"requestedOutputs":8,"explicitOutpoints":[{"txid":"\#(txid)","vout":4}],"includeSourceTransactions":true}"#
        )
        let renew = try await params(transport, 1)
        XCTAssertEqual(renew.map { $0.serialized() }, [authJSON, #""YmF0Y2g=""#])
        let abort = try await params(transport, 2)
        XCTAssertEqual(abort.map { $0.serialized() }, [authJSON, #""YmF0Y2g=""#])
        let methods = [try await method(transport, 0), try await method(transport, 1), try await method(transport, 2)]
        XCTAssertEqual(methods, ["extendActionBatch", "renewActionBatch", "abortActionBatch"])
    }

    // MARK: - Commit

    /// Storage recomputes the digest from the members in the order it parsed them, so the body is
    /// sent exactly as built.
    func test_commitSendsTheManifestInItsOwnMemberOrder() async throws {
        let transport = RecordingTransport([(#"""
            {"batchId":"YmF0Y2g=","manifestDigest":"d1","committedTxids":["\#(txid)"],
             "alreadyCommitted":false,"sendWithResults":[{"txid":"\#(txid)","status":"unproven"}]}
            """#, false)])
        let body = OrderedJSON.record([
            "format": .integer(2),
            "zeta": .string("first"),
            "batchId": .string("YmF0Y2g="),
            "alpha": .array([.record(["y": .integer(1), "x": .integer(2)])]),
            "digest": .string("d1"),
        ])

        let result = try await client(transport).commitActionBatch(
            auth, ActionBatchManifest(batchId: "YmF0Y2g=", digest: "d1", body: body)
        )
        XCTAssertEqual(result.committedTxids, [txid])
        XCTAssertEqual(result.sendWithResults, [SendWithResult(txid: txid, status: .unproven)])
        XCTAssertFalse(result.alreadyCommitted)

        let bodies = await transport.bodies
        let text = String(decoding: bodies[0], as: UTF8.self)
        XCTAssertTrue(text.contains(#"[\#(authJSON),{"format":2,"zeta":"first","batchId":"YmF0Y2g=","alpha":[{"y":1,"x":2}],"digest":"d1"}]"#), text)
    }

    // MARK: - Lifecycle errors

    func test_actionBatchStateErrorsAreDecoded() async throws {
        let transport = RecordingTransport([
            (#"{"name":"WERR_ACTION_BATCH_STATE","message":"batch expired","state":"expired","batchId":"YmF0Y2g="}"#, true),
            (#"{"name":"WERR_ACTION_BATCH_STATE","message":"no state"}"#, true),
        ])
        let storage = client(transport)
        do {
            _ = try await storage.renewActionBatch(auth, batchId: "YmF0Y2g=")
            XCTFail("expected a state error")
        } catch {
            XCTAssertEqual(
                error as? WireError,
                .actionBatchState(state: "expired", batchId: "YmF0Y2g=", message: "batch expired")
            )
            XCTAssertEqual((error as? WireError)?.wireName, "WERR_ACTION_BATCH_STATE")
        }
        do {
            _ = try await storage.renewActionBatch(auth, batchId: "YmF0Y2g=")
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(
                error as? WireError, .unrecognized(name: "WERR_ACTION_BATCH_STATE", message: "no state")
            )
        }
    }
}

private func XCTUnwrapAsync<T>(
    _ expression: @autoclosure () async throws -> T?, file: StaticString = #filePath, line: UInt = #line
) async throws -> T {
    let value = try await expression()
    return try XCTUnwrap(value, file: file, line: line)
}
