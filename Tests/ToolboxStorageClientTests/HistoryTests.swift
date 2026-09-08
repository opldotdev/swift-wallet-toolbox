import XCTest
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// Decoding history, and the shape of the housekeeping requests.
final class HistoryTests: XCTestCase {

    private actor RecordingTransport: AuthenticatedTransport {
        private let result: String
        private(set) var body: [UInt8]?

        init(result: String = #"{"totalActions":0,"actions":[]}"#) {
            self.result = result
        }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            self.body = body
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
            let response = JSONValue.object([
                "jsonrpc": .string("2.0"),
                "id": request["id"] ?? .number(1),
                "result": try JSONDecoder().decode(JSONValue.self, from: Data(result.utf8)),
            ])
            return AuthenticatedResponse(
                statusCode: 200, headers: [:], body: Array(try JSONEncoder().encode(response))
            )
        }

        func envelope() throws -> JSONValue {
            try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
        }
    }

    private struct CancellingTransport: AuthenticatedTransport {
        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            throw CancellationError()
        }
    }

    private func result(_ json: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
    }

    func test_actionsDecode() throws {
        let decoded = try StorageClient.decodeActions(try result("""
            {"totalActions": 1, "actions": [{
              "txid": "8ac7230489e80000000000000000000000000000000000000000000000000001",
              "satoshis": -4200, "status": "completed", "isOutgoing": true,
              "description": "coffee", "version": 1, "lockTime": 0
            }]}
            """))

        XCTAssertEqual(decoded.totalActions, 1)
        XCTAssertEqual(decoded.actions.count, 1)
        XCTAssertEqual(decoded.actions[0].satoshis, -4200)
        XCTAssertTrue(decoded.actions[0].isOutgoing)
        XCTAssertEqual(decoded.actions[0].status, .completed)
    }

    func test_everyListActionsArgumentIsForwardedIncludingExplicitFalse() async throws {
        let transport = RecordingTransport()
        let client = StorageClient(
            endpoint: URL(string: "https://storage.example/")!, transport: transport
        )
        let request = try WalletListActionsRequest(
            labels: ["payment", "settled"],
            labelQueryMode: .all,
            includeLabels: true,
            includeInputs: true,
            includeInputSourceLockingScripts: false,
            includeInputUnlockingScripts: true,
            includeOutputs: true,
            includeOutputLockingScripts: false,
            pagination: WalletPagination(limit: 25, offset: 50),
            seekPermission: false
        )

        _ = try await client.listActions(AuthID(identityKey: "02aa", userID: 7), request)

        let parameters = try await transport.envelope()["params"]?.arrayValue
        let arguments = try XCTUnwrap(parameters?[1])
        XCTAssertEqual(
            arguments["labels"]?.arrayValue?.compactMap(\.stringValue),
            ["payment", "settled"]
        )
        XCTAssertEqual(arguments["labelQueryMode"]?.stringValue, "all")
        XCTAssertEqual(arguments["includeLabels"]?.boolValue, true)
        XCTAssertEqual(arguments["includeInputs"]?.boolValue, true)
        XCTAssertEqual(arguments["includeInputSourceLockingScripts"]?.boolValue, false)
        XCTAssertEqual(arguments["includeInputUnlockingScripts"]?.boolValue, true)
        XCTAssertEqual(arguments["includeOutputs"]?.boolValue, true)
        XCTAssertEqual(arguments["includeOutputLockingScripts"]?.boolValue, false)
        XCTAssertEqual(arguments["limit"]?.intValue, 25)
        XCTAssertEqual(arguments["offset"]?.intValue, 50)
        XCTAssertEqual(arguments["seekPermission"]?.boolValue, false)
    }

    func test_nestedInputsAndOutputsDecodeWithoutLosingOptionalFields() throws {
        let sourceTxid = String(repeating: "11", count: 32)
        let actionTxid = String(repeating: "22", count: 32)
        let decoded = try StorageClient.decodeActions(try result("""
            {"totalActions":1,"actions":[{
              "txid":"\(actionTxid)","satoshis":-7,"status":"nosend",
              "isOutgoing":true,"description":"prepared payment","labels":["payment"],
              "version":2,"lockTime":500,
              "inputs":[{
                "sourceOutpoint":"\(sourceTxid).3","sourceSatoshis":42,
                "sourceLockingScript":"76a914","unlockingScript":"51",
                "inputDescription":"funding input","sequenceNumber":4294967295
              }],
              "outputs":[{
                "satoshis":35,"lockingScript":"6a01ff","spendable":false,
                "customInstructions":"private storage metadata","tags":["type:test"],
                "outputIndex":1,"outputDescription":"application output","basket":"apps"
              }]
            }]}
            """))

        let action = try XCTUnwrap(decoded.actions.first)
        XCTAssertEqual(action.transactionID.displayHex, actionTxid)
        XCTAssertEqual(action.labels, ["payment"])
        XCTAssertEqual(action.version, 2)
        XCTAssertEqual(action.lockTime, 500)
        let input = try XCTUnwrap(action.inputs?.first)
        XCTAssertEqual(input.sourceOutpoint.description, "\(sourceTxid).3")
        XCTAssertEqual(input.sourceSatoshis, 42)
        XCTAssertEqual(input.sourceLockingScript, [0x76, 0xa9, 0x14])
        XCTAssertEqual(input.unlockingScript, [0x51])
        XCTAssertEqual(input.inputDescription, "funding input")
        XCTAssertEqual(input.sequenceNumber, .max)
        let output = try XCTUnwrap(action.outputs?.first)
        XCTAssertEqual(output.satoshis, 35)
        XCTAssertEqual(output.lockingScript, [0x6a, 0x01, 0xff])
        XCTAssertFalse(output.spendable)
        XCTAssertEqual(output.customInstructions, "private storage metadata")
        XCTAssertEqual(output.tags, ["type:test"])
        XCTAssertEqual(output.outputIndex, 1)
        XCTAssertEqual(output.outputDescription, "application output")
        XCTAssertEqual(output.basket, "apps")
    }

    func test_presentEmptyNestedCollectionsRemainPresent() throws {
        let txid = String(repeating: "33", count: 32)
        let decoded = try StorageClient.decodeActions(try result("""
            {"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":0,"status":"completed",
              "isOutgoing":false,"description":"empty details","labels":[],
              "version":1,"lockTime":0,"inputs":[],"outputs":[]
            }]}
            """))

        XCTAssertEqual(decoded.actions[0].labels, [])
        XCTAssertEqual(decoded.actions[0].inputs, [])
        XCTAssertEqual(decoded.actions[0].outputs, [])
    }

    func test_malformedRequiredAndNestedFieldsAreRefused() throws {
        let txid = String(repeating: "44", count: 32)
        let sourceTxid = String(repeating: "55", count: 32)
        let malformed = [
            #"{"totalActions":-1,"actions":[]}"#,
            #"{"totalActions":4294967296,"actions":[]}"#,
            """
            {"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":0,"status":"completed",
              "isOutgoing":false,"version":1,"lockTime":0
            }]}
            """,
            """
            {"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":0,"status":"completed",
              "isOutgoing":false,"description":"bad inputs","version":1,"lockTime":0,
              "inputs":{}
            }]}
            """,
            """
            {"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":0,"status":"completed",
              "isOutgoing":false,"description":"bad source amount","version":1,"lockTime":0,
              "inputs":[{"sourceOutpoint":"\(sourceTxid).0","sourceSatoshis":-1,
                "inputDescription":"input","sequenceNumber":0}]
            }]}
            """,
            """
            {"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":0,"status":"completed",
              "isOutgoing":false,"description":"bad input script","version":1,"lockTime":0,
              "inputs":[{"sourceOutpoint":"\(sourceTxid).0","sourceSatoshis":1,
                "sourceLockingScript":"xyz","inputDescription":"input","sequenceNumber":0}]
            }]}
            """,
            """
            {"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":0,"status":"completed",
              "isOutgoing":false,"description":"missing tags","version":1,"lockTime":0,
              "outputs":[{"satoshis":1,"spendable":true,"outputIndex":0,
                "outputDescription":"output","basket":"apps"}]
            }]}
            """,
            """
            {"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":0,"status":"completed",
              "isOutgoing":false,"description":"bad custom instructions","version":1,"lockTime":0,
              "outputs":[{"satoshis":1,"spendable":true,"customInstructions":7,"tags":[],
                "outputIndex":0,"outputDescription":"output","basket":"apps"}]
            }]}
            """,
        ]

        for json in malformed {
            XCTAssertThrowsError(try StorageClient.decodeActions(try result(json))) { error in
                XCTAssertEqual(
                    error as? StorageClientError,
                    .unreadableResponse(method: "listActions")
                )
            }
        }
    }

    func test_anUnknownStatusIsRefused() throws {
        XCTAssertThrowsError(try StorageClient.decodeActions(try result("""
            {"totalActions": 1, "actions": [{
              "txid": "8ac7230489e80000000000000000000000000000000000000000000000000001",
              "satoshis": 1, "status": "levitating", "isOutgoing": false,
              "description": "unknown status", "version": 1, "lockTime": 0
            }]}
            """)))
    }

    func test_failedStatusDecodesFromTheCurrentABI() throws {
        let txid = String(repeating: "66", count: 32)
        let decoded = try StorageClient.decodeActions(try result("""
            {"totalActions":1,"actions":[{
              "txid":"\(txid)","satoshis":1,"status":"failed","isOutgoing":false,
              "description":"failed action","version":1,"lockTime":0
            }]}
            """))

        XCTAssertEqual(decoded.actions.count, 1)
        XCTAssertEqual(decoded.actions.first?.status, .failed)
    }

    func test_cancellationIsNotTranslatedIntoAMalformedResponse() async throws {
        let client = StorageClient(
            endpoint: URL(string: "https://storage.example/")!,
            transport: CancellingTransport()
        )

        do {
            _ = try await client.listActions(
                AuthID(identityKey: "02aa"), try WalletListActionsRequest(labels: [])
            )
            XCTFail("transport cancellation must escape")
        } catch is CancellationError {
            // Expected: listActions must not turn cooperative cancellation into protocol failure.
        }
    }

    func test_anEmptyHistoryDecodes() throws {
        let decoded = try StorageClient.decodeActions(
            try result(#"{"totalActions": 0, "actions": []}"#)
        )
        XCTAssertEqual(decoded.totalActions, 0)
        XCTAssertTrue(decoded.actions.isEmpty)
    }
}
