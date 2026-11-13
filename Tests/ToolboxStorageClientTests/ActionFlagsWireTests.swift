import XCTest
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// The noSend, delayed and sendWith flags as storage receives them on createAction and
/// processAction, in the reference client's wire shape.
///
/// Storage decides what to do with a signed transaction from the processAction flags alone. An
/// anchor created with `noSend` but processed with `isNoSend: false` is broadcast immediately, on
/// its own, instead of waiting for the action that names it in `sendWith`.
final class ActionFlagsWireTests: XCTestCase {

    private actor RecordingTransport: AuthenticatedTransport {
        private var results: [String]
        private(set) var bodies: [JSONValue] = []

        init(results: [String]) { self.results = results }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
            bodies.append(request)
            let result = results.isEmpty ? "null" : results.removeFirst()
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

    private let auth = AuthID(identityKey: "02" + String(repeating: "11", count: 32))

    private let fundedJSON = """
        {"reference":"cmVm","version":1,"lockTime":0,"derivationPrefix":"UHJl",
         "inputs":[],"outputs":[{"vout":0,"satoshis":2,"lockingScript":"51"}]}
        """
    private let processedJSON = #"{"sendWithResults":[]}"#

    private func client(_ transport: RecordingTransport) -> StorageClient {
        StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
    }

    private func request(_ options: WalletCreateActionOptions?) throws -> WalletCreateActionRequest {
        try WalletCreateActionRequest(
            description: "an action",
            outputs: [try WalletCreateActionOutput(
                lockingScript: [0x51], satoshis: 2, outputDescription: "anchor"
            )],
            options: options
        )
    }

    private func signedBytes() throws -> (raw: [UInt8], txid: String) {
        let output = TransactionOutput(
            satoshis: 2, lockingScript: try Script(bytes: [0x51], maximumByteCount: 10_000)
        )
        let transaction = Transaction(version: 1, inputs: [], outputs: [output], lockTime: 0)
        return (
            try transaction.serialized(limits: StorageLimits.transaction),
            try transaction.transactionID(limits: StorageLimits.transaction).displayHex
        )
    }

    private func params(_ body: JSONValue) throws -> JSONValue {
        try XCTUnwrap(body["params"]?.arrayValue?[1])
    }

    /// Step one of a two-step publish: the anchor is created and processed with `noSend`, so
    /// storage keeps it for the batch rather than broadcasting it.
    func test_aNoSendActionIsProcessedAsNoSend() async throws {
        let transport = RecordingTransport(results: [fundedJSON, processedJSON])
        let storage = client(transport)
        let signed = try signedBytes()

        _ = try await storage.createAction(auth, try request(
            try WalletCreateActionOptions(acceptDelayedBroadcast: false, noSend: true)
        ))
        _ = try await storage.processAction(auth, StorageProcessActionRequest(
            reference: "cmVm", isNewTx: true, isSendWith: false, rawTX: signed.raw,
            sendWith: [], isNoSend: true, isDelayed: false
        ))

        let bodies = await transport.bodies
        XCTAssertEqual(bodies.map { $0["method"]?.stringValue }, ["createAction", "processAction"])
        let created = try params(bodies[0])
        XCTAssertEqual(created["options"]?["noSend"], .bool(true))
        XCTAssertEqual(created["isNoSend"], .bool(true))
        XCTAssertEqual(created["isDelayed"], .bool(false))

        let processed = try params(bodies[1])
        XCTAssertEqual(processed["isNoSend"], .bool(true))
        XCTAssertEqual(processed["isDelayed"], .bool(false))
        XCTAssertEqual(processed["isNewTx"], .bool(true))
        XCTAssertEqual(processed["isSendWith"], .bool(false))
        XCTAssertEqual(processed["sendWith"], .array([]))
        XCTAssertEqual(processed["reference"], .string("cmVm"))
        XCTAssertEqual(processed["txid"], .string(signed.txid))
        XCTAssertEqual(processed["rawTx"], .array(signed.raw.map { .number(Double($0)) }))
    }

    /// Step two: the main action names the held anchor in `sendWith`, trusts the proofs storage
    /// already holds, and is processed as a delayed batch with the anchor.
    func test_aDelayedBatchCarriesItsSendWithAndTrustSelf() async throws {
        let transport = RecordingTransport(results: [fundedJSON, processedJSON])
        let storage = client(transport)
        let signed = try signedBytes()
        // The anchor from step one, already held by storage.
        let anchor = try Transaction(
            version: 1, inputs: [],
            outputs: [TransactionOutput(
                satoshis: 1, lockingScript: try Script(bytes: [0x52], maximumByteCount: 10_000)
            )],
            lockTime: 0
        ).transactionID(limits: StorageLimits.transaction)

        _ = try await storage.createAction(auth, try request(try WalletCreateActionOptions(
            acceptDelayedBroadcast: true, trustSelf: .known,
            knownTransactionIDs: [anchor], sendWith: [anchor]
        )))
        _ = try await storage.processAction(auth, StorageProcessActionRequest(
            reference: "cmVm", isNewTx: true, isSendWith: true, rawTX: signed.raw,
            sendWith: [anchor.displayHex], isNoSend: false, isDelayed: true
        ))

        let bodies = await transport.bodies
        let created = try params(bodies[0])
        XCTAssertEqual(created["options"]?["trustSelf"], .string("known"))
        XCTAssertEqual(created["options"]?["knownTxids"], .array([.string(anchor.displayHex)]))
        XCTAssertEqual(created["options"]?["sendWith"], .array([.string(anchor.displayHex)]))
        XCTAssertEqual(created["isSendWith"], .bool(true))
        XCTAssertEqual(created["isDelayed"], .bool(true))
        XCTAssertEqual(created["isNoSend"], .bool(false))

        let processed = try params(bodies[1])
        XCTAssertEqual(processed["isNoSend"], .bool(false))
        XCTAssertEqual(processed["isDelayed"], .bool(true))
        XCTAssertEqual(processed["isSendWith"], .bool(true))
        XCTAssertEqual(processed["sendWith"], .array([.string(anchor.displayHex)]))
        XCTAssertEqual(processed["txid"], .string(signed.txid))
    }

    /// Unset `acceptDelayedBroadcast` is true in the reference client, on the option and the flag.
    func test_unsetDelayedBroadcastIsSentAsDelayed() throws {
        for options in [nil, try WalletCreateActionOptions()] {
            let arguments = try StorageClient.arguments(for: try request(options))
            XCTAssertEqual(arguments["options"]?["acceptDelayedBroadcast"], .bool(true))
            XCTAssertEqual(arguments["isDelayed"], .bool(true))
            XCTAssertEqual(arguments["isNoSend"], .bool(false))
        }
    }
}
