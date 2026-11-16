import XCTest
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// Bytes on the wire as base64 once storage says it reads binary requests.
///
/// Storage's authentication layer (`@bsv/auth-express-middleware` 2.3) counts every JSON value of
/// a request and refuses one with more than 100,000, or an array longer than that, with an
/// unsigned `400 ERR_AUTH_MALFORMED` before storage sees it. A signed transaction written as an
/// array of numbers costs a value per byte, so any action over ~100 KB (an inscription carrying a
/// photo) failed in `processAction`, or in `commitActionBatch` with SIGMA signing, as
/// "The server refused the request (HTTP 400)". The reference client avoids it by sending bytes
/// as `{"$bsvBinary":"base64","data":...}` with `X-BSV-Binary-Request-Encoding: base64`.
final class BinaryRequestTests: XCTestCase {

    /// The auth layer's cap on JSON values in one request (`assertBoundedRequestValue`).
    private static let authValueLimit = 100_000

    private actor Storage: AuthenticatedTransport {
        let echoesBinary: Bool
        /// The `result` text for each method this store answers specially, written as storage
        /// writes it for the encoding the request asked for.
        let results: [String: (_ binary: Bool) -> String]
        private(set) var requests: [(headers: [String: String], body: [UInt8])] = []

        init(echoesBinary: Bool, results: [String: (_ binary: Bool) -> String] = [:]) {
            self.echoesBinary = echoesBinary
            self.results = results
        }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            let bytes = body ?? []
            requests.append((headers, bytes))
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(bytes))
            let id = request["id"]?.intValue ?? 0
            let result: String
            var replyHeaders: [String: String] = [:]
            // `StorageServer` echoes the header, lower-cased inside the signed response, on every
            // reply to a request that asked for it, and then writes that reply's bytes as base64.
            let binary = echoesBinary && headers["X-BSV-Binary-Encoding"] == "base64"
            if binary { replyHeaders["x-bsv-binary-encoding"] = "base64" }
            switch request["method"]?.stringValue {
            case let method? where results[method] != nil:
                result = results[method]!(binary)
            case "makeAvailable":
                result = #"{"storageIdentityKey":"\#(ActiveStorageFixture.storageIdentityKey)","storageName":"s","chain":"main"}"#
            case "findOrInsertUser":
                result = #"{"user":{"userId":7,"identityKey":"02","activeStorage":"\#(ActiveStorageFixture.storageIdentityKey)"},"isNew":false}"#
            case "commitActionBatch":
                result = #"{"batchId":"YmF0Y2g=","manifestDigest":"d1","committedTxids":[],"alreadyCommitted":false,"sendWithResults":[]}"#
            default:
                result = #"{"sendWithResults":[]}"#
            }
            return AuthenticatedResponse(
                statusCode: 200, headers: replyHeaders,
                body: Array(#"{"jsonrpc":"2.0","id":\#(id),"result":\#(result)}"#.utf8)
            )
        }

        /// The one request for `method`.
        func request(_ method: String) throws -> (headers: [String: String], body: [UInt8]) {
            try XCTUnwrap(requests.first { request in
                (try? JSONDecoder().decode(JSONValue.self, from: Data(request.body)))?["method"]?
                    .stringValue == method
            })
        }
    }

    private let auth = AuthID(identityKey: "02" + String(repeating: "11", count: 32))

    private func client(_ storage: Storage) -> StorageClient {
        StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: storage)
    }

    /// A signed transaction of about 150 KB, the size of a phone photo inscription.
    private func largeTransaction() throws -> [UInt8] {
        let data = [UInt8](repeating: 7, count: 150_000)
        let script = [0x00, 0x6a, 0x4e] + withUnsafeBytes(of: UInt32(data.count).littleEndian, Array.init) + data
        let output = TransactionOutput(
            satoshis: 1, lockingScript: try Script(bytes: script, maximumByteCount: 1_000_000)
        )
        let transaction = Transaction(version: 1, inputs: [], outputs: [output], lockTime: 0)
        return try transaction.serialized(limits: StorageLimits.transaction)
    }

    /// Every JSON value in a body, as the auth layer counts them.
    private func valueCount(_ value: JSONValue) -> Int {
        switch value {
        case .array(let values): 1 + values.reduce(0) { $0 + valueCount($1) }
        case .object(let members): 1 + members.values.reduce(0) { $0 + valueCount($1) }
        default: 1
        }
    }

    private func body(_ bytes: [UInt8]) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(bytes))
    }

    func test_aLargeSignedTransactionIsProcessedWithinTheAuthLayersValueLimit() async throws {
        let storage = Storage(echoesBinary: true)
        let raw = try largeTransaction()

        _ = try await client(storage).processAction(auth, StorageProcessActionRequest(
            reference: "cmVm", isNewTx: true, isSendWith: false, rawTX: raw, sendWith: []
        ))

        let sent = try await storage.request("processAction")
        XCTAssertEqual(sent.headers["X-BSV-Binary-Request-Encoding"], "base64")
        let request = try body(sent.body)
        XCTAssertLessThan(valueCount(request), Self.authValueLimit)
        let rawTx = try XCTUnwrap(request["params"]?.arrayValue?[1]["rawTx"])
        XCTAssertEqual(rawTx["$bsvBinary"]?.stringValue, "base64")
        XCTAssertEqual(rawTx["data"]?.stringValue, Data(raw).base64EncodedString())
    }

    /// The SIGMA publish travels as an inline blob of the batch commit.
    func test_aLargeInlineBlobIsCommittedWithinTheAuthLayersValueLimit() async throws {
        let storage = Storage(echoesBinary: true)
        let raw = try largeTransaction()
        let manifest = OrderedJSON.record([
            "format": .integer(2),
            "batchId": .string("YmF0Y2g="),
            "inlineBlobs": .object([.init("d1", .bytes(raw))]),
            "digest": .string("d2"),
        ])

        _ = try await client(storage).commitActionBatch(
            auth, ActionBatchManifest(batchId: "YmF0Y2g=", digest: "d2", body: manifest)
        )

        let sent = try await storage.request("commitActionBatch")
        XCTAssertEqual(sent.headers["X-BSV-Binary-Request-Encoding"], "base64")
        let request = try body(sent.body)
        XCTAssertLessThan(valueCount(request), Self.authValueLimit)
        let blob = try XCTUnwrap(request["params"]?.arrayValue?[1]["inlineBlobs"]?["d1"])
        XCTAssertEqual(blob["data"]?.stringValue, Data(raw).base64EncodedString())
    }

    /// A received payment over ~100 KB: `internalizeAction` carries its Atomic BEEF as bytes.
    func test_aLargeReceivedTransactionIsInternalizedWithinTheAuthLayersValueLimit() async throws {
        let storage = Storage(echoesBinary: true)
        let transaction = try Transaction(bytes: try largeTransaction(), limits: StorageLimits.transaction)
        let atomic = try AtomicBEEF(
            subjectTransactionID: try transaction.transactionID(limits: StorageLimits.transaction),
            beef: try BEEF(merklePaths: [], transactions: [.raw(transaction)], limits: StorageLimits.beef),
            limits: StorageLimits.beef
        )
        let request = try WalletInternalizeActionRequest(
            transaction: atomic, description: "incoming photo", labels: [],
            outputs: [WalletInternalizeOutput(
                outputIndex: 0,
                remittance: .basketInsertion(try WalletBasketInsertion(basket: "photos", tags: []))
            )]
        )

        _ = try await client(storage).internalizeAction(auth, request)

        let sent = try await storage.request("internalizeAction")
        XCTAssertEqual(sent.headers["X-BSV-Binary-Request-Encoding"], "base64")
        let body = try body(sent.body)
        XCTAssertLessThan(valueCount(body), Self.authValueLimit)
        let tx = try XCTUnwrap(body["params"]?.arrayValue?[1]["tx"])
        XCTAssertEqual(tx["$bsvBinary"]?.stringValue, "base64")
        XCTAssertEqual(
            tx["data"]?.stringValue,
            Data(try atomic.serialized(limits: StorageLimits.beef)).base64EncodedString()
        )
    }

    func test_theReclaimTransactionIsArmedAsBytes() async throws {
        let storage = Storage(echoesBinary: true)
        let raw = try largeTransaction()

        try await client(storage).armNoSendExpiry(auth, NoSendExpiryArm(
            reference: "cmVm", reclaimTxid: String(repeating: "ab", count: 32), reclaimRawTx: raw,
            reclaimDerivationPrefix: "UA==", reclaimDerivationSuffix: "Uw==", reclaimSatoshis: 950
        ))

        let sent = try await storage.request("armNoSendExpiry")
        XCTAssertEqual(sent.headers["X-BSV-Binary-Request-Encoding"], "base64")
        let arguments = try XCTUnwrap(try body(sent.body)["params"]?.arrayValue?[1])
        XCTAssertLessThan(valueCount(arguments), Self.authValueLimit)
        XCTAssertEqual(arguments["reclaimRawTx"]?["data"]?.stringValue, Data(raw).base64EncodedString())
        XCTAssertEqual(arguments["reclaimSatoshis"], .number(950))
    }

    func test_theSettingsReadAsksWhetherStorageReadsBinary() async throws {
        let storage = Storage(echoesBinary: true)
        _ = try await client(storage).makeAvailable(auth)

        let sent = try await storage.request("makeAvailable")
        XCTAssertEqual(sent.headers["X-BSV-Binary-Encoding"], "base64")
        XCTAssertNil(sent.headers["X-BSV-Binary-Request-Encoding"])
    }

    /// `StorageClient.rpcCall` sends `X-BSV-Binary-Encoding: base64` on every call, so storage
    /// writes every response's bytes as base64. Sent only on the settings read, the replies that
    /// carry bytes (`createAction`, `beginActionBatch`) came back as arrays of numbers.
    func test_everyCallAsksForBinaryResponses() async throws {
        for echoes in [true, false] {
            let storage = Storage(echoesBinary: echoes)
            let client = client(storage)

            _ = try await client.findOrInsertUser(auth.identityKey)
            _ = try await client.processAction(auth, StorageProcessActionRequest(
                reference: "cmVm", isNewTx: true, isSendWith: false, rawTX: try largeTransaction(),
                sendWith: []
            ))
            _ = try await client.call("listOutputs", [.object(auth.jsonObject), .object([:])])

            let requests = await storage.requests
            XCTAssertGreaterThanOrEqual(requests.count, 4)
            for request in requests {
                XCTAssertEqual(request.headers["X-BSV-Binary-Encoding"], "base64")
            }
        }
    }

    /// The funded action's proof graph, as a 1Sat store writes it for a binary request: about a
    /// third larger than the bytes, where an array of numbers was about four times larger.
    func test_aBinaryReplysBytesAreReadAsBytes() async throws {
        let beef = try largeTransaction()
        let storage = Storage(echoesBinary: true, results: ["createAction": { binary in
            let inputBeef = binary
                ? #"{"$bsvBinary":"base64","data":"\#(Data(beef).base64EncodedString())"}"#
                : "[" + beef.map(String.init).joined(separator: ",") + "]"
            return #"{"reference":"cmVm","version":1,"lockTime":0,"inputs":[],"outputs":[],"inputBeef":\#(inputBeef),"derivationPrefix":"cA=="}"#
        }])

        let result = try await client(storage).call(
            "createAction", [.object(auth.jsonObject), .object([:])]
        )

        XCTAssertEqual(try StorageClient.decodeCreateAction(result).inputBEEF, beef)
        let sent = try await storage.request("createAction")
        XCTAssertEqual(sent.headers["X-BSV-Binary-Encoding"], "base64")
    }

    /// A literal object shaped like a marker arrives escaped and is read back as itself.
    func test_anEscapedObjectInABinaryReplyIsReadBackAsItself() async throws {
        let storage = Storage(echoesBinary: true, results: ["listOutputs": { _ in
            #"{"customInstructions":{"$bsvBinary":"escaped","entries":[["$bsvBinary","base64"],["data","AQID"]]}}"#
        }])

        let result = try await client(storage).call("listOutputs", [.object(auth.jsonObject)])

        XCTAssertEqual(
            result["customInstructions"],
            .object(["$bsvBinary": .string("base64"), "data": .string("AQID")])
        )
    }

    /// Without the echoed header the reply is plain JSON: nothing in it is read as a marker.
    func test_aPlainReplyIsNotReadAsBinary() async throws {
        let storage = Storage(echoesBinary: false, results: ["listOutputs": { _ in
            #"{"customInstructions":{"$bsvBinary":"base64","data":"AQID"}}"#
        }])

        let result = try await client(storage).call("listOutputs", [.object(auth.jsonObject)])

        XCTAssertEqual(
            result["customInstructions"],
            .object(["$bsvBinary": .string("base64"), "data": .string("AQID")])
        )
    }

    /// Bytes that are not canonical base64 are a reply that cannot be read, as `fromBase64`
    /// throws in `parseJsonRpc`.
    func test_aBinaryReplyWithInvalidBase64IsUnreadable() async throws {
        let storage = Storage(echoesBinary: true, results: ["listOutputs": { _ in
            #"{"outputs":{"$bsvBinary":"base64","data":"AQJ="}}"#
        }])

        do {
            _ = try await client(storage).call("listOutputs", [.object(auth.jsonObject)])
            XCTFail("an invalid binary value was read")
        } catch let error as StorageClientError {
            XCTAssertEqual(error, .unreadableResponse(method: "listOutputs"))
        }
    }

    /// A store that does not echo the header gets bytes as numbers, as before.
    func test_bytesStayNumbersForAStoreThatDoesNotReadBinary() async throws {
        let storage = Storage(echoesBinary: false)
        let raw: [UInt8] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        _ = try await client(storage).processAction(auth, StorageProcessActionRequest(
            reference: "cmVm", isNewTx: true, isSendWith: false, rawTX: raw, sendWith: []
        ))

        let sent = try await storage.request("processAction")
        XCTAssertNil(sent.headers["X-BSV-Binary-Request-Encoding"])
        let rawTx = try body(sent.body)["params"]?.arrayValue?[1]["rawTx"]
        XCTAssertEqual(rawTx, .array(raw.map { .number(Double($0)) }))
    }
}
