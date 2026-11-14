import Foundation
import BSVAuth
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxBRC29
import ToolboxCore
import ToolboxStorage
import ToolboxStorageClient
import XCTest
@testable import ToolboxWallet

/// A send and an inscribe against a storage server that checks signatures the way the real one
/// does.
///
/// `wallet.1sat.app` and `testnet.wallet.1sat.app` run the TypeScript `StorageServer`:
/// `express.json()` parses the body, then `@bsv/auth-express-middleware` rebuilds the signed
/// BRC-104 payload from `JSON.stringify(req.body)` and verifies our signature over that. When the
/// text we signed is not what `JSON.stringify` writes back, verification fails and the server
/// answers an unsigned `401 ERR_AUTH_FAILED`, which the transport cannot tell from an evicted
/// session. It re-handshakes three times and then reports "Couldn't reconnect to storage".
///
/// The peer below does the same re-serialisation before verifying, so these tests fail on a
/// client that signs anything else.
final class StorageServerSignatureTests: XCTestCase {

    /// The reference storage handed out for the action. Real ones are `randomBytesBase64(12)`, so
    /// about one in five holds a `/`; this one always does.
    static let slashReference = "dGVz/A=="

    func testInscriptionTagAndSlashReferenceAreAcceptedByTheServer() async throws {
        let fixture = try Fixture()

        let created = try await fixture.wallet.createAction(fixture.request())

        XCTAssertNotNil(created.transactionID)
        let methods = await fixture.server.methods
        XCTAssertEqual(methods, ["createAction", "processAction"])
        let refused = await fixture.server.signatureFailures
        XCTAssertEqual(refused, 0, "every request must verify against JSON.stringify of its body")
        let handshakes = await fixture.server.handshakes
        XCTAssertEqual(handshakes, 1)
    }

    /// A send that fails after storage reserved its inputs must release them with `abortAction`,
    /// and that call carries the same slash-bearing reference. Before the fix it failed exactly
    /// like `processAction` did, so the coins stayed reserved until storage expired the action.
    func testFailedProcessReleasesTheReservedInputs() async throws {
        let fixture = try Fixture(processFails: true)

        do {
            _ = try await fixture.wallet.createAction(fixture.request())
            XCTFail("a refused processAction must surface")
        } catch let error as WireError {
            XCTAssertEqual(error, .internalFailure("broadcast refused"))
        } catch {
            XCTFail("expected the server's WireError, got \(error)")
        }

        let methods = await fixture.server.methods
        XCTAssertEqual(methods, ["createAction", "processAction", "abortAction"])
        let aborted = await fixture.server.abortedReferences
        XCTAssertEqual(aborted, [Self.slashReference])
        let refused = await fixture.server.signatureFailures
        XCTAssertEqual(refused, 0)
    }

    /// A session the server really did drop still recovers with one new handshake, mid-send.
    func testAnEvictedSessionReconnectsAndTheSendCompletes() async throws {
        let fixture = try Fixture()
        await fixture.server.evictSessionBefore("processAction")

        let created = try await fixture.wallet.createAction(fixture.request())

        XCTAssertNotNil(created.transactionID)
        let methods = await fixture.server.methods
        XCTAssertEqual(methods, ["createAction", "processAction"])
        let handshakes = await fixture.server.handshakes
        XCTAssertEqual(handshakes, 2)
    }

    // MARK: - Fixture

    private struct Fixture {
        let wallet: RemoteWallet
        let server: ExpressStorageServer

        init(processFails: Bool = false) throws {
            let key = try PrivateKey([UInt8](repeating: 1, count: 32))
            let spending = try BRC29.receivingPrivateKey(
                recipient: key, sender: key.publicKey, prefix: "Pr==", suffix: "Su=="
            )
            let funding = Transaction(outputs: [TransactionOutput(
                satoshis: 100, lockingScript: try BRC29.lockingScript(for: spending.publicKey)
            )])
            server = ExpressStorageServer(
                key: try PrivateKey([UInt8](repeating: 2, count: 32)),
                funding: funding,
                reference: StorageServerSignatureTests.slashReference,
                processFails: processFails
            )
            let endpoint = URL(string: "https://storage.example")!
            wallet = RemoteWallet(
                storage: StorageClient(
                    endpoint: endpoint,
                    transport: AuthenticatedSession(
                        baseURL: endpoint, wallet: ProtoWallet(rootKey: key), transport: server
                    )
                ),
                identityKey: key,
                auth: AuthID(identityKey: key.publicKey.compressedBytes.map {
                    String(format: "%02x", $0)
                }.joined())
            )
        }

        func request() throws -> WalletCreateActionRequest {
            try WalletCreateActionRequest(
                description: "Create inscription",
                outputs: [WalletCreateActionOutput(
                    lockingScript: [0x51], satoshis: 1, outputDescription: "Inscription",
                    tags: ["type:text/plain", "origin"]
                )],
                options: WalletCreateActionOptions(signAndProcess: true)
            )
        }
    }
}

/// The TypeScript storage server, as far as its signature check and four JSON-RPC methods go.
private actor ExpressStorageServer: HTTPTransport {
    let authenticator: PeerAuthenticator
    let funding: Transaction
    let reference: String
    let processFails: Bool

    private(set) var methods: [String] = []
    private(set) var abortedReferences: [String] = []
    private(set) var signatureFailures = 0
    private(set) var handshakes = 0
    private var evictBefore: String?

    init(key: PrivateKey, funding: Transaction, reference: String, processFails: Bool) {
        self.authenticator = PeerAuthenticator(wallet: ProtoWallet(rootKey: key))
        self.funding = funding
        self.reference = reference
        self.processFails = processFails
    }

    func evictSessionBefore(_ method: String) { evictBefore = method }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        if request.url.path.hasSuffix(BRC104HTTPHeaderName.handshakePath) {
            handshakes += 1
            let incoming = try AuthMessageCodec.decode(request.body ?? [])
            guard case .send(let reply)? = try await authenticator.receive(incoming).first else {
                return HTTPResponse(statusCode: 500, body: [])
            }
            return HTTPResponse(statusCode: 200, body: try AuthMessageCodec.encode(reply))
        }
        return try await general(request)
    }

    private func general(_ request: HTTPRequest) async throws -> HTTPResponse {
        // `express.json()` then `writeBodyToWriter`: the payload is rebuilt from
        // `JSON.stringify(req.body)`, never from the bytes that arrived.
        let rebuilt = try OrderedJSON.parse(request.body ?? []).utf8Bytes()
        let frame = try BRC104HTTPRequestFrame(
            method: request.method,
            path: request.url.path,
            query: request.url.query.map { "?" + $0 },
            headers: request.headers.map { BRC104Header(name: $0.key, value: $0.value) },
            body: rebuilt
        )
        let delivered: AuthReceivedMessage
        do {
            let message = try BRC104HTTPFrameCodec.decodeRequest(frame)
            guard case .deliver(let received)? = try await authenticator.receive(message).first(where: {
                if case .deliver = $0 { return true }
                return false
            }) else {
                return Self.authFailed("no payload")
            }
            delivered = received
        } catch {
            // The middleware's `messageCallback` catch: an auth-looking error becomes an
            // unsigned 401 with `ERR_AUTH_FAILED`.
            signatureFailures += 1
            return Self.authFailed("Invalid signature")
        }

        let inner = try BRC104Codec.decodeRequest(delivered.payload)
        let rpc = try JSONDecoder().decode(JSONValue.self, from: Data(inner.body ?? []))
        let method = rpc["method"]?.stringValue ?? ""
        if evictBefore == method {
            evictBefore = nil
            await authenticator.close(delivered.sessionID)
            return Self.authFailed("Session not found for nonce")
        }
        methods.append(method)
        let envelope = try respond(to: method, arguments: rpc["params"]?.arrayValue?[1], id: rpc["id"]!)

        let reply = try BRC104Response(
            requestID: inner.requestID, status: 200, headers: [],
            body: Array(try JSONEncoder().encode(envelope))
        )
        guard case .send(let signed) = try await authenticator.makeGeneralMessage(
            payload: try BRC104Codec.encode(reply), using: delivered.sessionID
        ) else {
            return HTTPResponse(statusCode: 500, body: [])
        }
        let responseFrame = try BRC104HTTPFrameCodec.encodeResponse(signed)
        return HTTPResponse(
            statusCode: responseFrame.status,
            headers: Dictionary(
                responseFrame.headers.map { ($0.name, $0.value) }, uniquingKeysWith: { _, last in last }
            ),
            body: responseFrame.body ?? []
        )
    }

    private func respond(to method: String, arguments: JSONValue?, id: JSONValue) throws -> JSONValue {
        var envelope: [String: JSONValue] = ["jsonrpc": .string("2.0"), "id": id]
        switch method {
        case "createAction":
            let outputs = (arguments?["outputs"]?.arrayValue ?? []).enumerated().map { index, row -> JSONValue in
                var value = row.objectValue ?? [:]
                value["vout"] = .number(Double(index))
                value["providedBy"] = .string("you")
                return .object(value)
            }
            let graph = try BEEF(merklePaths: [], transactions: [.raw(funding)], limits: StorageLimits.beef)
            envelope["result"] = .object([
                "reference": .string(reference), "version": .number(1), "lockTime": .number(0),
                "inputs": .array([.object([
                    "vin": .number(0),
                    "sourceTxid": .string(try funding.transactionID(limits: StorageLimits.transaction).displayHex),
                    "sourceVout": .number(0),
                    "sourceSatoshis": .number(100),
                    "sourceLockingScript": .string(
                        funding.outputs[0].lockingScript.bytes.map { String(format: "%02x", $0) }.joined()
                    ),
                    "unlockingScriptLength": .number(107),
                    "derivationPrefix": .string("Pr=="),
                    "derivationSuffix": .string("Su=="),
                ])]),
                "outputs": .array(outputs),
                "inputBeef": .array(try graph.serialized(limits: StorageLimits.beef).map { .number(Double($0)) }),
            ])
        case "processAction":
            XCTAssertEqual(arguments?["reference"]?.stringValue, reference)
            if processFails {
                envelope["error"] = .object([
                    "name": .string("WERR_INTERNAL"), "message": .string("broadcast refused"),
                ])
            } else {
                envelope["result"] = .object(["sendWithResults": .array([])])
            }
        case "abortAction":
            abortedReferences.append(arguments?["reference"]?.stringValue ?? "")
            envelope["result"] = .object(["aborted": .bool(true)])
        default:
            envelope["error"] = .object([
                "name": .string("WERR_NOT_IMPLEMENTED"), "message": .string(method),
            ])
        }
        return .object(envelope)
    }

    private static func authFailed(_ description: String) -> HTTPResponse {
        HTTPResponse(
            statusCode: 401,
            headers: ["Content-Type": "application/json"],
            body: Array(#"{"status":"error","code":"ERR_AUTH_FAILED","description":"\#(description)"}"#.utf8)
        )
    }
}
