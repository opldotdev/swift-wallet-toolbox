import XCTest
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// Zero-spend probes of binary request encoding against a real storage server.
///
/// Storage's authentication layer refuses a request holding more than 100,000 JSON values, or an
/// array longer than that, with an unsigned `400 ERR_AUTH_MALFORMED`. Bytes written as a JSON
/// array cost a value each, so the client sends them as `{"$bsvBinary":"base64","data":...}` once
/// the settings read has echoed `X-BSV-Binary-Encoding: base64`. These probes show, on a given
/// deployment, that the negotiation happens and that a request carrying ~200 KB of bytes reaches
/// storage itself rather than being refused by the auth layer.
///
/// Skipped unless `TEST_RUNNER_LIVE_STORAGE_URL` is set, so CI stays offline. The chain expected
/// is `TEST_RUNNER_LIVE_CHAIN` (`main` or `test`), or else `test` for a host containing `testnet`
/// and `main` for any other:
///
///     TEST_RUNNER_LIVE_STORAGE_URL=https://testnet.wallet.1sat.app \
///       swift test --filter LiveBinaryProbeTests
///
/// Nothing here can move coins. Every probe uses a fresh random identity that owns nothing, signs
/// nothing, sets `noSend`, and every byte payload is an OP_RETURN that spends no input. The one
/// record a run can leave behind is the throwaway identity's empty user row.
///
/// Each write probe also runs a control with binary negotiation stripped, so the request goes as a
/// JSON array of numbers the way it did before the fix. The control's outcome is printed and never
/// fails the suite: it describes the server, not the client.
///
/// Every line meant to be read back starts with `LIVEPROBE`.
final class LiveBinaryProbeTests: XCTestCase {

    /// The auth layer's cap on JSON values in one request.
    private static let authValueLimit = 100_000
    /// About the size of the photo inscription that first hit the cap, with room to spare.
    private static let payloadByteCount = 200_000

    // MARK: - Environment

    private struct Live {
        let endpoint: URL
        let chain: ToolboxStorage.Chain
    }

    private func live() throws -> Live {
        let environment = ProcessInfo.processInfo.environment
        let value = environment["TEST_RUNNER_LIVE_STORAGE_URL"]
        try XCTSkipIf(value == nil, "set TEST_RUNNER_LIVE_STORAGE_URL to run against a real server")
        let endpoint = try XCTUnwrap(URL(string: value!))
        let chain: ToolboxStorage.Chain
        if let named = environment["TEST_RUNNER_LIVE_CHAIN"], !named.isEmpty {
            chain = try XCTUnwrap(
                ToolboxStorage.Chain(rawValue: named), "TEST_RUNNER_LIVE_CHAIN must be main or test"
            )
        } else {
            chain = (endpoint.host ?? "").lowercased().contains("testnet") ? .test : .main
        }
        return Live(endpoint: endpoint, chain: chain)
    }

    // MARK: - Transport that records

    /// One request and what came back for it.
    struct Exchange: Sendable {
        let method: String
        let requestHeaders: [String: String]
        let requestByteCount: Int
        let requestValueCount: Int
        let response: AuthenticatedResponse?
        let failure: String?

        func responseHeader(_ name: String) -> String? {
            response?.headers.first { $0.key.lowercased() == name.lowercased() }?.value
        }
    }

    /// The real authenticated session, with every exchange kept for the probe to inspect.
    ///
    /// `stripsBinaryNegotiation` removes `X-BSV-Binary-Encoding` from outgoing requests, so the
    /// server never echoes it and the client keeps writing bytes as arrays of numbers: the control.
    actor Recorder: AuthenticatedTransport {
        private let session: AuthenticatedSession
        private let stripsBinaryNegotiation: Bool
        private(set) var exchanges: [Exchange] = []

        init(session: AuthenticatedSession, stripsBinaryNegotiation: Bool) {
            self.session = session
            self.stripsBinaryNegotiation = stripsBinaryNegotiation
        }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            var headers = headers
            if stripsBinaryNegotiation {
                headers = headers.filter {
                    $0.key.lowercased() != StorageClient.binaryHeader.lowercased()
                }
            }
            let bytes = body ?? []
            let parsed = try? JSONDecoder().decode(JSONValue.self, from: Data(bytes))
            let rpcMethod = parsed?["method"]?.stringValue ?? "-"
            let values = parsed.map(Self.valueCount) ?? 0
            do {
                let response = try await session.send(
                    method: method, path: path, query: query, headers: headers, body: body
                )
                exchanges.append(Exchange(
                    method: rpcMethod, requestHeaders: headers, requestByteCount: bytes.count,
                    requestValueCount: values, response: response, failure: nil
                ))
                return response
            } catch {
                exchanges.append(Exchange(
                    method: rpcMethod, requestHeaders: headers, requestByteCount: bytes.count,
                    requestValueCount: values, response: nil, failure: Self.describe(error)
                ))
                throw error
            }
        }

        func last(_ method: String) -> Exchange? {
            exchanges.last { $0.method == method }
        }

        /// Every JSON value, counted as the auth layer counts them.
        static func valueCount(_ value: JSONValue) -> Int {
            switch value {
            case .array(let values): 1 + values.reduce(0) { $0 + valueCount($1) }
            case .object(let members): 1 + members.values.reduce(0) { $0 + valueCount($1) }
            default: 1
            }
        }

        static func describe(_ error: Error) -> String {
            if case AuthTransportError.unauthenticatedReply(let status, let body) = error {
                return "unsigned HTTP \(status) body=\(String(decoding: body.prefix(300), as: UTF8.self))"
            }
            return "\(error)"
        }
    }

    private func makeClient(
        _ live: Live, stripsBinaryNegotiation: Bool = false
    ) throws -> (client: StorageClient, recorder: Recorder, auth: AuthID) {
        let root = try PrivateKey((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let identityKey = root.publicKey.compressedBytes
            .map { String(format: "%02x", $0) }.joined()
        let recorder = Recorder(
            session: AuthenticatedSession(baseURL: live.endpoint, wallet: ProtoWallet(rootKey: root)),
            stripsBinaryNegotiation: stripsBinaryNegotiation
        )
        return (
            StorageClient(endpoint: live.endpoint, transport: recorder), recorder,
            AuthID(identityKey: identityKey)
        )
    }

    // MARK: - Outcomes

    /// What one write probe came to.
    private enum Outcome {
        /// Storage itself answered, with a wallet error.
        case storageError(WireError)
        /// The auth layer refused it before storage saw it.
        case unsignedRefusal(status: Int, body: String)
        /// Storage accepted it. Not expected of an identity that owns nothing.
        case accepted(JSONValue?)
        case otherFailure(String)

        var line: String {
            switch self {
            case .storageError(let error):
                "storage error code=\(error.wireName) description=\(error.message)"
            case .unsignedRefusal(let status, let body):
                "auth-layer refusal status=\(status) unsigned body=\(body)"
            case .accepted:
                "accepted (unexpected for an unfunded identity)"
            case .otherFailure(let text):
                "other failure \(text)"
            }
        }
    }

    private func outcome(_ work: () async throws -> JSONValue?) async -> Outcome {
        do {
            return .accepted(try await work())
        } catch let error as WireError {
            return .storageError(error)
        } catch AuthTransportError.unauthenticatedReply(let status, let body) {
            return .unsignedRefusal(
                status: status, body: String(decoding: body.prefix(300), as: UTF8.self)
            )
        } catch {
            return .otherFailure(Recorder.describe(error))
        }
    }

    private func report(_ probe: String, _ mode: String, _ outcome: Outcome, _ sent: Exchange?) {
        let status = sent?.response.map { "\($0.statusCode)" } ?? "none"
        let request = sent.map {
            "requestBytes=\($0.requestByteCount) jsonValues=\($0.requestValueCount) "
                + "binaryRequestHeader=\($0.requestHeaders[StorageClient.binaryRequestHeader] ?? "-")"
        } ?? "request not sent"
        print("LIVEPROBE \(probe) [\(mode)] httpStatus=\(status) \(request) -> \(outcome.line)")
    }

    /// The binary run must reach storage: a wallet error passes, an auth refusal fails.
    private func assertReachedStorage(
        _ probe: String, _ outcome: Outcome, _ sent: Exchange?,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        guard let sent else {
            return XCTFail("\(probe): the request never left the client", file: file, line: line)
        }
        XCTAssertEqual(
            sent.requestHeaders[StorageClient.binaryRequestHeader], "base64",
            "\(probe): not sent as a binary request", file: file, line: line
        )
        XCTAssertLessThan(
            sent.requestValueCount, Self.authValueLimit,
            "\(probe): over the auth layer's value cap", file: file, line: line
        )
        switch outcome {
        case .storageError:
            break
        case .unsignedRefusal(let status, let body):
            XCTFail("\(probe): auth layer refused with HTTP \(status): \(body)", file: file, line: line)
        case .accepted:
            XCTFail("\(probe): an unfunded identity's request was accepted", file: file, line: line)
        case .otherFailure(let text):
            XCTFail("\(probe): \(text)", file: file, line: line)
        }
    }

    /// The control must really have gone out as arrays of numbers, or it controls for nothing.
    private func assertControlWasJSON(
        _ probe: String, _ sent: Exchange?, file: StaticString = #filePath, line: UInt = #line
    ) {
        guard let sent else {
            return XCTFail("\(probe) control: the request never left the client", file: file, line: line)
        }
        XCTAssertNil(
            sent.requestHeaders[StorageClient.binaryRequestHeader],
            "\(probe) control: sent as binary", file: file, line: line
        )
    }

    // MARK: - Payloads

    /// A transaction that spends nothing and carries `payloadByteCount` bytes in an OP_RETURN.
    /// Meaningless to any chain, so even a broadcast could not move a coin.
    private func inertTransaction() throws -> Transaction {
        let data = (0..<Self.payloadByteCount).map { _ in UInt8.random(in: .min ... .max) }
        let script = [0x00, 0x6a, 0x4e]
            + withUnsafeBytes(of: UInt32(data.count).littleEndian, Array.init) + data
        let output = TransactionOutput(
            satoshis: 0, lockingScript: try Script(bytes: script, maximumByteCount: 1_000_000)
        )
        return Transaction(version: 1, inputs: [], outputs: [output], lockTime: 0)
    }

    private func bigOutputScript() -> [UInt8] {
        let data = (0..<Self.payloadByteCount).map { _ in UInt8.random(in: .min ... .max) }
        return [0x00, 0x6a, 0x4e]
            + withUnsafeBytes(of: UInt32(data.count).littleEndian, Array.init) + data
    }

    private func safeOptions() throws -> WalletCreateActionOptions {
        try WalletCreateActionOptions(signAndProcess: false, noSend: true)
    }

    /// Releases anything an unexpected success reserved.
    private func abortIfAccepted(_ outcome: Outcome, _ client: StorageClient, _ auth: AuthID) async {
        guard case .accepted(let result) = outcome,
              let reference = result?["reference"]?.stringValue else { return }
        _ = try? await client.call(
            "abortAction",
            [.object(auth.jsonObject), .object(["reference": .string(reference)])]
        )
        print("LIVEPROBE aborted unexpected action reference=\(reference)")
    }

    // MARK: - (a) Negotiation

    /// The settings read asks for binary, the server echoes it, and the next request is binary.
    func test_probeA_settingsReadNegotiatesBinaryRequests() async throws {
        let live = try live()
        let (client, recorder, auth) = try makeClient(live)

        let settings = try await client.makeAvailable(auth)
        let lastRead = await recorder.last("makeAvailable")
        let read = try XCTUnwrap(lastRead)
        let echoed = read.responseHeader(StorageClient.binaryHeader)

        print("LIVEPROBE endpoint=\(live.endpoint.absoluteString) expectedChain=\(live.chain.rawValue)")
        print("LIVEPROBE settings storageIdentityKey=\(settings.storageIdentityKey) "
            + "storageName=\(settings.storageName) chain=\(settings.chain.rawValue)")
        if let body = read.response?.body,
           let raw = try? JSONDecoder().decode(JSONValue.self, from: Data(body)) {
            let result = raw["result"] ?? raw
            let text = (try? JSONEncoder().encode(result)).map { String(decoding: $0, as: UTF8.self) }
            print("LIVEPROBE settings raw=\(text ?? "-")")
        }
        let headers = (read.response?.headers ?? [:]).sorted { $0.key < $1.key }
            .filter { !$0.key.lowercased().hasPrefix("x-bsv-auth") }
            .map { "\($0.key)=\($0.value)" }.joined(separator: " ")
        print("LIVEPROBE settings responseHeaders: \(headers)")
        print("LIVEPROBE settings binaryEcho=\(echoed ?? "absent")")

        XCTAssertEqual(read.requestHeaders[StorageClient.binaryHeader], "base64")
        XCTAssertEqual(echoed, "base64", "the server did not echo X-BSV-Binary-Encoding: base64")
        XCTAssertEqual(settings.chain, live.chain)

        // A read with no side effects, to see the mode the client is now in.
        _ = try await client.listOutputs(auth, try WalletListOutputsRequest(basket: "default"))
        let lastNext = await recorder.last("listOutputs")
        let next = try XCTUnwrap(lastNext)
        print("LIVEPROBE next request binaryRequestHeader="
            + "\(next.requestHeaders[StorageClient.binaryRequestHeader] ?? "-")")
        XCTAssertEqual(
            next.requestHeaders[StorageClient.binaryRequestHeader], "base64",
            "the client did not switch to binary requests"
        )
    }

    // MARK: - (b) createAction

    /// One ~200 KB output locking script. Scripts travel as hex strings, one JSON value however
    /// long, so this request is small in values with or without binary; it shows a large
    /// createAction reaches storage, and the control says whether this server refuses it anyway.
    func test_probeB_createActionWithALargeOutputReachesStorage() async throws {
        let live = try live()
        let script = bigOutputScript()
        let request = try WalletCreateActionRequest(
            description: "live probe large output",
            outputs: [try WalletCreateActionOutput(
                lockingScript: script, satoshis: 1, outputDescription: "probe"
            )],
            options: try safeOptions()
        )

        let (binaryClient, binaryRecorder, binaryAuth) = try makeClient(live)
        _ = try await binaryClient.makeAvailable(binaryAuth)
        let binary = await outcome {
            let result = try await binaryClient.createAction(binaryAuth, request)
            return .string(result.reference)
        }
        await abortIfAccepted(binary, binaryClient, binaryAuth)
        let binarySent = await binaryRecorder.last("createAction")
        report("B createAction largeOutput", "binary", binary, binarySent)

        let (jsonClient, jsonRecorder, jsonAuth) = try makeClient(live, stripsBinaryNegotiation: true)
        _ = try await jsonClient.makeAvailable(jsonAuth)
        let control = await outcome {
            let result = try await jsonClient.createAction(jsonAuth, request)
            return .string(result.reference)
        }
        await abortIfAccepted(control, jsonClient, jsonAuth)
        let controlSent = await jsonRecorder.last("createAction")
        report("B createAction largeOutput", "control", control, controlSent)

        assertReachedStorage("B createAction largeOutput", binary, binarySent)
        assertControlWasJSON("B createAction largeOutput", controlSent)
    }

    /// The createAction byte parameter: a ~200 KB `inputBEEF` naming one input. As an array of
    /// numbers it is over the auth cap; as base64 it is one value. The input is an OP_RETURN of a
    /// transaction with no inputs and no proof, so storage can only refuse it.
    func test_probeB2_createActionWithALargeInputBEEFReachesStorage() async throws {
        let live = try live()
        let parent = try inertTransaction()
        let parentTxid = try parent.transactionID(limits: StorageLimits.transaction)
        // BRC-62 (V1): version, no BUMPs, one transaction, no BUMP for it.
        let beefBytes = [0x01, 0x00, 0xbe, 0xef, 0x00, 0x01]
            + (try parent.serialized(limits: StorageLimits.transaction)) + [0x00]
        let beef = try BEEF(bytes: beefBytes, limits: StorageLimits.beef, transactionOrder: .any)
        let request = try WalletCreateActionRequest(
            description: "live probe large input BEEF",
            inputBEEF: beef,
            inputs: [try WalletCreateActionInput(
                outpoint: Outpoint(transactionID: parentTxid, outputIndex: 0),
                inputDescription: "probe", unlockingScriptLength: 1
            )],
            outputs: [try WalletCreateActionOutput(
                lockingScript: [0x00, 0x6a], satoshis: 0, outputDescription: "probe"
            )],
            options: try safeOptions()
        )

        let (binaryClient, binaryRecorder, binaryAuth) = try makeClient(live)
        _ = try await binaryClient.makeAvailable(binaryAuth)
        let binary = await outcome {
            let result = try await binaryClient.createAction(binaryAuth, request)
            return .string(result.reference)
        }
        await abortIfAccepted(binary, binaryClient, binaryAuth)
        let binarySent = await binaryRecorder.last("createAction")
        report("B2 createAction largeInputBEEF", "binary", binary, binarySent)

        let (jsonClient, jsonRecorder, jsonAuth) = try makeClient(live, stripsBinaryNegotiation: true)
        _ = try await jsonClient.makeAvailable(jsonAuth)
        let control = await outcome {
            let result = try await jsonClient.createAction(jsonAuth, request)
            return .string(result.reference)
        }
        await abortIfAccepted(control, jsonClient, jsonAuth)
        let controlSent = await jsonRecorder.last("createAction")
        report("B2 createAction largeInputBEEF", "control", control, controlSent)

        assertReachedStorage("B2 createAction largeInputBEEF", binary, binarySent)
        assertControlWasJSON("B2 createAction largeInputBEEF", controlSent)
    }

    // MARK: - (c) processAction

    /// A ~200 KB raw transaction under a reference storage never issued. `isNoSend`, and the
    /// transaction spends nothing, so nothing can be broadcast or spent whatever storage does.
    func test_probeC_processActionWithALargeRawTxReachesStorage() async throws {
        let live = try live()
        let raw = try inertTransaction().serialized(limits: StorageLimits.transaction)
        let reference = Data((0..<12).map { _ in UInt8.random(in: .min ... .max) })
            .base64EncodedString()
        let request = StorageProcessActionRequest(
            reference: reference, isNewTx: true, isSendWith: false, rawTX: raw, sendWith: [],
            isNoSend: true, isDelayed: true
        )

        let (binaryClient, binaryRecorder, binaryAuth) = try makeClient(live)
        _ = try await binaryClient.makeAvailable(binaryAuth)
        let binary = await outcome {
            _ = try await binaryClient.processAction(binaryAuth, request)
            return nil
        }
        let binarySent = await binaryRecorder.last("processAction")
        report("C processAction largeRawTx", "binary", binary, binarySent)

        let (jsonClient, jsonRecorder, jsonAuth) = try makeClient(live, stripsBinaryNegotiation: true)
        _ = try await jsonClient.makeAvailable(jsonAuth)
        let control = await outcome {
            _ = try await jsonClient.processAction(jsonAuth, request)
            return nil
        }
        let controlSent = await jsonRecorder.last("processAction")
        report("C processAction largeRawTx", "control", control, controlSent)

        assertReachedStorage("C processAction largeRawTx", binary, binarySent)
        assertControlWasJSON("C processAction largeRawTx", controlSent)
    }
}
