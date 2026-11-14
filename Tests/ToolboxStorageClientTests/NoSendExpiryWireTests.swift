import XCTest
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// The BRC-177 storage calls in the reference client's wire shape.
final class NoSendExpiryWireTests: XCTestCase {

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
    private let txid = "8ac7230489e80000000000000000000000000000000000000000000000000001"

    private func client(_ transport: RecordingTransport) -> StorageClient {
        StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
    }

    private func target(labels: [String] = ["p nosend expiry seconds 60"],
                        noSend: Bool = true) throws -> WalletCreateActionRequest {
        try WalletCreateActionRequest(
            description: "Hand off",
            outputs: [try WalletCreateActionOutput(
                lockingScript: [0x51], satoshis: 1, outputDescription: "handoff"
            )],
            labels: labels,
            options: try WalletCreateActionOptions(noSend: noSend, randomizeOutputs: false)
        )
    }

    private let fundedJSON = """
        {"reference":"cmVm","version":1,"lockTime":0,"derivationPrefix":"UHJl",
         "inputs":[],"outputs":[{"vout":0,"satoshis":1000,"lockingScript":"51",
         "providedBy":"storage","purpose":"change","derivationSuffix":"U3U="}]}
        """

    func test_capabilitiesTakeNoParametersAndRequireVersionOne() async throws {
        let transport = RecordingTransport(results: [
            #"{"brc177NoSendExpiry":{"version":1}}"#, #"{"brc177NoSendExpiry":{"version":2}}"#, "{}",
        ])
        let storage = client(transport)
        let first = try await storage.supportsNoSendExpiry()
        let second = try await storage.supportsNoSendExpiry()
        let third = try await storage.supportsNoSendExpiry()
        XCTAssertTrue(first)
        XCTAssertFalse(second)
        XCTAssertFalse(third)
        let bodies = await transport.bodies
        XCTAssertEqual(bodies[0]["method"]?.stringValue, "getCapabilities")
        XCTAssertEqual(bodies[0]["params"], .array([]))
    }

    func test_prepareSendsTheCreateActionArgumentsAndReadsTheAmounts() async throws {
        let transport = RecordingTransport(results: [
            #"{"funding":\#(fundedJSON),"anchorSatoshis":1000,"anchorVout":0,"reclaimFee":50,"reclaimSatoshis":950}"#,
        ])
        let prepared = try await client(transport).prepareNoSendExpiry(auth, try target())
        XCTAssertEqual(prepared.anchorSatoshis, 1000)
        XCTAssertEqual(prepared.reclaimSatoshis, 950)
        XCTAssertEqual(prepared.funding.reference, "cmVm")

        let bodies = await transport.bodies
        XCTAssertEqual(bodies[0]["method"]?.stringValue, "prepareNoSendExpiry")
        let args = try XCTUnwrap(bodies[0]["params"]?.arrayValue?[1])
        XCTAssertEqual(args, try StorageClient.noSendExpiryTarget(try target()).jsonValue)
        XCTAssertEqual(args["labels"], .array([.string("p nosend expiry seconds 60")]))
        XCTAssertEqual(args["options"]?["noSend"], .bool(true))
        XCTAssertEqual(args["isNoSend"], .bool(true))
    }

    func test_activateWrapsTheSameTarget() async throws {
        let transport = RecordingTransport(results: [
            #"{"action":\#(fundedJSON),"expiry":{"mode":"seconds","value":60,"label":"p nosend expiry seconds 60"},"deadline":1900000000,"anchorTxid":"\#(txid)","anchorVout":0}"#,
        ])
        let activated = try await client(transport).activateNoSendExpiry(
            auth, target: try target(), fundingReference: "Zg==", fundingTxid: txid, anchorVout: 0
        )
        XCTAssertEqual(activated.mode, "seconds")
        XCTAssertEqual(activated.deadline, 1_900_000_000)
        XCTAssertEqual(activated.anchorTxid, txid)

        let recorded = await transport.bodies
        let args = try XCTUnwrap(recorded[0]["params"]?.arrayValue?[1])
        XCTAssertEqual(args["target"], try StorageClient.noSendExpiryTarget(try target()).jsonValue)
        XCTAssertEqual(args["fundingReference"], .string("Zg=="))
        XCTAssertEqual(args["fundingTxid"], .string(txid))
        XCTAssertEqual(args["anchorVout"], .number(0))
    }

    func test_aNullDeadlineIsRead() throws {
        let result = try JSONDecoder().decode(JSONValue.self, from: Data(
            #"{"action":\#(fundedJSON),"expiry":{"mode":"never"},"deadline":null,"anchorTxid":"\#(txid)","anchorVout":3}"#.utf8
        ))
        let activated = try StorageClient.decodeActivated(result)
        XCTAssertNil(activated.deadline)
        XCTAssertEqual(activated.anchorVout, 3)
    }

    func test_armSendsTheReclaimBytes() async throws {
        let transport = RecordingTransport(results: ["null"])
        try await client(transport).armNoSendExpiry(auth, NoSendExpiryArm(
            reference: "cmVm", reclaimTxid: txid, reclaimRawTx: [1, 2, 255],
            reclaimDerivationPrefix: "UA==", reclaimDerivationSuffix: "Uw==", reclaimSatoshis: 950
        ))
        let recorded = await transport.bodies
        let args = try XCTUnwrap(recorded[0]["params"]?.arrayValue?[1])
        XCTAssertEqual(args, .object([
            "reference": .string("cmVm"),
            "reclaimTxid": .string(txid),
            "reclaimRawTx": .array([.number(1), .number(2), .number(255)]),
            "reclaimDerivationPrefix": .string("UA=="),
            "reclaimDerivationSuffix": .string("Uw=="),
            "reclaimSatoshis": .number(950),
        ]))
    }

    func test_targetsStorageWouldRefuseAreRefusedFirst() async throws {
        let transport = RecordingTransport(results: [])
        let storage = client(transport)
        for request in [try target(labels: []), try target(noSend: false)] {
            do {
                _ = try await storage.prepareNoSendExpiry(auth, request)
                XCTFail("expected a refusal")
            } catch is NoSendExpiryError {}
        }
        let bodies = await transport.bodies
        XCTAssertTrue(bodies.isEmpty)
    }
}
