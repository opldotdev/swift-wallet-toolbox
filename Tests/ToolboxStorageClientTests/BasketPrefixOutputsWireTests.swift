import XCTest
import BSVWallet
import ToolboxAuth
import ToolboxCore
import ToolboxStorage
@testable import ToolboxStorageClient

/// The basket-prefix special operation runs in storage. The client's whole job is to send the
/// operation name as the basket and the namespace as the first tag, unchanged, and to read
/// reserved outputs back with `spendable` false rather than dropping them.
final class BasketPrefixOutputsWireTests: XCTestCase {

    private actor RecordingTransport: AuthenticatedTransport {
        private let result: String
        private(set) var bodies: [JSONValue] = []

        init(result: String) { self.result = result }

        func send(
            method: String, path: String, query: String?, headers: [String: String],
            body: [UInt8]?
        ) async throws -> AuthenticatedResponse {
            if let reply = ActiveStorageFixture.reply(to: body) { return reply }
            let request = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
            bodies.append(request)
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

    func test_basketAndTagsAreSentUnchanged() async throws {
        let transport = RecordingTransport(result: #"{"totalOutputs":0,"outputs":[]}"#)
        let storage = StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
        _ = try await storage.listOutputs(auth, try WalletListOutputsRequest(
            basket: ListOutputsSpecOp.basketPrefixOutputs,
            tags: ["p color"],
            include: .lockingScripts,
            pagination: WalletPagination(limit: 10_000)
        ))

        let bodies = await transport.bodies
        XCTAssertEqual(bodies.count, 1)
        XCTAssertEqual(bodies[0]["method"]?.stringValue, "listOutputs")
        let arguments = try XCTUnwrap(bodies[0]["params"]?.arrayValue?[1])
        XCTAssertEqual(
            arguments["basket"],
            .string("b9184a72141e6a4d3d148c67a6d0ad92864a4d85290579ea5bef8bd62eb01b6f")
        )
        XCTAssertEqual(arguments["tags"], .array([.string("p color")]))
        XCTAssertEqual(arguments["tagQueryMode"], .string("any"), "the validator's default")
        XCTAssertEqual(arguments["includeLockingScripts"], .bool(true))
        XCTAssertEqual(arguments["limit"], .number(10_000))
    }

    func test_reservedOutputsAreReadWithSpendableFalse() async throws {
        let first = String(repeating: "0", count: 63) + "1"
        let second = String(repeating: "0", count: 63) + "2"
        let transport = RecordingTransport(result: """
            {"totalOutputs":2,"outputs":[
              {"outpoint":"\(first).0","satoshis":1,"spendable":true,"lockingScript":"51"},
              {"outpoint":"\(second).3","satoshis":1,"spendable":false,"lockingScript":"52"}
            ]}
            """)
        let storage = StorageClient(endpoint: URL(string: "https://storage.example/")!, transport: transport)
        let result = try await storage.listOutputs(auth, try WalletListOutputsRequest(
            basket: ListOutputsSpecOp.basketPrefixOutputs,
            tags: ["p color"],
            include: .lockingScripts
        ))
        XCTAssertEqual(result.totalOutputs, 2)
        XCTAssertEqual(result.outputs.map(\.spendable), [true, false])
        XCTAssertEqual(result.outputs[1].outpoint.description, "\(second).3")
        XCTAssertEqual(result.outputs[1].lockingScript, [0x52])
    }
}
