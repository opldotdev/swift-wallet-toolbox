import Foundation
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxBRC29
import ToolboxCore
import ToolboxPaymail
import ToolboxStorage
import ToolboxStorageClient
import XCTest
@testable import ToolboxWallet

final class RemoteWalletActionTests: XCTestCase {
    func testDeferredCreateDoesNotSignOrProcessAndSignIsOneUse() async throws {
        let fixture = try Fixture()
        let created = try await fixture.wallet.createAction(fixture.request(deferred: true))
        let signable = try XCTUnwrap(created.signableTransaction)
        let tx = try XCTUnwrap(signable.transaction.beef.transaction(
            for: signable.transaction.subjectTransactionID, limits: StorageLimits.transaction
        ))
        XCTAssertTrue(tx.inputs.allSatisfy { $0.unlockingScript.bytes.isEmpty })
        let before = await fixture.transport.methods
        XCTAssertEqual(before, ["createAction"])
        let request = try WalletSignActionRequest(reference: signable.reference, spends: [:])
        let result = try await fixture.wallet.signAction(request)
        XCTAssertNotNil(result.transactionID)
        let signed = try XCTUnwrap(result.transaction?.beef.transaction(
            for: try XCTUnwrap(result.transactionID), limits: StorageLimits.transaction
        ))
        XCTAssertFalse(signed.inputs[0].unlockingScript.bytes.isEmpty)
        do { _ = try await fixture.wallet.signAction(request); XCTFail("replayed sign") }
        catch { XCTAssertEqual(error as? WalletActionLifecycleError, .unknownReference) }
        let after = await fixture.transport.methods
        XCTAssertEqual(after, ["createAction", "processAction"])
    }

    func testNoSendAndDelayedOptionsReachStorage() async throws {
        let fixture = try Fixture()
        _ = try await fixture.wallet.createAction(fixture.request(noSend: true))
        let processed = await fixture.transport.processArguments()
        let args = try XCTUnwrap(processed)
        XCTAssertEqual(args["isNoSend"]?.boolValue, true)
        XCTAssertEqual(args["isDelayed"]?.boolValue, true)
        let bytes = try XCTUnwrap(args["rawTx"]?.arrayValue).map { UInt8($0.intValue!) }
        let transaction = try Transaction(bytes: bytes, limits: StorageLimits.transaction)
        XCTAssertEqual(args["txid"]?.stringValue, try transaction.transactionID(limits: StorageLimits.transaction).displayHex)
    }

    func testAbortInvalidatesPendingReference() async throws {
        let fixture = try Fixture()
        let created = try await fixture.wallet.createAction(fixture.request(deferred: true))
        let reference = try XCTUnwrap(created.signableTransaction?.reference)
        _ = try await fixture.wallet.abortAction(.init(reference: reference))
        do {
            _ = try await fixture.wallet.signAction(.init(reference: reference, spends: [:]))
            XCTFail("aborted action signed")
        } catch { XCTAssertEqual(error as? WalletActionLifecycleError, .unknownReference) }
    }

    func testConcurrentSigningProcessesOnlyOnce() async throws {
        let fixture = try Fixture()
        let created = try await fixture.wallet.createAction(fixture.request(deferred: true))
        let request = try WalletSignActionRequest(reference: XCTUnwrap(created.signableTransaction?.reference), spends: [:])
        let successes = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<2 {
                group.addTask { (try? await fixture.wallet.signAction(request)) != nil }
            }
            var count = 0
            for await success in group { if success { count += 1 } }
            return count
        }
        XCTAssertEqual(successes, 1)
        let methods = await fixture.transport.methods
        XCTAssertEqual(methods.filter { $0 == "processAction" }.count, 1)
    }

    func testCallerInputAndSequenceArePreserved() async throws {
        let fixture = try Fixture(foreign: true)
        let created = try await fixture.wallet.createAction(fixture.request(deferred: true))
        let reference = try XCTUnwrap(created.signableTransaction?.reference)
        let result = try await fixture.wallet.signAction(.init(
            reference: reference, spends: [0: try WalletSignActionSpend(unlockingScript: [], sequenceNumber: 42)]
        ))
        let tx = try XCTUnwrap(result.transaction?.beef.transaction(
            for: XCTUnwrap(result.transactionID), limits: StorageLimits.transaction
        ))
        XCTAssertEqual(tx.inputs[0].sequence, 42)
        XCTAssertTrue(tx.inputs[0].unlockingScript.bytes.isEmpty)
        XCTAssertFalse(tx.inputs[1].unlockingScript.bytes.isEmpty)
    }

    func testCannotReplaceWalletInputUnlockingScript() async throws {
        let fixture = try Fixture()
        let created = try await fixture.wallet.createAction(fixture.request(deferred: true))
        do {
            _ = try await fixture.wallet.signAction(.init(
                reference: XCTUnwrap(created.signableTransaction?.reference),
                spends: [0: try WalletSignActionSpend(unlockingScript: [0x51])]
            ))
            XCTFail("wallet input accepted as caller input")
        } catch { XCTAssertEqual(error as? WalletActionLifecycleError, .invalidSpend) }
        let methods = await fixture.transport.methods
        XCTAssertEqual(methods, ["createAction", "abortAction"])
    }

    func testSubstitutedFundingAmountIsRejectedBeforeSigning() async throws {
        let fixture = try Fixture(wrongAmount: true)
        do { _ = try await fixture.wallet.createAction(fixture.request()); XCTFail("trusted false amount") }
        catch { }
        let methods = await fixture.transport.methods
        XCTAssertEqual(methods, ["createAction", "abortAction"])
    }

    /// A paymail host is told about the payment with its BEEF. When the funded graph cannot prove
    /// the payment, it is stopped before the broadcast and its inputs released, so no money moves
    /// that the host would never hear about.
    func testAPaymailPaymentWhoseBEEFCannotBeBuiltIsReleasedBeforeBroadcast() async throws {
        let fixture = try Fixture(omitsFunding: true, isPayment: true)
        let host = PaymailHost()
        do {
            _ = try await fixture.wallet.pay(
                to: "alice@example.com", satoshis: 42, description: "Paymail payment",
                paymail: Paymail(http: host)
            )
            XCTFail("paid without BEEF")
        } catch {
            guard case BEEFError.missingAncestor = error else {
                return XCTFail("expected missingAncestor, got \(error)")
            }
        }
        let methods = await fixture.transport.methods
        XCTAssertEqual(methods, ["createAction", "abortAction"])
        let delivered = await host.delivered
        XCTAssertTrue(delivered.isEmpty)
    }

    func testAPaymailPaymentDeliversTheBEEFBuiltBeforeBroadcast() async throws {
        let fixture = try Fixture(isPayment: true)
        let host = PaymailHost()
        _ = try await fixture.wallet.pay(
            to: "alice@example.com", satoshis: 42, description: "Paymail payment",
            paymail: Paymail(http: host)
        )
        let methods = await fixture.transport.methods
        XCTAssertEqual(methods, ["createAction", "processAction"])
        let delivered = await host.delivered
        XCTAssertEqual(delivered, [PaymailHost.beefURL])
    }

    private struct Fixture {
        let wallet: RemoteWallet
        let transport: ActionTransport
        let foreign: Transaction?

        init(
            foreign: Bool = false, wrongAmount: Bool = false, omitsFunding: Bool = false,
            isPayment: Bool = false
        ) throws {
            let key = try PrivateKey([UInt8](repeating: 1, count: 32))
            let spending = try BRC29.receivingPrivateKey(recipient: key, sender: key.publicKey, prefix: "Pr==", suffix: "Su==")
            let funding = Transaction(outputs: [TransactionOutput(
                satoshis: 100, lockingScript: try BRC29.lockingScript(for: spending.publicKey)
            )])
            self.foreign = foreign ? Transaction(outputs: [TransactionOutput(
                satoshis: 100, lockingScript: try Script(bytes: [0x51], maximumByteCount: 100)
            )]) : nil
            transport = ActionTransport(
                funding: funding, foreign: self.foreign, wrongAmount: wrongAmount, omitsFunding: omitsFunding,
                isPayment: isPayment
            )
            wallet = RemoteWallet(
                storage: StorageClient(endpoint: URL(string: "https://storage.example")!, transport: transport),
                identityKey: key,
                auth: AuthID(identityKey: key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined())
            )
        }

        func request(deferred: Bool = false, noSend: Bool = false) throws -> WalletCreateActionRequest {
            let inputs: [WalletCreateActionInput]?
            let graph: BEEF?
            if let foreign {
                inputs = [try WalletCreateActionInput(
                    outpoint: Outpoint(transactionID: foreign.transactionID(limits: StorageLimits.transaction), outputIndex: 0),
                    inputDescription: "Caller input", unlockingScriptLength: 1, sequenceNumber: 7
                )]
                graph = try BEEF(merklePaths: [], transactions: [.raw(foreign)], limits: StorageLimits.beef)
            } else { inputs = nil; graph = nil }
            return try WalletCreateActionRequest(
                description: "Test spending", inputBEEF: graph, inputs: inputs,
                outputs: [WalletCreateActionOutput(
                    lockingScript: [0x51], satoshis: foreign == nil ? 90 : 190, outputDescription: "Test recipient"
                )],
                options: WalletCreateActionOptions(signAndProcess: !deferred, noSend: noSend)
            )
        }
    }
}

private actor ActionTransport: AuthenticatedTransport {
    let funding: Transaction
    let foreign: Transaction?
    let wrongAmount: Bool
    /// Leaves the funding transaction out of the returned `inputBeef`, as storage that lost it would.
    let omitsFunding: Bool
    /// `RemoteWallet.pay` funds through storage directly rather than the BRC-100 `createAction`.
    let isPayment: Bool
    var methods: [String] = []
    private var processed: JSONValue?

    init(
        funding: Transaction, foreign: Transaction?, wrongAmount: Bool, omitsFunding: Bool = false,
        isPayment: Bool = false
    ) {
        self.funding = funding; self.foreign = foreign; self.wrongAmount = wrongAmount
        self.omitsFunding = omitsFunding; self.isPayment = isPayment
    }
    func processArguments() -> JSONValue? { processed }

    func send(method: String, path: String, query: String?, headers: [String: String], body: [UInt8]?) async throws -> AuthenticatedResponse {
        if let reply = ActiveStorageFixture.reply(to: body) { return reply }
        let rpc = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
        let name = rpc["method"]?.stringValue ?? ""
        methods.append(name)
        let args = try XCTUnwrap(rpc["params"]?.arrayValue?[1])
        let result: JSONValue
        switch name {
        case "createAction":
            if !isPayment { XCTAssertEqual(args["includeAllSourceTransactions"]?.boolValue, true) }
            let transactions = (foreign.map { [$0] } ?? []) + [funding]
            let inputs = try transactions.enumerated().map { index, tx -> JSONValue in
                var row: [String: JSONValue] = [
                    "vin": .number(Double(index)),
                    "sourceTxid": .string(try tx.transactionID(limits: StorageLimits.transaction).displayHex),
                    "sourceVout": .number(0),
                    "sourceSatoshis": .number(wrongAmount ? 101 : 100),
                    "sourceLockingScript": .string(tx.outputs[0].lockingScript.bytes.map { String(format: "%02x", $0) }.joined()),
                    "unlockingScriptLength": .number(107)
                ]
                if index == transactions.count - 1 {
                    row["derivationPrefix"] = .string("Pr=="); row["derivationSuffix"] = .string("Su==")
                }
                return .object(row)
            }
            let outputs = (args["outputs"]?.arrayValue ?? []).enumerated().map { index, row -> JSONValue in
                var value = row.objectValue ?? [:]
                value["vout"] = .number(Double(index)); value["providedBy"] = .string("you")
                return .object(value)
            }
            let graphTransactions = omitsFunding ? Array(transactions.dropLast()) : transactions
            let graph = try BEEF(merklePaths: [], transactions: graphTransactions.map { .raw($0) }, limits: StorageLimits.beef)
            result = .object([
                "reference": .string("dGVzdA=="), "version": .number(1), "lockTime": .number(0),
                "inputs": .array(inputs.reversed()), "outputs": .array(outputs),
                "inputBeef": .array(try graph.serialized(limits: StorageLimits.beef).map { .number(Double($0)) })
            ])
        case "processAction":
            processed = args
            result = .object(["sendWithResults": .array([])])
        case "abortAction": result = .object(["aborted": .bool(true)])
        default: throw WalletActionLifecycleError.invalidFunding
        }
        return AuthenticatedResponse(statusCode: 200, headers: [:], body: Array(try JSONEncoder().encode(JSONValue.object([
            "jsonrpc": .string("2.0"), "id": rpc["id"]!, "result": result
        ]))))
    }
}

/// A paymail host for `alice@example.com` with destination and receive-BEEF capabilities. It
/// records the delivery URLs it was posted to.
private actor PaymailHost: PaymailHTTP {
    static let dnsURL = "https://dns.google.com/resolve?name=_bsvalias._tcp.example.com&type=SRV&cd=0"
    static let capabilitiesURL = "https://example.com:443/.well-known/bsvalias"
    static let destinationURL = "https://pay.example.com/alice/example.com/destination"
    static let beefURL = "https://pay.example.com/alice/example.com/beef"

    private(set) var delivered: [String] = []

    func get(_ url: URL) async throws -> (status: Int, body: [UInt8]) {
        switch url.absoluteString {
        case Self.dnsURL:
            return (200, Array(#"{"Status":3}"#.utf8))
        case Self.capabilitiesURL:
            return (200, Array("""
                {"capabilities":{\
                "2a40af698840":"https://pay.example.com/{alias}/{domain.tld}/destination",\
                "5c55a7fdb7bb":"https://pay.example.com/{alias}/{domain.tld}/beef"}}
                """.utf8))
        default:
            throw URLError(.badURL)
        }
    }

    func post(_ url: URL, json: [UInt8]) async throws -> (status: Int, body: [UInt8]) {
        switch url.absoluteString {
        case Self.destinationURL:
            return (200, Array(#"{"reference":"payment-reference","outputs":[{"script":"51","satoshis":42}]}"#.utf8))
        case Self.beefURL:
            delivered.append(url.absoluteString)
            return (200, Array("{}".utf8))
        default:
            throw URLError(.badURL)
        }
    }
}
