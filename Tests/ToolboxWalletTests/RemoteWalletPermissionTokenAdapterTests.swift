import Foundation
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxAuth
import ToolboxBRC29
import ToolboxCore
import ToolboxPermissions
import ToolboxStorage
import ToolboxStorageClient
import XCTest
@testable import ToolboxWallet

final class RemoteWalletPermissionTokenAdapterTests: XCTestCase {
    func testAccountIDCanonicalizesKeyBytesAndBindsUserIDPresenceAndValue() throws {
        let key = try testIdentityKey()
        let canonical = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let transport = ScriptedPermissionTransport()

        let nilUser = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: canonical), transport: transport
        ))
        let uppercase = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: canonical.uppercased()), transport: transport
        ))
        let userZero = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: canonical, userID: 0), transport: transport
        ))
        let userOne = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: canonical, userID: 1), transport: transport
        ))

        XCTAssertEqual(nilUser.permissionAccountID, uppercase.permissionAccountID)
        XCTAssertNotEqual(nilUser.permissionAccountID, userZero.permissionAccountID)
        XCTAssertNotEqual(userZero.permissionAccountID, userOne.permissionAccountID)
    }

    func testMismatchedAuthIdentityIsRejectedBeforeTransport() throws {
        let key = try testIdentityKey()
        let other = try PrivateKey([UInt8](repeating: 2, count: 32))
        let authText = other.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let transport = ScriptedPermissionTransport()

        XCTAssertThrowsError(try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: authText), transport: transport
        ))) { error in
            XCTAssertEqual(error as? PermissionTokenMutationError, .accountMismatch)
        }
    }

    func testOnlyRepositoryShapedAdminQueriesReachStorage() async throws {
        let transport = ScriptedPermissionTransport()
        let adapter = try adapter(transport: transport)
        let exact = try WalletListOutputsRequest(
            basket: PermissionTokenBasket.basketAccess.rawValue,
            tags: ["originator example.com", "basket payments"],
            tagQueryMode: .all,
            include: .entireTransactions,
            includeTags: true,
            pagination: WalletPagination(limit: 100, offset: 0),
            seekPermission: false
        )
        let invalid = [
            try WalletListOutputsRequest(basket: "default"),
            try WalletListOutputsRequest(
                basket: "admin other", tags: exact.tags, tagQueryMode: .all,
                include: .entireTransactions, includeTags: true,
                pagination: WalletPagination(limit: 100), seekPermission: false
            ),
            try WalletListOutputsRequest(
                basket: exact.basket, tags: exact.tags, tagQueryMode: .any,
                include: .entireTransactions, includeTags: true,
                pagination: WalletPagination(limit: 100), seekPermission: false
            ),
            try WalletListOutputsRequest(
                basket: exact.basket, tags: [], tagQueryMode: .all,
                include: .entireTransactions, includeTags: true,
                pagination: WalletPagination(limit: 100), seekPermission: false
            ),
            try WalletListOutputsRequest(
                basket: exact.basket, tags: exact.tags, tagQueryMode: .all,
                include: .entireTransactions, includeTags: false,
                pagination: WalletPagination(limit: 100), seekPermission: false
            ),
            try WalletListOutputsRequest(
                basket: exact.basket, tags: exact.tags, tagQueryMode: .all,
                include: .entireTransactions, includeTags: true,
                pagination: WalletPagination(limit: 99), seekPermission: false
            ),
            try WalletListOutputsRequest(
                basket: exact.basket, tags: exact.tags, tagQueryMode: .all,
                include: .entireTransactions, includeTags: true,
                pagination: WalletPagination(limit: 100), seekPermission: true
            ),
        ]

        for request in invalid {
            do {
                _ = try await adapter.listPermissionTokenOutputs(request)
                XCTFail("invalid admin query reached storage")
            } catch let error as RemoteWalletPermissionTokenAdapterError {
                XCTAssertEqual(error, .invalidListRequest)
            }
        }
        let rejectedCallCount = await transport.callCount()
        XCTAssertEqual(rejectedCallCount, 0)

        let result = try await adapter.listPermissionTokenOutputs(exact)
        XCTAssertEqual(result.totalOutputs, 0)
        let acceptedCallCount = await transport.callCount()
        XCTAssertEqual(acceptedCallCount, 1)
    }


    func testMutationMergesDisjointSourcesSignsAndProcessesWithoutAbort() async throws {
        let key = try testIdentityKey()
        let identity = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let bootstrap = ScriptedPermissionTransport()
        let bootstrapAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: bootstrap
        ))
        let scope = BasketPermissionScope(
            originator: try CanonicalOriginator("example.com"), basket: "payments"
        )
        let oldOne = PermissionToken.dbap(try .init(scope: scope, expiry: 1))
        let oldTwo = PermissionToken.dbap(try .init(scope: scope, expiry: 2))
        let replacement = PermissionToken.dbap(try .init(scope: scope, expiry: 0))
        let first = try await tokenSource(oldOne, adapter: bootstrapAdapter)
        let second = try await tokenSource(oldTwo, adapter: bootstrapAdapter)
        let transport = MutationTransport(sources: [first.fixture, second.fixture])
        let adapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: transport
        ))
        let request = try PermissionTokenMutationRequest(
            accountID: adapter.permissionAccountID,
            consumed: [first.match, second.match],
            created: [replacement]
        )

        let result = try await adapter.commitPermissionTokenMutation(request)

        XCTAssertEqual(result.reference, "cmVm")
        let methods = await transport.methods()
        XCTAssertEqual(methods, ["createAction", "processAction"])
        let recordedAtomicBEEF = await transport.processedAtomicBEEF()
        let atomicBytes = try XCTUnwrap(recordedAtomicBEEF)
        let atomic = try AtomicBEEF(bytes: atomicBytes, limits: StorageLimits.beef)
        XCTAssertEqual(atomic.beef.transactions.count, 3)
    }

    func testPostReservationOutputAndProcessFailuresAbortExactlyOnce() async throws {
        for failure in [MutationTransport.Failure.substituteOutput, .process] {
            let key = try testIdentityKey()
            let identity = key.publicKey.compressedBytes.map {
                String(format: "%02x", $0)
            }.joined()
            let bootstrap = ScriptedPermissionTransport()
            let bootstrapAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
                key: key, auth: AuthID(identityKey: identity), transport: bootstrap
            ))
            let scope = BasketPermissionScope(
                originator: try CanonicalOriginator("example.com"), basket: "payments"
            )
            let old = PermissionToken.dbap(try .init(scope: scope, expiry: 1))
            let replacement = PermissionToken.dbap(try .init(scope: scope, expiry: 0))
            let source = try await tokenSource(old, adapter: bootstrapAdapter)
            let transport = MutationTransport(
                sources: [source.fixture], failure: failure, abortFails: true
            )
            let adapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
                key: key, auth: AuthID(identityKey: identity), transport: transport
            ))
            let request = try PermissionTokenMutationRequest(
                accountID: adapter.permissionAccountID,
                consumed: [source.match],
                created: [replacement]
            )

            do {
                _ = try await adapter.commitPermissionTokenMutation(request)
                XCTFail("failure should not process as success")
            } catch {
                if failure == .process {
                    XCTAssertEqual(error as? MutationTestError, .processFailed)
                } else {
                    XCTAssertNil(error as? MutationTestError,
                                 "abort failure must not mask output-verification failure")
                }
            }
            let abortCount = await transport.abortCount()
            XCTAssertEqual(abortCount, 1)
        }
    }

    func testCancellationBeforeAndAfterReservationHasCorrectAbortBoundary() async throws {
        let key = try testIdentityKey()
        let identity = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let bootstrap = ScriptedPermissionTransport()
        let bootstrapAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: bootstrap
        ))
        let scope = BasketPermissionScope(
            originator: try CanonicalOriginator("example.com"), basket: "payments"
        )
        let source = try await tokenSource(
            .dbap(try .init(scope: scope, expiry: 1)), adapter: bootstrapAdapter
        )

        let beforeTransport = MutationTransport(sources: [source.fixture])
        let beforeAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: beforeTransport
        ))
        let beforeRequest = try PermissionTokenMutationRequest(
            accountID: beforeAdapter.permissionAccountID,
            consumed: [source.match],
            created: []
        )
        let beforeTask = Task {
            try Task.checkCancellation()
            return try await beforeAdapter.commitPermissionTokenMutation(beforeRequest)
        }
        beforeTask.cancel()
        do {
            _ = try await beforeTask.value
            XCTFail("pre-cancelled mutation must stop")
        } catch is CancellationError {}
        let beforeMethods = await beforeTransport.methods()
        XCTAssertTrue(beforeMethods.isEmpty)

        let gate = MutationGate()
        let afterTransport = MutationTransport(sources: [source.fixture], createGate: gate)
        let afterAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: afterTransport
        ))
        let afterRequest = try PermissionTokenMutationRequest(
            accountID: afterAdapter.permissionAccountID,
            consumed: [source.match],
            created: []
        )
        let afterTask = Task { try await afterAdapter.commitPermissionTokenMutation(afterRequest) }
        await gate.waitUntilEntered()
        afterTask.cancel()
        await gate.release()
        do {
            _ = try await afterTask.value
            XCTFail("cancelled reserved mutation must stop")
        } catch is CancellationError {}
        let abortCount = await afterTransport.abortCount()
        XCTAssertEqual(abortCount, 1)
    }

    func testRevocationPreservesAProvenSourceBUMPAndNeverAbortsSuccess() async throws {
        let key = try testIdentityKey()
        let identity = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let bootstrap = ScriptedPermissionTransport()
        let bootstrapAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: bootstrap
        ))
        let scope = BasketPermissionScope(
            originator: try CanonicalOriginator("example.com"), basket: "payments"
        )
        let source = try await tokenSource(
            .dbap(try .init(scope: scope, expiry: 1)),
            adapter: bootstrapAdapter,
            proven: true
        )
        let transport = MutationTransport(sources: [source.fixture])
        let adapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: transport
        ))
        let request = try PermissionTokenMutationRequest(
            accountID: adapter.permissionAccountID,
            consumed: [source.match],
            created: []
        )

        _ = try await adapter.commitPermissionTokenMutation(request)

        let recordedBytes = await transport.processedAtomicBEEF()
        let bytes = try XCTUnwrap(recordedBytes)
        let atomic = try AtomicBEEF(bytes: bytes, limits: StorageLimits.beef)
        XCTAssertEqual(atomic.beef.merklePaths.count, 1)
        let successAbortCount = await transport.abortCount()
        XCTAssertEqual(successAbortCount, 0)
    }

    func testFundedSourceOmissionSubstitutionAndUnrelatedGraphAbortBeforeProcess() async throws {
        let failures: [MutationTransport.Failure] = [
            .omitBEEF, .unrelatedBEEF, .substituteInputScript,
            .substituteInputValue, .substituteInputOutpoint,
        ]
        for failure in failures {
            let key = try testIdentityKey()
            let identity = key.publicKey.compressedBytes.map {
                String(format: "%02x", $0)
            }.joined()
            let bootstrap = ScriptedPermissionTransport()
            let bootstrapAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
                key: key, auth: AuthID(identityKey: identity), transport: bootstrap
            ))
            let scope = BasketPermissionScope(
                originator: try CanonicalOriginator("example.com"), basket: "payments"
            )
            let source = try await tokenSource(
                .dbap(try .init(scope: scope, expiry: 1)), adapter: bootstrapAdapter
            )
            let transport = MutationTransport(sources: [source.fixture], failure: failure)
            let adapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
                key: key, auth: AuthID(identityKey: identity), transport: transport
            ))
            let request = try PermissionTokenMutationRequest(
                accountID: adapter.permissionAccountID,
                consumed: [source.match],
                created: []
            )

            do {
                _ = try await adapter.commitPermissionTokenMutation(request)
                XCTFail("untrustworthy funded source must fail")
            } catch {}
            let methods = await transport.methods()
            XCTAssertFalse(methods.contains("processAction"))
            let abortCount = await transport.abortCount()
            XCTAssertEqual(abortCount, 1)
        }
    }

    func testStorageMayReorderAMixedBRC29AndPermissionTokenInputSet() async throws {
        let key = try testIdentityKey()
        let identity = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let bootstrap = ScriptedPermissionTransport()
        let bootstrapAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: bootstrap
        ))
        let scope = BasketPermissionScope(
            originator: try CanonicalOriginator("example.com"), basket: "payments"
        )
        let source = try await tokenSource(
            .dbap(try .init(scope: scope, expiry: 1)), adapter: bootstrapAdapter
        )
        let mixed = try brc29Source(identity: key)
        let transport = MutationTransport(sources: [source.fixture], extraBRC29: mixed)
        let adapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: transport
        ))
        let request = try PermissionTokenMutationRequest(
            accountID: adapter.permissionAccountID,
            consumed: [source.match],
            created: []
        )

        _ = try await adapter.commitPermissionTokenMutation(request)

        let recorded = await transport.processedAtomicBEEF()
        let atomic = try AtomicBEEF(
            bytes: try XCTUnwrap(recorded), limits: StorageLimits.beef
        )
        let subject = try XCTUnwrap(try atomic.beef.transaction(
            for: atomic.subjectTransactionID, limits: StorageLimits.transaction
        ))
        XCTAssertEqual(subject.inputs.count, 2)
        XCTAssertTrue(subject.inputs.allSatisfy { !$0.unlockingScript.bytes.isEmpty })
    }

    func testFeeFailureAfterReservationAbortsOnce() async throws {
        let key = try testIdentityKey()
        let identity = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let bootstrap = ScriptedPermissionTransport()
        let bootstrapAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: bootstrap
        ))
        let scope = BasketPermissionScope(
            originator: try CanonicalOriginator("example.com"), basket: "payments"
        )
        let source = try await tokenSource(
            .dbap(try .init(scope: scope, expiry: 1)), adapter: bootstrapAdapter
        )
        let transport = MutationTransport(sources: [source.fixture])
        let restrictedWallet = wallet(
            key: key,
            auth: AuthID(identityKey: identity),
            transport: transport,
            maximumFee: 0
        )
        let adapter = try RemoteWalletPermissionTokenAdapter(wallet: restrictedWallet)
        let request = try PermissionTokenMutationRequest(
            accountID: adapter.permissionAccountID,
            consumed: [source.match],
            created: []
        )

        do {
            _ = try await adapter.commitPermissionTokenMutation(request)
            XCTFail("one-satoshi revocation fee must exceed zero fee policy")
        } catch {}
        let abortCount = await transport.abortCount()
        XCTAssertEqual(abortCount, 1)
    }

    func testBrandNewTokenCreationUsesStorageFundingAndProcesses() async throws {
        let key = try testIdentityKey()
        let identity = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let mixed = try brc29Source(identity: key)
        let transport = MutationTransport(sources: [], extraBRC29: mixed)
        let adapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: transport
        ))
        let token = PermissionToken.dbap(try .init(
            scope: .init(
                originator: try CanonicalOriginator("example.com"), basket: "payments"
            ),
            expiry: 0
        ))
        let request = try PermissionTokenMutationRequest(
            accountID: adapter.permissionAccountID,
            consumed: [],
            created: [token]
        )

        _ = try await adapter.commitPermissionTokenMutation(request)

        let methods = await transport.methods()
        let abortCount = await transport.abortCount()
        XCTAssertEqual(methods, ["createAction", "processAction"])
        XCTAssertEqual(abortCount, 0)
    }

    func testInvalidStorageReferenceFailsBeforeSigningOrProcessing() async throws {
        let key = try testIdentityKey()
        let identity = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        let bootstrap = ScriptedPermissionTransport()
        let bootstrapAdapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: bootstrap
        ))
        let source = try await tokenSource(
            .dbap(try .init(
                scope: .init(
                    originator: try CanonicalOriginator("example.com"), basket: "payments"
                ),
                expiry: 1
            )),
            adapter: bootstrapAdapter
        )
        let transport = MutationTransport(
            sources: [source.fixture], failure: .invalidReference
        )
        let adapter = try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: transport
        ))
        let request = try PermissionTokenMutationRequest(
            accountID: adapter.permissionAccountID,
            consumed: [source.match],
            created: []
        )

        do {
            _ = try await adapter.commitPermissionTokenMutation(request)
            XCTFail("noncanonical storage reference must fail")
        } catch let error as PermissionTokenMutationError {
            XCTAssertEqual(error, .invalidStorageReference)
        }
        let methods = await transport.methods()
        XCTAssertEqual(methods, ["createAction"])
    }

    private func adapter(
        transport: any AuthenticatedTransport
    ) throws -> RemoteWalletPermissionTokenAdapter {
        let key = try testIdentityKey()
        let identity = key.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        return try RemoteWalletPermissionTokenAdapter(wallet: wallet(
            key: key, auth: AuthID(identityKey: identity), transport: transport
        ))
    }

    private func wallet(
        key: PrivateKey,
        auth: AuthID,
        transport: any AuthenticatedTransport,
        maximumFee: Int64 = 100_000
    ) -> RemoteWallet {
        let storage = StorageClient(
            endpoint: URL(string: "https://storage.example/")!, transport: transport
        )
        return RemoteWallet(
            storage: storage, identityKey: key, auth: auth, maximumFee: maximumFee
        )
    }

    private func testIdentityKey() throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 1, count: 32))
    }

    private func tokenSource(
        _ token: PermissionToken,
        adapter: RemoteWalletPermissionTokenAdapter,
        proven: Bool = false
    ) async throws -> (match: PermissionTokenMatch, fixture: MutationSourceFixture) {
        let script = try await PermissionTokenCodec.encode(token, using: adapter)
        let transaction = Transaction(outputs: [TransactionOutput(
            satoshis: 1, lockingScript: script
        )])
        let transactionID = try transaction.transactionID(limits: StorageLimits.transaction)
        let outpoint = Outpoint(transactionID: transactionID, outputIndex: 0)
        let beef: BEEF
        if proven {
            let path = try MerklePath(blockHeight: 1, levels: [[.hash(
                offset: 0,
                hash: try Hash256(transactionID.wireBytes),
                isTransactionID: true
            )]])
            beef = try BEEF(
                merklePaths: [path],
                transactions: [.rawWithMerklePath(transaction: transaction, merklePathIndex: 0)],
                limits: StorageLimits.beef
            )
        } else {
            beef = try BEEF(
                merklePaths: [], transactions: [.raw(transaction)], limits: StorageLimits.beef
            )
        }
        return (
            PermissionTokenMatch(
                accountID: adapter.permissionAccountID,
                token: token,
                outpoint: outpoint,
                satoshis: 1,
                lockingScript: script.bytes,
                sourceBEEF: beef
            ),
            MutationSourceFixture(outpoint: outpoint, transaction: transaction)
        )
    }

    private func brc29Source(identity: PrivateKey) throws -> MutationBRC29Fixture {
        let prefix = "Pr=="
        let suffix = "Su=="
        let spendingKey = try BRC29.receivingPrivateKey(
            recipient: identity,
            sender: identity.publicKey,
            prefix: prefix,
            suffix: suffix
        )
        let transaction = Transaction(outputs: [TransactionOutput(
            satoshis: 10,
            lockingScript: try BRC29.lockingScript(for: spendingKey.publicKey)
        )])
        let transactionID = try transaction.transactionID(limits: StorageLimits.transaction)
        let outpoint = Outpoint(transactionID: transactionID, outputIndex: 0)
        let beef = try BEEF(
            merklePaths: [], transactions: [.raw(transaction)], limits: StorageLimits.beef
        )
        return MutationBRC29Fixture(
            source: MutationSourceFixture(outpoint: outpoint, transaction: transaction),
            prefix: prefix,
            suffix: suffix,
            beef: beef
        )
    }
}

private actor ScriptedPermissionTransport: AuthenticatedTransport {
    private var calls = 0

    func callCount() -> Int { calls }

    func send(
        method: String,
        path: String,
        query: String?,
        headers: [String: String],
        body: [UInt8]?
    ) async throws -> AuthenticatedResponse {
        calls += 1
        let request = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
        let envelope = JSONValue.object([
            "jsonrpc": .string("2.0"),
            "id": request["id"] ?? .number(1),
            "result": .object(["totalOutputs": .number(0), "outputs": .array([])]),
        ])
        return AuthenticatedResponse(
            statusCode: 200,
            headers: [:],
            body: Array(try JSONEncoder().encode(envelope))
        )
    }
}

private struct MutationSourceFixture: Sendable {
    let outpoint: Outpoint
    let transaction: Transaction
}

private struct MutationBRC29Fixture: Sendable {
    let source: MutationSourceFixture
    let prefix: String
    let suffix: String
    let beef: BEEF
}

private enum MutationTestError: Error, Equatable {
    case processFailed
    case abortFailed
}

private actor MutationTransport: AuthenticatedTransport {
    enum Failure: Equatable, Sendable {
        case substituteOutput, process, omitBEEF, unrelatedBEEF
        case substituteInputScript, substituteInputValue, substituteInputOutpoint
        case invalidReference
    }

    private let sources: [String: MutationSourceFixture]
    private let failure: Failure?
    private let abortFails: Bool
    private let createGate: MutationGate?
    private let extraBRC29: MutationBRC29Fixture?
    private var calledMethods = [String]()
    private var aborts = 0
    private var processedBEEF: [UInt8]?

    init(
        sources: [MutationSourceFixture],
        failure: Failure? = nil,
        abortFails: Bool = false,
        createGate: MutationGate? = nil,
        extraBRC29: MutationBRC29Fixture? = nil
    ) {
        self.sources = Dictionary(uniqueKeysWithValues: sources.map {
            ($0.outpoint.description, $0)
        })
        self.failure = failure
        self.abortFails = abortFails
        self.createGate = createGate
        self.extraBRC29 = extraBRC29
    }

    func methods() -> [String] { calledMethods }
    func abortCount() -> Int { aborts }
    func processedAtomicBEEF() -> [UInt8]? { processedBEEF }

    func send(
        method: String,
        path: String,
        query: String?,
        headers: [String: String],
        body: [UInt8]?
    ) async throws -> AuthenticatedResponse {
        let request = try JSONDecoder().decode(JSONValue.self, from: Data(body ?? []))
        let rpcMethod = request["method"]?.stringValue ?? ""
        calledMethods.append(rpcMethod)
        let result: JSONValue
        switch rpcMethod {
        case "createAction":
            if let createGate { await createGate.wait() }
            result = try createResult(request)
        case "processAction":
            if failure == .process { throw MutationTestError.processFailed }
            processedBEEF = try byteArray(request["params"]?.arrayValue?[1]["rawTx"])
            result = .object(["sendWithResults": .array([])])
        case "abortAction":
            aborts += 1
            if abortFails { throw MutationTestError.abortFailed }
            result = .object(["aborted": .bool(true)])
        default:
            result = .null
        }
        let envelope = JSONValue.object([
            "jsonrpc": .string("2.0"),
            "id": request["id"] ?? .number(1),
            "result": result,
        ])
        return AuthenticatedResponse(
            statusCode: 200, headers: [:], body: Array(try JSONEncoder().encode(envelope))
        )
    }

    private func createResult(_ request: JSONValue) throws -> JSONValue {
        let arguments = try XCTUnwrap(request["params"]?.arrayValue?[1])
        let inputRows = try XCTUnwrap(arguments["inputs"]?.arrayValue)
        var fundedInputs = try inputRows.map { row -> JSONValue in
            let outpointText = try XCTUnwrap(row["outpoint"]?.stringValue)
            let fixture = try XCTUnwrap(sources[outpointText])
            let output = fixture.transaction.outputs[Int(fixture.outpoint.outputIndex)]
            var sourceTXID = fixture.outpoint.transactionID.displayHex
            var sourceSatoshis = output.satoshis
            var sourceScript = output.lockingScript.bytes
            if failure == .substituteInputOutpoint {
                sourceTXID = String(repeating: "aa", count: 32)
            }
            if failure == .substituteInputValue { sourceSatoshis += 1 }
            if failure == .substituteInputScript { sourceScript = [0x51] }
            return .object([
                "sourceTxid": .string(sourceTXID),
                "sourceVout": .number(Double(fixture.outpoint.outputIndex)),
                "sourceSatoshis": .number(Double(sourceSatoshis)),
                "sourceLockingScript": .string(hex(sourceScript)),
                "unlockingScriptLength": row["unlockingScriptLength"] ?? .number(73),
            ])
        }
        if let extraBRC29 {
            let source = extraBRC29.source
            let output = source.transaction.outputs[Int(source.outpoint.outputIndex)]
            fundedInputs.insert(.object([
                "sourceTxid": .string(source.outpoint.transactionID.displayHex),
                "sourceVout": .number(Double(source.outpoint.outputIndex)),
                "sourceSatoshis": .number(Double(output.satoshis)),
                "sourceLockingScript": .string(hex(output.lockingScript.bytes)),
                "unlockingScriptLength": .number(107),
                "derivationPrefix": .string(extraBRC29.prefix),
                "derivationSuffix": .string(extraBRC29.suffix),
            ]), at: 0)
        }
        var outputRows = try XCTUnwrap(arguments["outputs"]?.arrayValue)
        outputRows = outputRows.enumerated().map { index, row in
            var object = row.objectValue ?? [:]
            object["vout"] = .number(Double(index))
            object["providedBy"] = .string("you")
            if failure == .substituteOutput { object["satoshis"] = .number(2) }
            return .object(object)
        }
        var object: [String: JSONValue] = [
            "reference": .string(failure == .invalidReference ? "not-base64" : "cmVm"),
            "version": .number(1),
            "lockTime": .number(0),
            "inputs": .array(fundedInputs),
            "outputs": .array(outputRows),
        ]
        if failure != .omitBEEF {
            var inputBEEF = arguments["inputBEEF"] ?? .array([])
            if let extraBRC29 {
                let bytes = try byteArray(inputBEEF)
                let graph = bytes.isEmpty
                    ? try BEEF(
                        merklePaths: [], transactions: [], limits: StorageLimits.beef
                    )
                    : try BEEF(bytes: bytes, limits: StorageLimits.beef)
                let merged = try graph.merging(extraBRC29.beef, limits: StorageLimits.beef)
                inputBEEF = .array(try merged.serialized(limits: StorageLimits.beef).map {
                    .number(Double($0))
                })
            }
            if failure == .unrelatedBEEF {
                let bytes = try byteArray(inputBEEF)
                let graph = try BEEF(bytes: bytes, limits: StorageLimits.beef)
                let unrelated = Transaction(outputs: [TransactionOutput(
                    satoshis: 1,
                    lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
                )])
                let expanded = try BEEF(
                    version: graph.version,
                    merklePaths: graph.merklePaths,
                    transactions: graph.transactions + [.raw(unrelated)],
                    limits: StorageLimits.beef
                )
                inputBEEF = .array(try expanded.serialized(limits: StorageLimits.beef).map {
                    .number(Double($0))
                })
            }
            object["inputBeef"] = inputBEEF
        }
        return .object(object)
    }

    private func byteArray(_ value: JSONValue?) throws -> [UInt8] {
        try XCTUnwrap(value?.arrayValue).map {
            UInt8(try XCTUnwrap($0.intValue))
        }
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

private actor MutationGate {
    private var entered = false
    private var released = false
    private var entryWaiters = [CheckedContinuation<Void, Never>]()
    private var releaseWaiters = [CheckedContinuation<Void, Never>]()

    func wait() async {
        entered = true
        let waiters = entryWaiters
        entryWaiters.removeAll()
        waiters.forEach { $0.resume() }
        guard !released else { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
}
