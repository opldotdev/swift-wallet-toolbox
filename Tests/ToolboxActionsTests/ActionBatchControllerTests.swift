import XCTest
import Foundation
import BSVCore
import BSVInterpreter
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxCore
import ToolboxStorage
@testable import ToolboxActions

/// The action-batch controller against a scripted storage.
///
/// The case it exists for: a wallet whose only spendable output is one unspent change output
/// creates a `noSend` anchor, then a publish that spends the anchor's output and is funded by the
/// anchor's own change. Ordinary createAction cannot fund the publish, because the anchor's
/// change is not yet in storage. In a batch, the anchor is staged in memory and both are committed
/// in one manifest when the publish is processed.
final class ActionBatchControllerTests: XCTestCase, @unchecked Sendable {

    // MARK: - Fixture

    private let prefix = "cHJlZml4"
    private let suffix = "c3VmZml4"
    private let start = Date(timeIntervalSince1970: 1_800_000_000)

    private func identity() throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [7])
    }

    private var auth: AuthID {
        get throws { AuthID(identityKey: ActionBatchWire.hex(try identity().publicKey.compressedBytes), userID: 9) }
    }

    /// The wallet's single unspent output: BRC-29 change it paid itself.
    private func utxo(satoshis: UInt64 = 1_000, tag: UInt8 = 0) throws -> Transaction {
        let identity = try identity()
        let key = try BRC29.receivingPrivateKey(
            recipient: identity, sender: identity.publicKey, prefix: prefix, suffix: suffix
        )
        return Transaction(
            version: 1,
            inputs: [],
            outputs: [
                TransactionOutput(satoshis: satoshis, lockingScript: try BRC29.lockingScript(for: key.publicKey)),
                // Distinct transactions for distinct tags.
                TransactionOutput(satoshis: 0, lockingScript: try Script(bytes: [0x6a, tag], maximumByteCount: 2)),
            ],
            lockTime: 0
        )
    }

    private func txid(_ transaction: Transaction) throws -> String {
        try transaction.transactionID(limits: WalletTransactionLimits.standard).displayHex
    }

    private func row(_ transaction: Transaction, outputId: Int = 41) throws -> ActionBatchFundingOutput {
        ActionBatchFundingOutput(
            outputId: outputId, txid: try txid(transaction), vout: 0,
            satoshis: transaction.outputs[0].satoshis, change: true, providedBy: "storage",
            purpose: "change", type: "P2PKH", basketId: 1, derivationPrefix: prefix,
            derivationSuffix: suffix
        )
    }

    private func beef(_ transactions: [Transaction]) throws -> [UInt8] {
        try BEEF(
            version: .v2, merklePaths: [], transactions: transactions.map { .raw($0) },
            limits: WalletBEEFLimits.standard
        ).serialized(limits: WalletBEEFLimits.standard)
    }

    private func capabilities(manifestVersion: Int? = 2, version: Int = 1) -> ActionBatchCapabilities {
        ActionBatchCapabilities(
            version: version, maxInlineBytes: 4 * 1024 * 1024, maxBlobBytes: 16 * 1024 * 1024,
            maxConcurrentUploads: 4, leaseMs: 60_000, hardLifetimeMs: 600_000, compactBegin: true,
            manifestVersion: manifestVersion, commitByDigest: false, resume: false,
            maxReservedOutputs: 8
        )
    }

    private func begin(
        _ request: ActionBatchBeginRequest, funding: [Transaction], commission: UInt64 = 0
    ) throws -> ActionBatchBegin {
        ActionBatchBegin(
            batchId: request.batchId,
            expiresAt: start.addingTimeInterval(60),
            hardExpiresAt: start.addingTimeInterval(600),
            changeBasket: ActionBatchChangeBasket(
                basketId: 1, name: "default", numberOfDesiredUTXOs: 32, minimumDesiredUTXOValue: 1_000
            ),
            feeModel: ActionBatchFeeModel(value: 100),
            commissionSatoshis: commission,
            commissionPubKeyHex: nil,
            availableChangeCount: funding.count,
            reservedOutputs: try funding.enumerated().map { try row($1, outputId: 41 + $0) },
            explicitOutputs: [],
            inputBeef: try beef(funding)
        )
    }

    /// OP_DROP OP_TRUE: spent with any single push, leaving a clean stack.
    private let anchorScript: [UInt8] = [0x75, 0x51]
    private let publishScript: [UInt8] = [0x00, 0x6a, 0x04, 0x74, 0x65, 0x73, 0x74]

    private func anchorRequest() throws -> WalletCreateActionRequest {
        try WalletCreateActionRequest(
            description: "sigma anchor",
            outputs: [try WalletCreateActionOutput(
                lockingScript: anchorScript, satoshis: 2, outputDescription: "anchor"
            )],
            labels: ["anchor"],
            options: try WalletCreateActionOptions(acceptDelayedBroadcast: false, noSend: true)
        )
    }

    private func publishRequest(spending anchor: Outpoint, sendWith: [String]) throws -> WalletCreateActionRequest {
        try WalletCreateActionRequest(
            description: "publish",
            inputs: [try WalletCreateActionInput(
                outpoint: anchor, inputDescription: "spend anchor", unlockingScript: [0x51]
            )],
            outputs: [try WalletCreateActionOutput(
                lockingScript: publishScript, satoshis: 0, outputDescription: "inscription"
            )],
            options: try WalletCreateActionOptions(
                acceptDelayedBroadcast: false,
                sendWith: try sendWith.map { try TransactionID(displayHex: $0) }
            )
        )
    }

    /// Signs as `TrackedAction` does: assemble, the caller's own unlocking scripts, then BRC-29 for
    /// every input that carries a derivation.
    private func sign(
        _ funded: StorageCreateActionResult, _ request: WalletCreateActionRequest
    ) throws -> SignedAction {
        let identity = try identity()
        var transaction = try ActionAssembler.assemble(
            funded, requested: request.outputs ?? [], changeKey: identity
        )
        for input in request.inputs ?? [] {
            guard case .script(let bytes) = input.unlocking,
                  let index = funded.inputs.firstIndex(where: {
                      $0.sourceTXID == input.outpoint.transactionID.displayHex
                          && $0.sourceVout == input.outpoint.outputIndex
                  }) else { continue }
            transaction.inputs[index].unlockingScript = try Script(bytes: bytes, maximumByteCount: bytes.count)
        }
        for (index, input) in funded.inputs.enumerated() {
            guard let prefix = input.derivationPrefix, let suffix = input.derivationSuffix else { continue }
            let key = try BRC29.receivingPrivateKey(
                recipient: identity, sender: identity.publicKey, prefix: prefix, suffix: suffix
            )
            try transaction.signPayToPublicKeyHashInput(
                at: index, with: key, limits: WalletTransactionLimits.standard
            )
        }
        return try SignedAction(funded: funded, transaction: transaction)
    }

    /// The anchor's change, which the SDK passes as `fundFrom` for the action after it.
    private func changeOutpoint(_ funded: StorageCreateActionResult, _ signed: SignedAction) throws -> Outpoint {
        let vout = try XCTUnwrap(funded.outputs.first { $0.isChange }?.vout)
        return Outpoint(transactionID: signed.transactionID, outputIndex: vout)
    }

    private func verifyScripts(_ transaction: Transaction) throws {
        let configuration = try ScriptExecutionConfiguration(
            era: .afterGenesis, flags: [.enableForkID], resourceLimits: .standard
        )
        for (index, input) in transaction.inputs.enumerated() {
            let source = try XCTUnwrap(input.sourceOutput)
            _ = try ScriptInterpreter.execute(
                unlockingScript: input.unlockingScript, lockingScript: source.lockingScript,
                configuration: configuration,
                context: ScriptExecutionContext(
                    transaction: transaction, inputIndex: index, spentOutput: source,
                    transactionLimits: WalletTransactionLimits.standard
                )
            )
        }
    }

    private func controller(_ storage: FakeBatchStorage, clock: TestClock? = nil) -> ActionBatchController {
        let clock = clock ?? TestClock(start)
        return ActionBatchController(storage: storage, now: { clock.now })
    }

    // MARK: - The anchor and its publish

    func test_anAnchorAndThePublishItFundsCommitOnce() async throws {
        let auth = try auth
        let funding = try utxo()
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [funding]) }
        let batch = controller(storage)

        // The anchor begins the batch and is funded from the reservation.
        let anchorRequest = try anchorRequest()
        let anchorFunded = try await XCTUnwrapAsync(await batch.plan(auth, anchorRequest))
        XCTAssertEqual(anchorFunded.inputs.map(\.sourceTXID), [try txid(funding)])
        XCTAssertEqual(anchorFunded.outputs.count, 2, "the anchor and one change output")
        let anchor = try sign(anchorFunded, anchorRequest)
        try verifyScripts(anchor.transaction)

        // Staged only: a noSend member makes no storage call.
        let staged = try await XCTUnwrapAsync(
            await batch.process(auth, anchor, sendWith: [], isNoSend: true, isDelayed: false)
        )
        XCTAssertEqual(staged.sendWithResults, [])
        var calls = await storage.calls
        XCTAssertEqual(calls, ["getCapabilities", "beginActionBatch"])

        let anchorTxid = anchor.transactionID.displayHex
        let anchorVout = try XCTUnwrap(anchorFunded.outputs.first { !$0.isChange }?.vout)
        let changeVout = try XCTUnwrap(anchorFunded.outputs.first { $0.isChange }?.vout)
        let anchorOutpoint = Outpoint(transactionID: anchor.transactionID, outputIndex: anchorVout)
        let change = Outpoint(transactionID: anchor.transactionID, outputIndex: changeVout)

        // The publish spends the anchor's output and is funded by the anchor's change.
        let publishRequest = try publishRequest(spending: anchorOutpoint, sendWith: [anchorTxid])
        let publishFunded = try await XCTUnwrapAsync(await batch.plan(auth, publishRequest, fundFrom: [change]))
        XCTAssertEqual(publishFunded.inputs.map(\.sourceTXID), [anchorTxid, anchorTxid])
        XCTAssertEqual(publishFunded.inputs.map(\.sourceVout), [anchorVout, changeVout])
        let publish = try sign(publishFunded, publishRequest)
        try verifyScripts(publish.transaction)
        // The envelope an SDK returns to its caller still builds from the planned graph.
        let envelope = try AtomicBEEF(bytes: try publish.atomicBEEF(), limits: WalletBEEFLimits.standard)
        XCTAssertEqual(envelope.subjectTransactionID, publish.transactionID)

        let result = try await XCTUnwrapAsync(
            await batch.process(auth, publish, sendWith: [anchorTxid], isNoSend: false, isDelayed: false)
        )
        let publishTxid = publish.transactionID.displayHex
        XCTAssertEqual(result.sendWithResults.map(\.txid), [anchorTxid, publishTxid])

        calls = await storage.calls
        XCTAssertEqual(calls, ["getCapabilities", "beginActionBatch", "commitActionBatch"])
        let isActive = await batch.isActive
        XCTAssertFalse(isActive)

        // The manifest as storage would read it.
        let commits = await storage.commits
        let manifest = try XCTUnwrap(commits.first)
        let parsed = try OrderedJSON.parse(manifest.body.utf8Bytes())
        XCTAssertTrue(try ActionBatchDigest.verify(parsed), "storage recomputes the same digest")
        XCTAssertEqual(parsed["digest"]?.stringValue, manifest.digest)
        XCTAssertEqual(parsed["sendWith"], .strings([anchorTxid, publishTxid]))
        XCTAssertEqual(parsed["isDelayed"], .bool(false))
        let actions = try XCTUnwrap(parsed["actions"]?.arrayValue)
        XCTAssertEqual(actions.map { $0["txid"]?.stringValue }, [anchorTxid, publishTxid], "topological order")
        XCTAssertEqual(actions[0]["plan"]?["noSendChangeOutputVouts"], .array([.int(changeVout)]))
        XCTAssertNil(actions[1]["plan"]?["noSendChangeOutputVouts"])
        XCTAssertEqual(actions[0]["metadata"]?["isNoSend"], .bool(true))
        XCTAssertEqual(actions[1]["metadata"]?["isNoSend"], .bool(false))

        // Every raw transaction and the dependency graph travel inline, by digest.
        let blobs = try XCTUnwrap(parsed["inlineBlobs"]?.members)
        func blob(_ digest: String?) throws -> [UInt8] {
            let values = try XCTUnwrap(blobs.first { $0.key == digest }?.value.arrayValue)
            return values.compactMap { $0.int64Value.flatMap(UInt8.init(exactly:)) }
        }
        let rawTransactions = try actions.map {
            try Transaction(bytes: blob($0["rawTxDigest"]?.stringValue), limits: WalletTransactionLimits.standard)
        }
        XCTAssertEqual(try rawTransactions.map(txid), [anchorTxid, publishTxid])
        let dependency = try BEEF(
            bytes: blob(parsed["dependencyBeefDigest"]?.stringValue), limits: WalletBEEFLimits.standard
        )
        let dependencyTxids = try dependency.transactions.map { entry -> String in
            guard case .raw(let transaction) = entry else { throw ActionBatchError.invalidOperation("not raw") }
            return try txid(transaction)
        }
        XCTAssertEqual(dependencyTxids, [try txid(funding)])

        // Each pays at least storage's minimum fee for its signed size.
        for (signed, funded) in [(anchor, anchorFunded), (publish, publishFunded)] {
            let spent = funded.inputs.reduce(Int64(0)) { $0 + $1.sourceSatoshis }
            let paid = signed.transaction.outputs.reduce(UInt64(0)) { $0 + $1.satoshis }
            let size = try signed.transaction.serialized(limits: WalletTransactionLimits.standard).count
            XCTAssertGreaterThanOrEqual(UInt64(spent) - paid, UInt64((Double(size) * 100 / 1000).rounded(.up)))
        }
    }

    /// The manifest is sent in the member order its digest was computed over, and the digest is
    /// computed over the reference's payload order, not the manifest's.
    func test_theManifestKeepsTheReferenceMemberOrder() async throws {
        let auth = try auth
        let funding = try utxo()
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [funding]) }
        let batch = controller(storage)
        let request = try WalletCreateActionRequest(
            description: "send now",
            outputs: [try WalletCreateActionOutput(lockingScript: anchorScript, satoshis: 5, outputDescription: "o")],
            options: try WalletCreateActionOptions(noSend: true)
        )
        let funded = try await XCTUnwrapAsync(await batch.plan(auth, request))
        let signed = try sign(funded, request)
        _ = try await batch.process(auth, signed, sendWith: [], isNoSend: true, isDelayed: true)
        _ = try await batch.send(auth, sendWith: [signed.transactionID.displayHex], isDelayed: true)

        let commits = await storage.commits
        let manifest = try XCTUnwrap(commits.first)
        XCTAssertEqual(manifest.body.members?.map(\.key), [
            "format", "batchId", "actions", "dependencyBeefDigest", "inlineBlobs", "sendWith",
            "isDelayed", "digest",
        ])
        let action = try XCTUnwrap(manifest.body["actions"]?.arrayValue?.first)
        XCTAssertEqual(action.members?.map(\.key), [
            "reference", "txid", "rawTxDigest", "lockingScriptDigests", "deriveLockingScripts",
            "plan", "metadata",
        ])
        XCTAssertEqual(action["plan"]?.members?.map(\.key), [
            "reference", "version", "lockTime", "inputs", "outputs", "derivationPrefix",
            "noSendChangeOutputVouts",
        ])
        XCTAssertEqual(action["plan"]?["inputs"]?.arrayValue?.first?.members?.map(\.key), [
            "vin", "sourceTxid", "sourceVout", "sourceSatoshis", "unlockingScriptLength",
            "providedBy", "type", "derivationPrefix", "derivationSuffix",
        ])
        XCTAssertEqual(action["metadata"]?.members?.map(\.key), [
            "description", "labels", "isNoSend", "isDelayed", "inputs", "outputs",
        ])
        let payload = try ActionBatchDigest.payload(manifest.body.setting("digest", nil))
        XCTAssertEqual(payload.members?.map(\.key), [
            "format", "batchId", "actions", "dependencyBeefDigest", "sendWith", "isDelayed",
        ])
        XCTAssertEqual(payload["actions"]?.arrayValue?.first?["plan"]?.members?.map(\.key), [
            "inputs", "outputs", "noSendChangeOutputVouts", "derivationPrefix", "version",
            "lockTime", "reference",
        ])
        let calls = await storage.calls
        XCTAssertEqual(calls.filter { $0 == "commitActionBatch" }.count, 1)
    }

    // MARK: - Failure

    /// When the publish cannot be committed, the caller aborts and storage releases the batch's
    /// reservations, once.
    func test_aFailedPublishAbortsTheBatchOnce() async throws {
        let auth = try auth
        let funding = try utxo()
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [funding]) }
        await storage.failCommit(with: WireError.internalFailure("broadcast refused"))
        let batch = controller(storage)

        let anchorRequest = try anchorRequest()
        let anchorFunded = try await XCTUnwrapAsync(await batch.plan(auth, anchorRequest))
        let anchor = try sign(anchorFunded, anchorRequest)
        _ = try await batch.process(auth, anchor, isNoSend: true)
        let vout = try XCTUnwrap(anchorFunded.outputs.first { !$0.isChange }?.vout)
        let change = try changeOutpoint(anchorFunded, anchor)
        let publishRequest = try publishRequest(
            spending: Outpoint(transactionID: anchor.transactionID, outputIndex: vout),
            sendWith: [anchor.transactionID.displayHex]
        )
        let publishFunded = try await XCTUnwrapAsync(await batch.plan(auth, publishRequest, fundFrom: [change]))
        let publish = try sign(publishFunded, publishRequest)

        do {
            _ = try await batch.process(
                auth, publish, sendWith: [anchor.transactionID.displayHex], isNoSend: false, isDelayed: false
            )
            XCTFail("the commit failed")
        } catch {
            XCTAssertEqual(error as? WireError, .internalFailure("broadcast refused"))
        }
        let aborted = await batch.abort(auth)
        let again = await batch.abort(auth)
        XCTAssertTrue(aborted)
        XCTAssertFalse(again)
        let calls = await storage.calls
        XCTAssertEqual(calls.filter { $0 == "abortActionBatch" }.count, 1)
        XCTAssertEqual(calls.filter { $0 == "commitActionBatch" }.count, 1)
    }

    /// A terminal lifecycle error retires the batch on the spot; a later abort finds nothing.
    func test_aTerminalStateErrorRetiresTheBatch() async throws {
        let auth = try auth
        let funding = try utxo()
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [funding]) }
        await storage.failCommit(with: WireError.actionBatchState(state: "hard-expired", batchId: nil, message: "gone"))
        let batch = controller(storage)
        let request = try anchorRequest()
        let signed = try sign(try await XCTUnwrapAsync(await batch.plan(auth, request)), request)

        do {
            _ = try await batch.process(auth, signed, isNoSend: false)
            XCTFail("the commit failed")
        } catch WireError.actionBatchState(let state, _, _) {
            XCTAssertEqual(state, "hard-expired")
        }
        let isActive = await batch.isActive
        XCTAssertFalse(isActive)
        let aborted = await batch.abort(auth)
        XCTAssertFalse(aborted)
        let calls = await storage.calls
        XCTAssertEqual(calls.filter { $0 == "abortActionBatch" }.count, 1)
    }

    /// A soft expiry keeps the batch: commit can still reacquire its inputs.
    func test_aSoftExpiryKeepsTheBatch() async throws {
        let auth = try auth
        let funding = try utxo()
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [funding]) }
        await storage.failCommit(with: WireError.actionBatchState(state: "expired", batchId: nil, message: "lease"))
        let batch = controller(storage)
        let request = try anchorRequest()
        let signed = try sign(try await XCTUnwrapAsync(await batch.plan(auth, request)), request)

        await XCTAssertThrowsAsync(try await batch.process(auth, signed, isNoSend: false))
        let isActive = await batch.isActive
        XCTAssertTrue(isActive)
        let calls = await storage.calls
        XCTAssertFalse(calls.contains("abortActionBatch"))
    }

    // MARK: - Fallback to the ordinary calls

    func test_storageWithoutTheCapabilityKeepsTheOrdinaryPath() async throws {
        let auth = try auth
        for capabilities: ActionBatchCapabilities? in [nil, capabilities(manifestVersion: nil), capabilities(manifestVersion: 1), capabilities(version: 2)] {
            let storage = FakeBatchStorage(capabilities: capabilities) { try self.begin($0, funding: [try self.utxo()]) }
            let batch = controller(storage)
            let planned = try await batch.plan(auth, try anchorRequest())
            XCTAssertNil(planned)
            let calls = await storage.calls
            XCTAssertEqual(calls, ["getCapabilities"])
        }

        let failing = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [try self.utxo()]) }
        await failing.failCapabilities()
        let planned = try await controller(failing).plan(auth, try anchorRequest())
        XCTAssertNil(planned, "a failed negotiation is no batch, not an error")
    }

    func test_requestsThatDoNotStartABatchKeepTheOrdinaryPath() async throws {
        let auth = try auth
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [try self.utxo()]) }
        let batch = controller(storage)
        let output = try WalletCreateActionOutput(lockingScript: anchorScript, satoshis: 2, outputDescription: "o")

        let sendNow = try WalletCreateActionRequest(description: "now", outputs: [output])
        let tooManyInputs = try WalletCreateActionRequest(
            description: "many",
            inputs: try (0..<9).map {
                try WalletCreateActionInput(
                    outpoint: Outpoint(transactionID: try TransactionID(displayHex: String(repeating: "ab", count: 32)), outputIndex: UInt32($0)),
                    inputDescription: "i", unlockingScriptLength: 1
                )
            },
            outputs: [output],
            options: try WalletCreateActionOptions(noSend: true)
        )
        let protected = try WalletCreateActionRequest(
            description: "protected", outputs: [output], labels: [NoSendExpiry.labelPrefix + "1800000000"],
            options: try WalletCreateActionOptions(noSend: true)
        )
        let sweep = try WalletCreateActionRequest(
            description: "sweep",
            outputs: [try WalletCreateActionOutput(
                lockingScript: anchorScript, satoshis: ActionBatchPlanner.maxPossibleSatoshis, outputDescription: "all"
            )],
            options: try WalletCreateActionOptions(noSend: true)
        )
        let empty = try WalletCreateActionRequest(description: "empty", options: try WalletCreateActionOptions(noSend: true))
        for request in [sendNow, tooManyInputs, protected, sweep, empty] {
            let planned = try await batch.plan(auth, request)
            XCTAssertNil(planned, request.description)
        }
        let calls = await storage.calls
        XCTAssertEqual(calls, [], "nothing was reserved")
    }

    func test_aFirstActionThatDoesNotFitKeepsTheOrdinaryPath() async throws {
        let auth = try auth
        for error in [
            WireError.invalidParameter(name: "firstAction", message: "too many outputs"),
            WireError.invalidOperation("action batch would exceed the maximum reserved outputs"),
        ] {
            let storage = FakeBatchStorage(capabilities: capabilities()) { _ in throw error }
            let planned = try await controller(storage).plan(auth, try anchorRequest())
            XCTAssertNil(planned)
            let calls = await storage.calls
            XCTAssertEqual(calls, ["getCapabilities", "beginActionBatch"])
        }

        let broken = FakeBatchStorage(capabilities: capabilities()) { _ in throw WireError.internalFailure("down") }
        await XCTAssertThrowsAsync(try await controller(broken).plan(auth, try anchorRequest()))
    }

    /// Commission would have to be paid and validated by every member; such storage keeps the
    /// ordinary path, and the reservation just made is released.
    func test_commissionChargingStorageReleasesTheReservation() async throws {
        let auth = try auth
        let storage = FakeBatchStorage(capabilities: capabilities()) {
            try self.begin($0, funding: [try self.utxo()], commission: 10)
        }
        let batch = controller(storage)
        let planned = try await batch.plan(auth, try anchorRequest())
        XCTAssertNil(planned)
        let calls = await storage.calls
        XCTAssertEqual(calls, ["getCapabilities", "beginActionBatch", "abortActionBatch"])
        let isActive = await batch.isActive
        XCTAssertFalse(isActive)
    }

    /// With a batch open, work that does not spend or send a staged transaction stays out of it.
    func test_unrelatedWorkDoesNotJoinAnOpenBatch() async throws {
        let auth = try auth
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [try self.utxo()]) }
        let batch = controller(storage)
        let request = try anchorRequest()
        let anchor = try sign(try await XCTUnwrapAsync(await batch.plan(auth, request)), request)
        _ = try await batch.process(auth, anchor, isNoSend: true)

        let unrelatedPlan = try await batch.plan(auth, try anchorRequest())
        XCTAssertNil(unrelatedPlan)
        let unrelatedSend = try await batch.send(auth, sendWith: [String(repeating: "cd", count: 32)])
        XCTAssertNil(unrelatedSend)

        // A signed action from elsewhere is not the batch's to process.
        let foreign = try sign(
            StorageCreateActionResult(
                reference: "Zm9yZWlnbg==", version: 1, lockTime: 0,
                outputs: [StorageActionOutput(vout: 0, satoshis: 2, lockingScript: anchorScript, providedBy: .you, purpose: nil, derivationSuffix: nil)],
                inputs: [], inputBEEF: nil, derivationPrefix: prefix
            ),
            request
        )
        let processed = try await batch.process(auth, foreign, isNoSend: false)
        XCTAssertNil(processed)

        let calls = await storage.calls
        XCTAssertEqual(calls, ["getCapabilities", "beginActionBatch"])
        let isActive = await batch.isActive
        XCTAssertTrue(isActive)
    }

    // MARK: - Funding and the lease

    func test_aShortReservationIsExtendedForTheShortfall() async throws {
        let auth = try auth
        let small = try utxo(satoshis: 10, tag: 1)
        let more = try utxo(satoshis: 5_000, tag: 2)
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [small]) }
        await storage.extendWith([try row(more, outputId: 99)], beef: try beef([more]))
        let batch = controller(storage)

        let request = try anchorRequest()
        let funded = try await XCTUnwrapAsync(await batch.plan(auth, request))
        // The smallest reservation that covers the anchor, as the canonical selection picks.
        XCTAssertEqual(funded.inputs.map(\.sourceTXID), [try txid(more)])
        let extensions = await storage.extensions
        XCTAssertEqual(extensions.count, 1)
        XCTAssertEqual(extensions.first?.requestedOutputs, 8)
        XCTAssertEqual(extensions.first?.explicitOutpoints, [])
        XCTAssertGreaterThan(extensions.first?.targetSatoshis ?? 0, 0)
        XCTAssertLessThan(extensions.first?.targetSatoshis ?? .max, 1_000, "the shortfall, not the whole amount")
        try verifyScripts(try sign(funded, request).transaction)
    }

    func test_insufficientFundsAfterAnEmptyExtensionThrowsAndReleases() async throws {
        let auth = try auth
        let storage = FakeBatchStorage(capabilities: capabilities()) {
            try self.begin($0, funding: [try self.utxo(satoshis: 10)])
        }
        let batch = controller(storage)

        do {
            _ = try await batch.plan(auth, try anchorRequest())
            XCTFail("ten satoshis cannot pay for the anchor")
        } catch ActionBatchError.insufficientFunds(let more) {
            XCTAssertGreaterThan(more, 0)
        }
        let calls = await storage.calls
        XCTAssertEqual(calls, ["getCapabilities", "beginActionBatch", "extendActionBatch", "abortActionBatch"])
        let isActive = await batch.isActive
        XCTAssertFalse(isActive)
    }

    func test_theLeaseIsRenewedPastEightyPercent() async throws {
        let auth = try auth
        let clock = TestClock(start)
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [try self.utxo()]) }
        let batch = controller(storage, clock: clock)
        let request = try anchorRequest()
        let anchorFunded = try await XCTUnwrapAsync(await batch.plan(auth, request))
        let anchor = try sign(anchorFunded, request)
        _ = try await batch.process(auth, anchor, isNoSend: true)
        let vout = try XCTUnwrap(anchorFunded.outputs.first { !$0.isChange }?.vout)
        let spend = try publishRequest(
            spending: Outpoint(transactionID: anchor.transactionID, outputIndex: vout), sendWith: []
        )

        // At 40 of 60 seconds: not yet.
        clock.now = start.addingTimeInterval(40)
        let early = try await batch.plan(auth, spend, fundFrom: [try changeOutpoint(anchorFunded, anchor)])
        XCTAssertNotNil(early)
        var renewals = await storage.calls.filter { $0 == "renewActionBatch" }
        XCTAssertEqual(renewals.count, 0)

        // At 50 of 60 seconds the publish renews first; a lapsed race is not an error.
        await storage.renewWith(.failure(WireError.actionBatchState(state: "expired", batchId: nil, message: "")))
        clock.now = start.addingTimeInterval(50)
        let signed = try sign(try XCTUnwrap(early), spend)
        _ = try await batch.process(auth, signed, isNoSend: false)
        renewals = await storage.calls.filter { $0 == "renewActionBatch" }
        XCTAssertEqual(renewals.count, 1)
        let commits = await storage.commits
        XCTAssertEqual(commits.count, 1)
    }

    func test_anAlreadyLapsedLeaseIsLeftForCommitToReacquire() async throws {
        let auth = try auth
        let clock = TestClock(start)
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [try self.utxo()]) }
        let batch = controller(storage, clock: clock)
        let request = try anchorRequest()
        let signed = try sign(try await XCTUnwrapAsync(await batch.plan(auth, request)), request)
        clock.now = start.addingTimeInterval(61)
        _ = try await batch.process(auth, signed, isNoSend: false)
        let calls = await storage.calls
        XCTAssertEqual(calls, ["getCapabilities", "beginActionBatch", "commitActionBatch"])
    }

    func test_renewalMovesTheLeaseForward() async throws {
        let auth = try auth
        let clock = TestClock(start)
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [try self.utxo()]) }
        await storage.renewWith(.success(start.addingTimeInterval(120)))
        let batch = controller(storage, clock: clock)
        let request = try anchorRequest()
        let anchorFunded = try await XCTUnwrapAsync(await batch.plan(auth, request))
        let anchor = try sign(anchorFunded, request)
        _ = try await batch.process(auth, anchor, isNoSend: true)
        let vout = try XCTUnwrap(anchorFunded.outputs.first { !$0.isChange }?.vout)
        let spend = try publishRequest(
            spending: Outpoint(transactionID: anchor.transactionID, outputIndex: vout), sendWith: []
        )
        clock.now = start.addingTimeInterval(55)
        let funded = try await XCTUnwrapAsync(await batch.plan(auth, spend, fundFrom: [try changeOutpoint(anchorFunded, anchor)]))
        // Renewed to 120 s, so at 70 s the commit needs no second renewal.
        clock.now = start.addingTimeInterval(70)
        _ = try await batch.process(auth, try sign(funded, spend), isNoSend: false)
        let renewals = await storage.calls.filter { $0 == "renewActionBatch" }
        XCTAssertEqual(renewals.count, 1)
    }

    /// A chain of noSend members, each funded by the change its predecessor names in
    /// `noSendChange`, is committed by one later broadcast-only call.
    func test_aNoSendChainIsCommittedByALaterSendWith() async throws {
        let auth = try auth
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [try self.utxo()]) }
        let batch = controller(storage)
        let request = try anchorRequest()
        let anchorFunded = try await XCTUnwrapAsync(await batch.plan(auth, request))
        let anchor = try sign(anchorFunded, request)
        _ = try await batch.process(auth, anchor, isNoSend: true)

        let vout = try XCTUnwrap(anchorFunded.outputs.first { !$0.isChange }?.vout)
        let next = try WalletCreateActionRequest(
            description: "held publish",
            inputs: [try WalletCreateActionInput(
                outpoint: Outpoint(transactionID: anchor.transactionID, outputIndex: vout),
                inputDescription: "spend anchor", unlockingScript: [0x51]
            )],
            outputs: [try WalletCreateActionOutput(lockingScript: publishScript, satoshis: 0, outputDescription: "o")],
            options: try WalletCreateActionOptions(
                noSend: true, noSendChange: [try changeOutpoint(anchorFunded, anchor)]
            )
        )
        let nextFunded = try await XCTUnwrapAsync(await batch.plan(auth, next))
        XCTAssertEqual(nextFunded.inputs.count, 2, "the anchor's output and its change")
        let held = try sign(nextFunded, next)
        try verifyScripts(held.transaction)
        let staged = try await batch.process(auth, held, isNoSend: true)
        XCTAssertEqual(staged?.sendWithResults, [])
        var commits = await storage.commits
        XCTAssertEqual(commits.count, 0)

        let txids = [anchor.transactionID.displayHex, held.transactionID.displayHex]
        let sent = try await XCTUnwrapAsync(await batch.send(auth, sendWith: txids))
        XCTAssertEqual(sent.sendWithResults.map(\.txid), txids)
        commits = await storage.commits
        XCTAssertEqual(commits.count, 1)
        XCTAssertEqual(commits.first?.body["sendWith"], .strings(txids))
        XCTAssertTrue(try ActionBatchDigest.verify(try XCTUnwrap(commits.first?.body)))
        let actions = commits.first?.body["actions"]?.arrayValue ?? []
        XCTAssertEqual(actions.map { $0["metadata"]?["isNoSend"] }, [.bool(true), .bool(true)])
        XCTAssertNotNil(actions.last?["plan"]?["noSendChangeOutputVouts"])
    }

    /// A noSend member that names unrelated transactions in sendWith stays staged, and the
    /// unrelated broadcast goes through the ordinary call.
    func test_anUnrelatedSendWithGoesThroughTheOrdinaryCall() async throws {
        let auth = try auth
        let storage = FakeBatchStorage(capabilities: capabilities()) { try self.begin($0, funding: [try self.utxo()]) }
        let batch = controller(storage)
        let request = try anchorRequest()
        let anchor = try sign(try await XCTUnwrapAsync(await batch.plan(auth, request)), request)
        let other = String(repeating: "cd", count: 32)
        _ = try await batch.process(auth, anchor, sendWith: [other], isNoSend: true, isDelayed: true)

        let processed = await storage.processed
        XCTAssertEqual(processed.count, 1)
        XCTAssertEqual(processed.first?.sendWith, [other])
        XCTAssertEqual(processed.first?.isNewTx, false)
        XCTAssertEqual(processed.first?.isSendWith, true)
        XCTAssertEqual(processed.first?.isNoSend, false)
        XCTAssertEqual(processed.first?.isDelayed, true)
        let owns = await batch.owns(reference: anchor.reference)
        XCTAssertTrue(owns)
    }
}

// MARK: - Doubles

final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(_ start: Date) { value = start }

    var now: Date {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
}

actor FakeBatchStorage: ActionBatchStorage {
    private let capabilities: ActionBatchCapabilities?
    private let beginHandler: @Sendable (ActionBatchBeginRequest) throws -> ActionBatchBegin
    private var capabilitiesFail = false
    private var commitError: Error?
    private var renewal: Result<Date, Error>?
    private var extension_: (rows: [ActionBatchFundingOutput], beef: [UInt8]?) = ([], nil)
    private var batchId: String?

    private(set) var calls: [String] = []
    private(set) var commits: [ActionBatchManifest] = []
    private(set) var extensions: [ActionBatchExtendRequest] = []
    private(set) var processed: [StorageProcessActionRequest] = []

    init(
        capabilities: ActionBatchCapabilities?,
        begin: @escaping @Sendable (ActionBatchBeginRequest) throws -> ActionBatchBegin
    ) {
        self.capabilities = capabilities
        self.beginHandler = begin
    }

    func failCapabilities() { capabilitiesFail = true }
    func failCommit(with error: Error) { commitError = error }
    func renewWith(_ result: Result<Date, Error>) { renewal = result }
    func extendWith(_ rows: [ActionBatchFundingOutput], beef: [UInt8]?) { extension_ = (rows, beef) }

    func actionBatchCapabilities() async throws -> ActionBatchCapabilities? {
        calls.append("getCapabilities")
        if capabilitiesFail { throw WireError.notImplemented("getCapabilities") }
        return capabilities
    }

    func beginActionBatch(_ auth: AuthID, _ request: ActionBatchBeginRequest) async throws -> ActionBatchBegin {
        calls.append("beginActionBatch")
        XCTAssertEqual(Data(base64Encoded: request.batchId)?.count, 24)
        let begin = try beginHandler(request)
        batchId = begin.batchId
        return begin
    }

    func extendActionBatch(_ auth: AuthID, _ request: ActionBatchExtendRequest) async throws -> ActionBatchExtension {
        calls.append("extendActionBatch")
        XCTAssertEqual(request.batchId, batchId)
        extensions.append(request)
        let (rows, beef) = extension_
        extension_ = ([], nil)
        return ActionBatchExtension(
            expiresAt: Date(timeIntervalSince1970: 1_800_000_060), reservedOutputs: rows,
            explicitOutputs: [], inputBeef: beef
        )
    }

    func renewActionBatch(_ auth: AuthID, batchId: String) async throws -> Date {
        calls.append("renewActionBatch")
        XCTAssertEqual(batchId, self.batchId)
        guard let renewal else { return Date(timeIntervalSince1970: 1_800_000_120) }
        return try renewal.get()
    }

    func commitActionBatch(_ auth: AuthID, _ manifest: ActionBatchManifest) async throws -> ActionBatchCommitResult {
        calls.append("commitActionBatch")
        commits.append(manifest)
        if let commitError { throw commitError }
        let sendWith = manifest.body["sendWith"]?.arrayValue?.compactMap(\.stringValue) ?? []
        return ActionBatchCommitResult(
            batchId: manifest.batchId, manifestDigest: manifest.digest,
            committedTxids: manifest.body["actions"]?.arrayValue?.compactMap { $0["txid"]?.stringValue } ?? [],
            alreadyCommitted: false,
            sendWithResults: sendWith.map { SendWithResult(txid: $0, status: .unproven) }
        )
    }

    func abortActionBatch(_ auth: AuthID, batchId: String) async throws -> Bool {
        calls.append("abortActionBatch")
        XCTAssertEqual(batchId, self.batchId)
        return true
    }

    func processAction(_ auth: AuthID, _ request: StorageProcessActionRequest) async throws -> StorageProcessActionResult {
        calls.append("processAction")
        processed.append(request)
        return StorageProcessActionResult(sendWithResults: request.sendWith.map { SendWithResult(txid: $0, status: .unproven) })
    }
}

func XCTUnwrapAsync<T>(
    _ expression: @autoclosure () async throws -> T?, file: StaticString = #filePath, line: UInt = #line
) async throws -> T {
    let value = try await expression()
    return try XCTUnwrap(value, file: file, line: line)
}

func XCTAssertThrowsAsync<T>(
    _ expression: @autoclosure () async throws -> T, file: StaticString = #filePath, line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error", file: file, line: line)
    } catch {}
}
