import XCTest
import BSVCore
import BSVInterpreter
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage
@testable import ToolboxActions

/// The BRC-177 client flow against a scripted storage: funding, activation, the reclaim, and the
/// protected action, in that order, with every reservation aborted on failure.
final class NoSendExpiryActionTests: XCTestCase {

    private actor ScriptedStorage: NoSendExpiryStorage {
        enum Call: Equatable {
            case capabilities
            case prepare
            case process(reference: String, isNoSend: Bool)
            case activate(fundingReference: String, fundingTxid: String, anchorVout: UInt32)
            case arm(reference: String)
            case abort(reference: String)
        }

        let identity: PrivateKey
        var supported = true
        var fundingStatus: SendWithResult.Status = .unproven
        var armFails = false
        var activateMode = "seconds"
        private(set) var calls: [Call] = []
        private(set) var armed: NoSendExpiryArm?
        private(set) var processed: [StorageProcessActionRequest] = []

        static let fundingPrefix = "RnVuZGluZ1ByZWZpeA=="
        static let anchorSuffix = "QW5jaG9yU3VmZml4"
        static let fundingReference = Data("funding".utf8).base64EncodedString()
        static let targetReference = Data("target".utf8).base64EncodedString()

        private var source: Transaction?

        init(identity: PrivateKey) { self.identity = identity }

        private func graph(_ transactions: [Transaction]) throws -> [UInt8] {
            try BEEF(
                version: .v2, merklePaths: [], transactions: transactions.map { .raw($0) },
                limits: WalletBEEFLimits.standard
            ).serialized(limits: WalletBEEFLimits.standard)
        }

        func configure(
            supported: Bool = true, fundingStatus: SendWithResult.Status = .unproven,
            armFails: Bool = false, activateMode: String = "seconds"
        ) {
            self.supported = supported
            self.fundingStatus = fundingStatus
            self.armFails = armFails
            self.activateMode = activateMode
        }

        func supportsNoSendExpiry() async throws -> Bool {
            calls.append(.capabilities)
            return supported
        }

        func prepareNoSendExpiry(
            _ auth: AuthID, _ target: WalletCreateActionRequest
        ) async throws -> NoSendExpiryPrepared {
            calls.append(.prepare)
            let sourceKey = try BRC29.receivingPrivateKey(
                recipient: identity, sender: identity.publicKey,
                prefix: Self.fundingPrefix, suffix: "U291cmNl"
            )
            let source = Transaction(
                version: 1, inputs: [],
                outputs: [TransactionOutput(
                    satoshis: 10_000, lockingScript: try BRC29.lockingScript(for: sourceKey.publicKey)
                )],
                lockTime: 0
            )
            self.source = source
            let funding = StorageCreateActionResult(
                reference: Self.fundingReference, version: 1, lockTime: 0,
                outputs: [
                    StorageActionOutput(
                        vout: 0, satoshis: 1_000, lockingScript: [0x00], providedBy: .storage,
                        purpose: .change, derivationSuffix: Self.anchorSuffix
                    ),
                    StorageActionOutput(
                        vout: 1, satoshis: 8_900, lockingScript: [0x00], providedBy: .storage,
                        purpose: .change, derivationSuffix: "Q2hhbmdl"
                    ),
                ],
                inputs: [StorageActionInput(
                    sourceTXID: try source.transactionID(limits: WalletTransactionLimits.standard).displayHex,
                    sourceVout: 0, sourceSatoshis: 10_000,
                    sourceLockingScript: try BRC29.lockingScript(for: sourceKey.publicKey).bytes,
                    unlockingScriptLength: 107, derivationPrefix: Self.fundingPrefix,
                    derivationSuffix: "U291cmNl"
                )],
                inputBEEF: try graph([source]), derivationPrefix: Self.fundingPrefix
            )
            return NoSendExpiryPrepared(
                funding: funding, anchorSatoshis: 1_000, anchorVout: 0,
                reclaimFee: 100, reclaimSatoshis: 900
            )
        }

        func activateNoSendExpiry(
            _ auth: AuthID, target: WalletCreateActionRequest, fundingReference: String,
            fundingTxid: String, anchorVout: UInt32
        ) async throws -> NoSendExpiryActivated {
            calls.append(.activate(
                fundingReference: fundingReference, fundingTxid: fundingTxid, anchorVout: anchorVout
            ))
            let anchorKey = try BRC29.receivingPrivateKey(
                recipient: identity, sender: identity.publicKey,
                prefix: Self.fundingPrefix, suffix: Self.anchorSuffix
            )
            let requested = target.outputs ?? []
            let action = StorageCreateActionResult(
                reference: Self.targetReference, version: 1, lockTime: 0,
                outputs: requested.enumerated().map { index, output in
                    StorageActionOutput(
                        vout: UInt32(index), satoshis: output.satoshis,
                        lockingScript: output.lockingScript, providedBy: .you,
                        purpose: nil, derivationSuffix: nil
                    )
                },
                inputs: [StorageActionInput(
                    sourceTXID: fundingTxid, sourceVout: anchorVout, sourceSatoshis: 1_000,
                    sourceLockingScript: try BRC29.lockingScript(for: anchorKey.publicKey).bytes,
                    unlockingScriptLength: 107, derivationPrefix: Self.fundingPrefix,
                    derivationSuffix: Self.anchorSuffix
                )],
                inputBEEF: try graph([
                    try XCTUnwrap(source),
                    try Transaction(bytes: try XCTUnwrap(processed.first?.rawTX),
                                    limits: WalletTransactionLimits.standard),
                ]),
                derivationPrefix: Self.fundingPrefix
            )
            return NoSendExpiryActivated(
                action: action, mode: activateMode, deadline: 1_900_000_000,
                anchorTxid: fundingTxid, anchorVout: anchorVout
            )
        }

        func armNoSendExpiry(_ auth: AuthID, _ arm: NoSendExpiryArm) async throws {
            calls.append(.arm(reference: arm.reference))
            if armFails { throw NoSendExpiryError.unexpectedAction("refused") }
            armed = arm
        }

        func processAction(
            _ auth: AuthID, _ request: StorageProcessActionRequest
        ) async throws -> StorageProcessActionResult {
            calls.append(.process(reference: request.reference, isNoSend: request.isNoSend))
            processed.append(request)
            if request.reference == Self.fundingReference {
                return StorageProcessActionResult(sendWithResults: [
                    SendWithResult(txid: "00", status: fundingStatus),
                ])
            }
            return StorageProcessActionResult(sendWithResults: [])
        }

        func abortAction(
            _ auth: AuthID, _ request: WalletAbortActionRequest
        ) async throws -> WalletAbortActionResult {
            calls.append(.abort(reference: request.reference.base64))
            return WalletAbortActionResult(aborted: true)
        }
    }

    private let auth = AuthID(identityKey: "02" + String(repeating: "11", count: 32))

    private func identity() throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [7])
    }

    private func request(labels: [String] = ["p nosend expiry seconds 31536000"]) throws
        -> WalletCreateActionRequest {
        try WalletCreateActionRequest(
            description: "Hand off",
            outputs: [try WalletCreateActionOutput(
                lockingScript: [0x76, 0xa9, 0x14] + [UInt8](repeating: 3, count: 20) + [0x88, 0xac],
                satoshis: 1, outputDescription: "handoff"
            )],
            labels: labels,
            options: try WalletCreateActionOptions(noSend: true, randomizeOutputs: false)
        )
    }

    private func verify(_ transaction: Transaction) throws {
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

    func test_theFlowFundsActivatesArmsThenProcessesAsNoSend() async throws {
        let identity = try identity()
        let storage = ScriptedStorage(identity: identity)

        let result = try await NoSendExpiryAction.run(
            storage: storage, auth: auth, identity: identity, request: try request(),
            maximumFee: 1_000, signCallerInputs: { _, _ in [:] }
        )

        let calls = await storage.calls
        let processed = await storage.processed
        let funding = try Transaction(bytes: try XCTUnwrap(processed.first?.rawTX),
                                      limits: WalletTransactionLimits.standard)
        let fundingTxid = try funding.transactionID(limits: WalletTransactionLimits.standard).displayHex
        XCTAssertEqual(calls, [
            .capabilities,
            .prepare,
            .process(reference: ScriptedStorage.fundingReference, isNoSend: false),
            .activate(fundingReference: ScriptedStorage.fundingReference,
                      fundingTxid: fundingTxid, anchorVout: 0),
            .arm(reference: ScriptedStorage.targetReference),
            .process(reference: ScriptedStorage.targetReference, isNoSend: true),
        ])
        XCTAssertEqual(result.anchorTxid, fundingTxid)
        XCTAssertEqual(result.deadline, 1_900_000_000)

        // The protected action spends the anchor, and the signature verifies.
        var target = result.signed.transaction
        XCTAssertEqual(target.inputs.count, 1)
        XCTAssertEqual(target.inputs[0].previousOutput.transactionID.displayHex, fundingTxid)
        target.inputs[0].sourceOutput = funding.outputs[0]
        try verify(target)
        XCTAssertFalse(processed[1].isDelayed)
    }

    func test_theReclaimHasTheShapeStorageRequiresAndVerifies() async throws {
        let identity = try identity()
        let storage = ScriptedStorage(identity: identity)
        _ = try await NoSendExpiryAction.run(
            storage: storage, auth: auth, identity: identity, request: try request(),
            maximumFee: 1_000, signCallerInputs: { _, _ in [:] }
        )
        let armed = await storage.armed
        let arm = try XCTUnwrap(armed)
        let processed = await storage.processed
        let funding = try Transaction(bytes: try XCTUnwrap(processed.first?.rawTX),
                                      limits: WalletTransactionLimits.standard)

        var reclaim = try Transaction(bytes: arm.reclaimRawTx, limits: WalletTransactionLimits.standard)
        XCTAssertEqual(try reclaim.serialized(limits: WalletTransactionLimits.standard), arm.reclaimRawTx)
        XCTAssertEqual(try reclaim.transactionID(limits: WalletTransactionLimits.standard).displayHex,
                       arm.reclaimTxid)
        XCTAssertLessThanOrEqual(arm.reclaimRawTx.count, 1000)
        XCTAssertEqual(reclaim.version, 1)
        XCTAssertEqual(reclaim.lockTime, 0)
        XCTAssertEqual(reclaim.inputs.count, 1)
        XCTAssertEqual(reclaim.inputs[0].sequence, 0xffff_ffff)
        XCTAssertEqual(reclaim.inputs[0].previousOutput.outputIndex, 0)
        XCTAssertEqual(reclaim.outputs.count, 1)
        XCTAssertEqual(reclaim.outputs[0].satoshis, 900)
        XCTAssertEqual(arm.reclaimSatoshis, 900)

        // Paid back to this wallet under the derivation it reports.
        let own = try BRC29.receivingPrivateKey(
            recipient: identity, sender: identity.publicKey,
            prefix: arm.reclaimDerivationPrefix, suffix: arm.reclaimDerivationSuffix
        )
        XCTAssertEqual(reclaim.outputs[0].lockingScript.bytes,
                       try BRC29.lockingScript(for: own.publicKey).bytes)
        XCTAssertEqual(Data(base64Encoded: arm.reclaimDerivationPrefix)?.count, 16)
        XCTAssertEqual(Data(base64Encoded: arm.reclaimDerivationSuffix)?.count, 16)

        // SIGHASH_ALL|FORKID, and valid against the anchor.
        let chunks = reclaim.inputs[0].unlockingScript.bytes
        let signatureLength = Int(chunks[0])
        XCTAssertEqual(chunks[signatureLength], 0x41)
        reclaim.inputs[0].sourceOutput = funding.outputs[0]
        try verify(reclaim)
    }

    func test_neverArmsNothing() async throws {
        let identity = try identity()
        let storage = ScriptedStorage(identity: identity)
        await storage.configure(activateMode: "never")
        _ = try await NoSendExpiryAction.run(
            storage: storage, auth: auth, identity: identity,
            request: try request(labels: ["p nosend expiry never"]),
            maximumFee: 1_000, signCallerInputs: { _, _ in [:] }
        )
        let calls = await storage.calls
        XCTAssertFalse(calls.contains(.arm(reference: ScriptedStorage.targetReference)))
    }

    func test_unsupportedStorageIsRefusedBeforeAnythingIsReserved() async throws {
        let identity = try identity()
        let storage = ScriptedStorage(identity: identity)
        await storage.configure(supported: false)
        do {
            _ = try await NoSendExpiryAction.run(
                storage: storage, auth: auth, identity: identity, request: try request(),
                maximumFee: 1_000, signCallerInputs: { _, _ in [:] }
            )
            XCTFail("expected a refusal")
        } catch let error as NoSendExpiryError {
            XCTAssertEqual(error, .unsupported)
        }
        let calls = await storage.calls
        XCTAssertEqual(calls, [.capabilities])
    }

    func test_aFailedFundingBroadcastAbortsTheFunding() async throws {
        let identity = try identity()
        let storage = ScriptedStorage(identity: identity)
        await storage.configure(fundingStatus: .failed)
        do {
            _ = try await NoSendExpiryAction.run(
                storage: storage, auth: auth, identity: identity, request: try request(),
                maximumFee: 1_000, signCallerInputs: { _, _ in [:] }
            )
            XCTFail("expected a refusal")
        } catch {}
        let calls = await storage.calls
        XCTAssertEqual(calls.last, .abort(reference: ScriptedStorage.fundingReference))
    }

    func test_aRefusedArmAbortsTheProtectedAction() async throws {
        let identity = try identity()
        let storage = ScriptedStorage(identity: identity)
        await storage.configure(armFails: true)
        do {
            _ = try await NoSendExpiryAction.run(
                storage: storage, auth: auth, identity: identity, request: try request(),
                maximumFee: 1_000, signCallerInputs: { _, _ in [:] }
            )
            XCTFail("expected a refusal")
        } catch {}
        let calls = await storage.calls
        XCTAssertEqual(calls.last, .abort(reference: ScriptedStorage.targetReference))
        XCTAssertFalse(calls.contains(.process(reference: ScriptedStorage.targetReference, isNoSend: true)))
    }

    func test_aModeOtherThanTheLabelIsRefused() async throws {
        let identity = try identity()
        let storage = ScriptedStorage(identity: identity)
        await storage.configure(activateMode: "never")
        do {
            _ = try await NoSendExpiryAction.run(
                storage: storage, auth: auth, identity: identity, request: try request(),
                maximumFee: 1_000, signCallerInputs: { _, _ in [:] }
            )
            XCTFail("expected a refusal")
        } catch {}
        let calls = await storage.calls
        XCTAssertEqual(calls.last, .abort(reference: ScriptedStorage.targetReference))
    }

    // MARK: - Labels

    func test_labelsParse() throws {
        XCTAssertNil(try NoSendExpiry.parse(labels: ["1color send aa bb"]))
        XCTAssertEqual(try NoSendExpiry.parse(labels: ["p nosend expiry seconds 31536000"]),
                       .seconds(31_536_000))
        XCTAssertEqual(try NoSendExpiry.parse(labels: ["p nosend expiry never"]), .never)
        XCTAssertEqual(try NoSendExpiry.parse(labels: ["p nosend expiry timestamp 0"]), .timestamp(0))
        XCTAssertEqual(try NoSendExpiry.parse(labels: ["p nosend expiry blockheight 900000"]),
                       .blockHeight(900_000))
        XCTAssertEqual(NoSendExpiry.Expiry.seconds(5).label, "p nosend expiry seconds 5")
        for bad in [
            ["p nosend expiry seconds 0"], ["p nosend expiry seconds 01"],
            ["p nosend expiry seconds -1"], ["p nosend expiry seconds"],
            ["p nosend expiry minutes 5"], ["p nosend later"],
            ["p nosend expiry never", "p nosend expiry seconds 5"],
            ["p nosend expiry seconds 9007199254740992"],
        ] {
            XCTAssertThrowsError(try NoSendExpiry.parse(labels: bad), "\(bad)")
        }
    }
}
