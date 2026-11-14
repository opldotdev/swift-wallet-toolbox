import XCTest
import Foundation
import BSVCore
import BSVCrypto
import BSVInterpreter
import BSVKeys
import BSVOverlay
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxStorage
@testable import ToolboxWallet

/// Vectors from `@bsv/sdk` 4.1.0 with `@bsv/message-box-client` 2.7.0's arguments, made with Bun by
/// `docs/research/messagebox-advertisement-vectors.ts`.
private enum Vector {
    static let rootKey = "6a1751169c111b4667a6539ee1be6b7cd9f6e9c8fe011a5f2fe31e03a15e0ede"
    static let identityKey = "02133b035cda4ba15f93b5fdde11c1f73eb9f1a79b60c6caa1c78e1c4c64ed72ce"
    /// `anointHost('https://messagebox.1sat.app')`'s locking script.
    static let oneSatLock = "2102fb636d95c40760392db1e4cdcd9818504e26efe952edaf0d9eaa97c6854e0b4fac2102133b035cda4ba15f93b5fdde11c1f73eb9f1a79b60c6caa1c78e1c4c64ed72ce1b68747470733a2f2f6d657373616765626f782e317361742e61707046304402207adeccd157d944e41ff4502f644248c66449a9c59904e45fc8c2819db877779602207b768542821e208fdf728f3a9a2132ebd1f479fa2bb9e0f7211b1a56e64e022e6d75"
    /// `anointHost('https://messagebox.bsvblockchain.tech')`'s locking script.
    static let bsvbLock = "2102fb636d95c40760392db1e4cdcd9818504e26efe952edaf0d9eaa97c6854e0b4fac2102133b035cda4ba15f93b5fdde11c1f73eb9f1a79b60c6caa1c78e1c4c64ed72ce2568747470733a2f2f6d657373616765626f782e627376626c6f636b636861696e2e7465636846304402204919b778020771bad03aee1256200333601e9e586d80e05571587796bca4b298022021e21a2a67a6ff5d8afe33787b655878fd039837ed8250b169c442ca3356dbaf6d75"
    /// The 1Sat advertisement's own transaction: no inputs, one 1-satoshi output.
    static let sourceTxid = "dac442c772cb6fc5b2716469d319e7de00d4d885d026ba7c087f871bdc5128bb"
    /// `pushdrop.unlock(...).sign(tx, 0)` spending it in a transaction whose one output is the
    /// bsvblockchain.tech advertisement (an anoint that moves the host).
    static let anointUnlocking = "483045022100a90c957a69caee4db06dfc1dd522daa804b7fbcbcc6262b60f24f6bd82364f0602201a81d539f2b3724cbebda4d2bb0aed35c81b45ea8f93eff7db25c29e1897a1f141"
    /// The same spend in a transaction with no outputs (a revoke).
    static let revokeUnlocking = "47304402200890552f9dc279e87c1644c931a1132184e4be7d603c0f107292778dc1df7bc202207e16bfd1daf378350f3f7be34e00f2bbb7880493308423b1ee7b2537134363ab41"
}

private let oneSat = URL(string: "https://messagebox.1sat.app")!
private let bsvb = URL(string: "https://messagebox.bsvblockchain.tech")!

private func script(_ hex: String) throws -> Script { try Script(hex: hex, maximumByteCount: 10_000) }
private func rootKey() throws -> PrivateKey { try PrivateKey(Hex.decode(Vector.rootKey, maximumDecodedByteCount: 32)) }

/// A value behind a lock, for the fakes below.
private final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func read<T>(_ body: (Value) -> T) -> T { lock.lock(); defer { lock.unlock() }; return body(value) }
    func write(_ body: (inout Value) -> Void) { lock.lock(); defer { lock.unlock() }; body(&value) }
}

/// The overlay: answers `ls_messagebox` with the given outputs and records each query.
private final class AdvertisementOverlay: OverlayLookupResolving, @unchecked Sendable {
    private let outputs: [OutputListItem]
    private let recorded = Locked<[String]>([])
    init(_ outputs: [OutputListItem]) { self.outputs = outputs }
    var queries: [String] { recorded.read { $0 } }
    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer {
        XCTAssertEqual(question.service.rawValue, "ls_messagebox")
        recorded.write { $0.append(String(decoding: question.query, as: UTF8.self)) }
        return try LookupAnswer(outputList: outputs)
    }
}

private struct OverlayDown: Error {}

private struct UnavailableOverlay: OverlayLookupResolving {
    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer { throw OverlayDown() }
}

/// A wallet that funds nothing: it builds the transaction the request describes, hands it back
/// to be signed when the request spends caller inputs, and runs every unlock it is given against
/// the spent script.
private final class AdvertisingWallet: MessageBoxAdvertisingWallet, @unchecked Sendable {
    private struct State {
        var created: [WalletCreateActionRequest] = []
        var signed: [WalletSignActionRequest] = []
        var aborted: [WalletBase64Data] = []
        var pending: (transaction: Transaction, sources: BEEF?)?
    }
    let advertisementKeys: ProtoWallet
    private let basket: [WalletOutput]
    private let failsSigning: Bool
    private let state = Locked(State())

    init(keys: ProtoWallet, basket: [WalletOutput], failsSigning: Bool = false) {
        advertisementKeys = keys; self.basket = basket; self.failsSigning = failsSigning
    }

    var created: [WalletCreateActionRequest] { state.read(\.created) }
    var signed: [WalletSignActionRequest] { state.read(\.signed) }
    var aborted: [WalletBase64Data] { state.read(\.aborted) }

    func listOutputs(_ request: WalletListOutputsRequest) async throws -> WalletListOutputsResult {
        XCTAssertEqual(request.basket, "overlay advertisements")
        XCTAssertEqual(request.pagination.limit, 10_000)
        return try WalletListOutputsResult(totalOutputs: UInt32(basket.count), outputs: basket)
    }

    func createAction(_ request: WalletCreateActionRequest) async throws -> WalletCreateActionResult {
        state.write { $0.created.append(request) }
        let inputs = try (request.inputs ?? []).map {
            TransactionInput(previousOutput: $0.outpoint, unlockingScript: try Script(bytes: [], maximumByteCount: 10),
                sequence: 0xffff_ffff)
        }
        let outputs = try (request.outputs ?? []).map {
            TransactionOutput(satoshis: $0.satoshis, lockingScript: try Script(bytes: $0.lockingScript, maximumByteCount: 10_000))
        }
        let transaction = Transaction(version: 1, inputs: inputs, outputs: outputs, lockTime: 0)
        let atomic = try Self.atomic(transaction, sources: request.inputBEEF)
        guard !inputs.isEmpty else {
            return try WalletCreateActionResult(transactionID: atomic.subjectTransactionID, transaction: atomic)
        }
        state.write { $0.pending = (transaction, request.inputBEEF) }
        return try WalletCreateActionResult(signableTransaction: .init(transaction: atomic,
            reference: WalletBase64Data(base64: "cmVm")))
    }

    func signAction(_ request: WalletSignActionRequest) async throws -> WalletSignActionResult {
        state.write { $0.signed.append(request) }
        if failsSigning { throw WalletActionLifecycleError.invalidSpend }
        guard let pending = state.read(\.pending) else { throw WalletActionLifecycleError.unknownReference }
        var transaction = pending.transaction
        let configuration = try ScriptExecutionConfiguration(era: .afterGenesis, flags: [.enableForkID],
            resourceLimits: .standard)
        for index in transaction.inputs.indices {
            let previous = transaction.inputs[index].previousOutput
            let spend = try XCTUnwrap(request.spends[UInt32(index)])
            let parent = try XCTUnwrap(pending.sources?.transaction(for: previous.transactionID,
                limits: StorageLimits.transaction))
            let spent = parent.outputs[Int(previous.outputIndex)]
            transaction.inputs[index].unlockingScript = try Script(bytes: spend.unlockingScript, maximumByteCount: 10_000)
            transaction.inputs[index].sourceOutput = spent
        }
        for (index, input) in transaction.inputs.enumerated() {
            let spent = try XCTUnwrap(input.sourceOutput)
            _ = try ScriptInterpreter.execute(unlockingScript: input.unlockingScript,
                lockingScript: spent.lockingScript, configuration: configuration,
                context: ScriptExecutionContext(transaction: transaction, inputIndex: index, spentOutput: spent,
                    transactionLimits: StorageLimits.transaction))
        }
        let atomic = try Self.atomic(transaction, sources: pending.sources)
        return try WalletSignActionResult(transactionID: atomic.subjectTransactionID, transaction: atomic)
    }

    func abortAction(_ request: WalletAbortActionRequest) async throws -> WalletAbortActionResult {
        state.write { $0.aborted.append(request.reference) }
        return WalletAbortActionResult(aborted: true)
    }

    static func atomic(_ transaction: Transaction, sources: BEEF?) throws -> AtomicBEEF {
        let beef = try BEEF(merklePaths: [], transactions: (sources?.transactions ?? []) + [.raw(transaction)],
            limits: StorageLimits.beef)
        return try AtomicBEEF(subjectTransactionID: transaction.transactionID(limits: StorageLimits.transaction),
            beef: beef, limits: StorageLimits.beef)
    }
}

/// `ls_ship`: answers with a signed SHIP advertisement of `tm_messagebox` for each host, and one
/// for another topic that must be ignored.
private final class ShipOverlay: OverlayLookupResolving, @unchecked Sendable {
    private let outputs: [OutputListItem]
    private let recorded = Locked<[String]>([])
    var queries: [String] { recorded.read { $0 } }

    init(hosts: [String]) throws {
        let operator_ = try PrivateKey(Array(repeating: 0, count: 31) + [9])
        func token(_ host: String, topic: String) throws -> OutputListItem {
            let fields = [Array("SHIP".utf8), operator_.publicKey.compressedBytes, Array(host.utf8), Array(topic.utf8)]
            let signature = try operator_.sign(digest: BSVHashing.sha256(fields.flatMap { $0 }))
            let lock = try PushDrop.lockingScript(fields: fields + [signature.derBytes],
                publicKey: operator_.publicKey, lockPosition: .beforeCompatibility)
            let transaction = Transaction(version: 1, inputs: [],
                outputs: [TransactionOutput(satoshis: 1, lockingScript: lock)], lockTime: 0)
            let beef = try BEEF(merklePaths: [], transactions: [.raw(transaction)], limits: StorageLimits.beef)
            return try OutputListItem(beef: beef.serialized(limits: StorageLimits.beef), outputIndex: 0)
        }
        outputs = try hosts.map { try token($0, topic: "tm_messagebox") }
            + [try token("https://elsewhere.example", topic: "tm_other")]
    }

    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer {
        XCTAssertEqual(question.service.rawValue, "ls_ship")
        recorded.write { $0.append(String(decoding: question.query, as: UTF8.self)) }
        return try LookupAnswer(outputList: outputs)
    }
}

/// SHIP hosts answering a submission as told.
private actor SubmitFacilitator: TopicFacilitator {
    enum Answer: Sendable { case admitted, unacknowledged, empty, fails }
    private let answers: [String: Answer]
    private(set) var submitted: [String] = []
    private(set) var topics: [[String]] = []
    init(answers: [String: Answer]) throws { self.answers = answers }

    func submit(_ taggedBEEF: TaggedBEEF, to host: OverlayHost) async throws -> Steak {
        submitted.append(host.rawValue)
        topics.append(taggedBEEF.topics.map(\.rawValue))
        let topic = try OverlayTopic(rawValue: "tm_messagebox")
        switch answers[host.rawValue] ?? .fails {
        case .admitted: return try Steak(instructions: [topic: AdmittanceInstructions(outputsToAdmit: [0])])
        case .unacknowledged: return try Steak(instructions: [topic: AdmittanceInstructions()])
        case .empty: return try Steak()
        case .fails: throw OverlayDown()
        }
    }
}

/// Records what is submitted to `tm_messagebox`.
private final class Broadcasts: @unchecked Sendable {
    private let recorded = Locked<[AtomicBEEF]>([])
    var sent: [AtomicBEEF] { recorded.read { $0 } }
    func record(_ atomic: AtomicBEEF) -> MessageBoxAdvertisementBroadcast {
        recorded.write { $0.append(atomic) }
        return MessageBoxAdvertisementBroadcast(transactionID: atomic.subjectTransactionID, acceptedHosts: [],
            failedHosts: [])
    }
}

final class MessageBoxAdvertisementTests: XCTestCase, @unchecked Sendable {
    /// The TS advertisement's own transaction, as the overlay returns it.
    private func advertisementOutput(_ lockingScript: Script) throws -> (OutputListItem, Transaction) {
        let transaction = Transaction(version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: lockingScript)], lockTime: 0)
        let beef = try BEEF(merklePaths: [], transactions: [.raw(transaction)], limits: StorageLimits.beef)
        return (try OutputListItem(beef: beef.serialized(limits: StorageLimits.beef), outputIndex: 0), transaction)
    }

    private func advertiser(_ overlay: any OverlayLookupResolving, _ broadcasts: Broadcasts) -> MessageBoxAdvertiser {
        MessageBoxAdvertiser(resolver: overlay) { broadcasts.record($0) }
    }

    func test_lockingScriptMatchesTypeScriptAnointHost() async throws {
        let wallet = ProtoWallet(rootKey: try rootKey())
        XCTAssertEqual(Hex.encode(try rootKey().publicKey.compressedBytes), Vector.identityKey)
        let oneSatScript = try await MessageBoxAdvertiser.lockingScript(host: oneSat, wallet: wallet)
        XCTAssertEqual(Hex.encode(oneSatScript.bytes), Vector.oneSatLock)
        let bsvbScript = try await MessageBoxAdvertiser.lockingScript(host: bsvb, wallet: wallet)
        XCTAssertEqual(Hex.encode(bsvbScript.bytes), Vector.bsvbLock)
        // TS `normalizeMessageBoxHost` writes the origin and path without trailing slashes.
        let spelled = try await MessageBoxAdvertiser.lockingScript(host: URL(string: "https://MessageBox.1sat.app:443/")!,
            wallet: wallet)
        XCTAssertEqual(Hex.encode(spelled.bytes), Vector.oneSatLock)
    }

    func test_advertisedTextNormalizesAndRefusesHostsTheOverlayWouldDrop() {
        XCTAssertEqual(MessageBoxAdvertiser.advertisedText(URL(string: "https://Box.Example.org/api//")!),
            "https://box.example.org/api")
        XCTAssertEqual(MessageBoxAdvertiser.advertisedText(URL(string: "https://box.example.org:8443")!),
            "https://box.example.org:8443")
        for text in ["http://box.example.org", "https://localhost", "https://10.0.0.1", "https://box.test"] {
            XCTAssertNil(MessageBoxAdvertiser.advertisedText(URL(string: text)!), text)
        }
    }

    func test_lookupReturnsOnlySignedAdvertisementsOfTheIdentity() async throws {
        let identity = try rootKey().publicKey
        let (signed, signedTransaction) = try advertisementOutput(script(Vector.oneSatLock))
        let other = try PrivateKey(Array(repeating: 0, count: 31) + [7])
        let otherScript = try await MessageBoxAdvertiser.lockingScript(host: bsvb, wallet: ProtoWallet(rootKey: other))
        let (foreign, _) = try advertisementOutput(otherScript)
        // The two-field form, with no signature, and a signature over another host.
        let (unsigned, _) = try advertisementOutput(PushDrop.lockingScript(
            fields: [identity.compressedBytes, Array(bsvb.absoluteString.utf8)], publicKey: identity,
            lockPosition: .beforeCompatibility))
        let decoded = try PushDrop.decode(script(Vector.oneSatLock), lockPosition: .beforeCompatibility)
        let (forged, _) = try advertisementOutput(PushDrop.lockingScript(
            fields: [identity.compressedBytes, Array(bsvb.absoluteString.utf8), decoded.fields[2]],
            publicKey: decoded.publicKey, lockPosition: .beforeCompatibility))

        let overlay = AdvertisementOverlay([foreign, unsigned, forged, signed, signed])
        let found = try await advertiser(overlay, Broadcasts()).advertisements(of: identity)
        XCTAssertEqual(found.count, 1)
        XCTAssertEqual(found.first?.host, oneSat)
        XCTAssertTrue(found.first?.names(URL(string: "https://messagebox.1sat.app/")!) == true)
        XCTAssertEqual(found.first?.outpoint, Outpoint(transactionID: try TransactionID(displayHex: Vector.sourceTxid),
            outputIndex: 0))
        XCTAssertEqual(try signedTransaction.transactionID(limits: StorageLimits.transaction).displayHex, Vector.sourceTxid)
        XCTAssertEqual(overlay.queries, [#"{"identityKey":"\#(Vector.identityKey)"}"#])

        _ = try await advertiser(overlay, Broadcasts()).advertisements(of: identity, host: oneSat)
        XCTAssertEqual(overlay.queries.last, #"{"host":"https://messagebox.1sat.app","identityKey":"\#(Vector.identityKey)"}"#)
    }

    func test_lookupFailureThrowsRatherThanReportingNoAdvertisement() async throws {
        do {
            _ = try await advertiser(UnavailableOverlay(), Broadcasts()).advertisements(of: rootKey().publicKey)
            XCTFail("expected the lookup failure")
        } catch is OverlayDown {}
    }

    func test_anointSpendsTheSpendableAdvertisementAsTypeScriptDoes() async throws {
        let (listed, _) = try advertisementOutput(script(Vector.oneSatLock))
        let outpoint = Outpoint(transactionID: try TransactionID(displayHex: Vector.sourceTxid), outputIndex: 0)
        let wallet = AdvertisingWallet(keys: ProtoWallet(rootKey: try rootKey()),
            basket: [try WalletOutput(satoshis: 1, spendable: true, outpoint: outpoint)])
        let broadcasts = Broadcasts()
        let txid = try await advertiser(AdvertisementOverlay([listed]), broadcasts).anoint(bsvb, using: wallet)

        let request = try XCTUnwrap(wallet.created.first)
        XCTAssertEqual(wallet.created.count, 1)
        XCTAssertEqual(request.description, "Anoint host for overlay routing")
        let input = try XCTUnwrap(request.inputs?.first)
        XCTAssertEqual(request.inputs?.count, 1)
        XCTAssertEqual(input.outpoint, outpoint)
        XCTAssertEqual(input.inputDescription, "Revoking advertisement for https://messagebox.1sat.app")
        guard case .scriptLength(73) = input.unlocking else { return XCTFail("expected a 73-byte unlock reservation") }
        XCTAssertNotNil(try request.inputBEEF?.transaction(for: outpoint.transactionID, limits: StorageLimits.transaction))
        let output = try XCTUnwrap(request.outputs?.first)
        XCTAssertEqual(request.outputs?.count, 1)
        XCTAssertEqual(Hex.encode(output.lockingScript), Vector.bsvbLock)
        XCTAssertEqual(output.satoshis, 1)
        XCTAssertEqual(output.basket, "overlay advertisements")
        XCTAssertEqual(output.outputDescription, "Overlay advertisement output")
        XCTAssertEqual(request.options?.randomizeOutputs, false)
        XCTAssertEqual(request.options?.acceptDelayedBroadcast, false)

        let sign = try XCTUnwrap(wallet.signed.first)
        XCTAssertEqual(sign.spends.count, 1)
        XCTAssertEqual(Hex.encode(try XCTUnwrap(sign.spends[0]).unlockingScript), Vector.anointUnlocking)
        XCTAssertEqual(sign.options?.acceptDelayedBroadcast, false)

        XCTAssertEqual(broadcasts.sent.count, 1)
        XCTAssertEqual(broadcasts.sent.first?.subjectTransactionID, txid.transactionID)
    }

    func test_anointLeavesAnAdvertisementTheWalletCannotSpendAndBroadcastsDirectly() async throws {
        let (listed, _) = try advertisementOutput(script(Vector.oneSatLock))
        let outpoint = Outpoint(transactionID: try TransactionID(displayHex: Vector.sourceTxid), outputIndex: 0)
        let wallet = AdvertisingWallet(keys: ProtoWallet(rootKey: try rootKey()),
            basket: [try WalletOutput(satoshis: 1, spendable: false, outpoint: outpoint)])
        let broadcasts = Broadcasts()
        let txid = try await advertiser(AdvertisementOverlay([listed]), broadcasts).anoint(oneSat, using: wallet)

        let request = try XCTUnwrap(wallet.created.first)
        XCTAssertNil(request.inputs)
        XCTAssertNil(request.inputBEEF)
        XCTAssertEqual(request.outputs.map { $0.map { Hex.encode($0.lockingScript) } }, [Vector.oneSatLock])
        XCTAssertTrue(wallet.signed.isEmpty)
        XCTAssertEqual(broadcasts.sent.map(\.subjectTransactionID), [txid.transactionID])
    }

    func test_anointRefusesWhenTheLookupFailsOrTheHostIsNotPublic() async throws {
        let wallet = AdvertisingWallet(keys: ProtoWallet(rootKey: try rootKey()), basket: [])
        let broadcasts = Broadcasts()
        do {
            _ = try await advertiser(UnavailableOverlay(), broadcasts).anoint(oneSat, using: wallet)
            XCTFail("expected the lookup failure")
        } catch is OverlayDown {}
        do {
            _ = try await advertiser(AdvertisementOverlay([]), broadcasts)
                .anoint(URL(string: "https://localhost")!, using: wallet)
            XCTFail("expected invalidHost")
        } catch MessageBoxAdvertisementError.invalidHost {}
        XCTAssertTrue(wallet.created.isEmpty)
        XCTAssertTrue(broadcasts.sent.isEmpty)
    }

    func test_revokeSpendsTheAdvertisementAsTypeScriptDoes() async throws {
        let (listed, _) = try advertisementOutput(script(Vector.oneSatLock))
        let identity = try rootKey().publicKey
        let broadcasts = Broadcasts()
        let subject = advertiser(AdvertisementOverlay([listed]), broadcasts)
        let listedAdvertisements = try await subject.advertisements(of: identity)
        let advertisement = try XCTUnwrap(listedAdvertisements.first)
        let wallet = AdvertisingWallet(keys: ProtoWallet(rootKey: try rootKey()), basket: [])
        let txid = try await subject.revoke(advertisement, using: wallet)

        let request = try XCTUnwrap(wallet.created.first)
        XCTAssertEqual(request.description, "Revoke MessageBox host advertisement")
        XCTAssertNil(request.outputs)
        XCTAssertNil(request.options)
        let input = try XCTUnwrap(request.inputs?.first)
        XCTAssertEqual(input.outpoint, advertisement.outpoint)
        XCTAssertEqual(input.inputDescription, "Revoking host advertisement token")
        guard case .scriptLength(73) = input.unlocking else { return XCTFail("expected a 73-byte unlock reservation") }
        let sign = try XCTUnwrap(wallet.signed.first)
        XCTAssertEqual(Hex.encode(try XCTUnwrap(sign.spends[0]).unlockingScript), Vector.revokeUnlocking)
        XCTAssertEqual(sign.options?.acceptDelayedBroadcast, false)
        XCTAssertEqual(broadcasts.sent.map(\.subjectTransactionID), [txid.transactionID])
    }

    func test_aFailedSigningAbortsTheAction() async throws {
        let (listed, _) = try advertisementOutput(script(Vector.oneSatLock))
        let outpoint = Outpoint(transactionID: try TransactionID(displayHex: Vector.sourceTxid), outputIndex: 0)
        let wallet = AdvertisingWallet(keys: ProtoWallet(rootKey: try rootKey()),
            basket: [try WalletOutput(satoshis: 1, spendable: true, outpoint: outpoint)], failsSigning: true)
        let broadcasts = Broadcasts()
        do {
            _ = try await advertiser(AdvertisementOverlay([listed]), broadcasts).anoint(bsvb, using: wallet)
            XCTFail("expected the signing failure")
        } catch WalletActionLifecycleError.invalidSpend {}
        XCTAssertEqual(wallet.aborted, [try WalletBase64Data(base64: "cmVm")])
        XCTAssertTrue(broadcasts.sent.isEmpty)
    }

    /// As TS `TopicBroadcaster`: every SHIP host advertising `tm_messagebox` is sent the
    /// transaction; one that fails, or answers with no instructions, is dropped and reported, and
    /// one host admitting it is enough.
    func test_submitSucceedsWhenOneHostAdmitsAndReportsTheOthers() async throws {
        let ship = try ShipOverlay(hosts: ["https://a.example", "https://b.example", "https://c.example"])
        let facilitator = try SubmitFacilitator(answers: [
            "https://a.example": .admitted, "https://b.example": .fails, "https://c.example": .empty,
        ])
        let atomic = try AdvertisingWallet.atomic(Transaction(version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: script(Vector.oneSatLock))], lockTime: 0),
            sources: nil)
        let result = try await MessageBoxAdvertiser.submit(atomic, resolver: ship, facilitator: facilitator)
        XCTAssertEqual(result.transactionID, atomic.subjectTransactionID)
        XCTAssertEqual(result.acceptedHosts.map(\.rawValue), ["https://a.example"])
        XCTAssertEqual(result.failedHosts.map(\.rawValue), ["https://b.example", "https://c.example"])
        XCTAssertEqual(ship.queries, [#"{"topics":["tm_messagebox"]}"#])
        let submitted = await facilitator.submitted
        XCTAssertEqual(submitted.sorted(), ["https://a.example", "https://b.example", "https://c.example"])
        let topics = await facilitator.topics
        XCTAssertTrue(topics.allSatisfy { $0 == ["tm_messagebox"] })
    }

    func test_submitFailsOnlyWhenNoHostAdmits() async throws {
        let atomic = try AdvertisingWallet.atomic(Transaction(version: 1, inputs: [],
            outputs: [TransactionOutput(satoshis: 1, lockingScript: script(Vector.oneSatLock))], lockTime: 0),
            sources: nil)
        let ship = try ShipOverlay(hosts: ["https://a.example", "https://b.example"])
        let cases: [([String: SubmitFacilitator.Answer], MessageBoxAdvertisementError)] = [
            (["https://a.example": .fails, "https://b.example": .empty], .allHostsRejected),
            (["https://a.example": .unacknowledged, "https://b.example": .fails], .notAcknowledged),
        ]
        for (answers, expected) in cases {
            do {
                _ = try await MessageBoxAdvertiser.submit(atomic, resolver: ship,
                    facilitator: SubmitFacilitator(answers: answers))
                XCTFail("expected \(expected)")
            } catch let error as MessageBoxAdvertisementError {
                XCTAssertEqual(error, expected)
            }
        }
        do {
            _ = try await MessageBoxAdvertiser.submit(atomic, resolver: ShipOverlay(hosts: []),
                facilitator: SubmitFacilitator(answers: [:]))
            XCTFail("expected noInterestedHosts")
        } catch MessageBoxAdvertisementError.noInterestedHosts {}
    }

    func test_networkPresetsBuild() {
        XCTAssertNoThrow(try MessageBoxAdvertiser())
        XCTAssertNoThrow(try MessageBoxAdvertiser(network: .testnet))
    }
}
