import XCTest
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage
@testable import ToolboxActions

/// Packaging a signed transaction for storage to broadcast.
///
/// The action is built the way a real one is: storage funds it and returns the ancestor graph as
/// `inputBEEF`, the signer signs, and `SignedAction` turns the pair into the Atomic BEEF storage
/// finalises. The graph is required — an envelope missing an ancestor is invalid — so these tests
/// carry a real one rather than an empty placeholder.
final class SignedActionTests: XCTestCase {

    private let prefix = "Pr=="
    private let suffix = "Su=="

    private func key(_ byte: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [byte])
    }

    /// The transaction our payment spends from, locked to the BRC-29 key.
    private func sourceTransaction(parent: TransactionID? = nil) throws -> Transaction {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let spending = try BRC29.receivingPrivateKey(
            recipient: identity, sender: sender, prefix: prefix, suffix: suffix
        )
        return Transaction(
            version: 1,
            inputs: try parent.map {
                [TransactionInput(
                    previousOutput: Outpoint(transactionID: $0, outputIndex: 0),
                    unlockingScript: try Script(bytes: [], maximumByteCount: 0)
                )]
            } ?? [],
            outputs: [
                TransactionOutput(
                    satoshis: 5_000,
                    lockingScript: try BRC29.lockingScript(for: spending.publicKey)
                )
            ],
            lockTime: 0
        )
    }

    /// The proof graph storage returns, holding the source transaction.
    private func serialized(_ beef: BEEF) throws -> [UInt8] {
        try beef.serialized(limits: WalletBEEFLimits.standard)
    }

    private func parts(
        source: Transaction,
        inputBEEF: [UInt8]?,
        reference: String = "ref"
    ) throws -> (funded: StorageCreateActionResult, transaction: Transaction) {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let spending = try BRC29.receivingPrivateKey(
            recipient: identity, sender: sender, prefix: prefix, suffix: suffix
        )
        let script = try BRC29.lockingScript(for: spending.publicKey)
        let sourceID = try source.transactionID(limits: WalletTransactionLimits.standard)
        let requested = [
            try WalletCreateActionOutput(
                lockingScript: [0x76, 0xa9], satoshis: 1_000, outputDescription: "payment"
            )
        ]
        let funded = StorageCreateActionResult(
            reference: reference, version: 1, lockTime: 0,
            outputs: [
                StorageActionOutput(
                    vout: 0, satoshis: 1_000, lockingScript: [0x76, 0xa9],
                    providedBy: .you, purpose: nil, derivationSuffix: nil
                )
            ],
            inputs: [
                StorageActionInput(
                    sourceTXID: sourceID.displayHex, sourceVout: 0, sourceSatoshis: 5_000,
                    sourceLockingScript: script.bytes, unlockingScriptLength: 108,
                    derivationPrefix: prefix, derivationSuffix: suffix
                )
            ],
            inputBEEF: inputBEEF, derivationPrefix: prefix
        )
        let transaction = try ActionSigner.sign(
            funded, requested: requested, identityKey: identity, senderPublicKey: sender,
            maximumFee: 1_000_000
        )
        return (funded, transaction)
    }

    /// A funded action with its proof graph, signed.
    private func signed(reference: String = "ref") throws -> SignedAction {
        let source = try sourceTransaction()
        let graph = try BEEF(
            merklePaths: [], transactions: [.raw(source)],
            limits: WalletBEEFLimits.standard
        )
        let value = try parts(
            source: source,
            inputBEEF: try serialized(graph),
            reference: reference
        )
        return try SignedAction(funded: value.funded, transaction: value.transaction)
    }

    func test_aSignedActionKnowsItsTransactionID() throws {
        let action = try signed()

        XCTAssertFalse(action.transactionID.displayHex.isEmpty)
        XCTAssertEqual(action.reference, "ref")
    }

    // MARK: - Finalization

    /// The finding this fixes: storage cannot commit or broadcast without the signed transaction,
    /// and its inputs stay reserved. The request must carry it as Atomic BEEF.
    func test_theRequestCarriesTheSignedTransaction() throws {
        let request = try signed(reference: "abc123").processRequest()

        XCTAssertEqual(request.reference, "abc123")
        XCTAssertTrue(request.isNewTx)
        XCTAssertNotNil(request.rawTX)
        XCTAssertEqual(Array(request.rawTX!.prefix(4)), [0x01, 0x01, 0x01, 0x01])
    }

    func test_sendWithMarksTheRequestAsABatch() throws {
        let request = try signed().processRequest(sendWith: ["aa", "bb"])

        XCTAssertTrue(request.isSendWith)
        XCTAssertEqual(request.sendWith, ["aa", "bb"])
    }

    // MARK: - The envelope

    /// The envelope round-trips through the SDK's own reader and names our transaction as its
    /// subject, carrying the ancestor from the funded graph.
    func test_theEnvelopeReadsBackNamingOurTransaction() throws {
        let action = try signed()

        let envelope = try action.atomicBEEF()
        let parsed = try AtomicBEEF(bytes: envelope, limits: WalletBEEFLimits.standard)

        XCTAssertEqual(parsed.subjectTransactionID, action.transactionID)
        XCTAssertEqual(parsed.beef.transactions.count, 2, "the ancestor and the subject")
    }

    func test_preservesTheFundedBEEFVersionAndBUMP() throws {
        let source = try sourceTransaction()
        let sourceID = try source.transactionID(limits: WalletTransactionLimits.standard)
        let path = try MerklePath(
            blockHeight: 900_001,
            levels: [[.hash(
                offset: 0,
                hash: try Hash256(sourceID.wireBytes),
                isTransactionID: true
            )]]
        )
        let graph = try BEEF(
            version: .v1,
            merklePaths: [path],
            transactions: [.rawWithMerklePath(transaction: source, merklePathIndex: 0)],
            limits: WalletBEEFLimits.standard
        )
        let value = try parts(source: source, inputBEEF: try serialized(graph))

        let action = try SignedAction(funded: value.funded, transaction: value.transaction)
        let parsed = try AtomicBEEF(
            bytes: action.atomicBEEF(), limits: WalletBEEFLimits.standard
        )

        XCTAssertEqual(parsed.beef.version, .v1)
        XCTAssertEqual(parsed.beef.merklePaths, [path])
        XCTAssertEqual(
            parsed.beef.transactions.first,
            .rawWithMerklePath(transaction: source, merklePathIndex: 0)
        )
    }

    func test_preservesCompleteUnprovenAncestry() throws {
        let ancestor = Transaction(outputs: [TransactionOutput(
            satoshis: 6_000,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )])
        let ancestorID = try ancestor.transactionID(limits: WalletTransactionLimits.standard)
        let source = try sourceTransaction(parent: ancestorID)
        let graph = try BEEF(
            merklePaths: [],
            transactions: [.raw(ancestor), .raw(source)],
            limits: WalletBEEFLimits.standard
        )
        let value = try parts(source: source, inputBEEF: try serialized(graph))

        let action = try SignedAction(funded: value.funded, transaction: value.transaction)
        let parsed = try AtomicBEEF(
            bytes: action.atomicBEEF(), limits: WalletBEEFLimits.standard
        )

        XCTAssertEqual(parsed.beef.transactions.count, 3)
        XCTAssertEqual(parsed.beef.transactions[0], .raw(ancestor))
        XCTAssertEqual(parsed.beef.transactions[1], .raw(source))
        XCTAssertEqual(parsed.beef.transactions[2], .raw(value.transaction))
    }

    func test_rejectsAnUnrelatedFundedTransaction() throws {
        let source = try sourceTransaction()
        let unrelated = Transaction(outputs: [TransactionOutput(
            satoshis: 1,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )])
        let unrelatedID = try unrelated.transactionID(limits: WalletTransactionLimits.standard)
        let graph = try BEEF(
            merklePaths: [],
            transactions: [.raw(source), .raw(unrelated)],
            limits: WalletBEEFLimits.standard
        )
        let value = try parts(source: source, inputBEEF: try serialized(graph))

        XCTAssertThrowsError(
            try SignedAction(funded: value.funded, transaction: value.transaction)
        ) { error in
            XCTAssertEqual(error as? BEEFError, .unrelatedTransaction(unrelatedID))
        }
    }

    func test_rejectsAMissingFundedAncestor() throws {
        let source = try sourceTransaction()
        let sourceID = try source.transactionID(limits: WalletTransactionLimits.standard)
        let value = try parts(source: source, inputBEEF: nil)
        let subjectID = try value.transaction.transactionID(
            limits: WalletTransactionLimits.standard
        )

        XCTAssertThrowsError(
            try SignedAction(funded: value.funded, transaction: value.transaction)
        ) { error in
            XCTAssertEqual(
                error as? BEEFError,
                .missingAncestor(transaction: subjectID, ancestor: sourceID)
            )
        }
    }

    func test_rejectsAProofGraphThatCollidesWithTheSubject() throws {
        let source = try sourceTransaction()
        let valid = try BEEF(
            merklePaths: [], transactions: [.raw(source)],
            limits: WalletBEEFLimits.standard
        )
        let value = try parts(source: source, inputBEEF: try serialized(valid))
        let subjectID = try value.transaction.transactionID(
            limits: WalletTransactionLimits.standard
        )
        let collision = try BEEF(
            version: .v2,
            merklePaths: [],
            transactions: [.raw(source), .transactionID(subjectID)],
            limits: WalletBEEFLimits.standard
        )
        let funded = StorageCreateActionResult(
            reference: value.funded.reference,
            version: value.funded.version,
            lockTime: value.funded.lockTime,
            outputs: value.funded.outputs,
            inputs: value.funded.inputs,
            inputBEEF: try serialized(collision),
            derivationPrefix: value.funded.derivationPrefix
        )

        XCTAssertThrowsError(try SignedAction(funded: funded, transaction: value.transaction)) {
            error in
            XCTAssertEqual(error as? BEEFError, .duplicateTransactionID(subjectID))
        }
    }

    func test_rejectsConflictingBUMPsForOneBlockHeight() throws {
        let source = try sourceTransaction()
        let sourceID = try source.transactionID(limits: WalletTransactionLimits.standard)
        let sourceHash = try Hash256(sourceID.wireBytes)
        let singleton = try MerklePath(
            blockHeight: 900_002,
            levels: [[.hash(offset: 0, hash: sourceHash, isTransactionID: true)]]
        )
        let conflicting = try MerklePath(
            blockHeight: 900_002,
            levels: [[
                .hash(offset: 0, hash: sourceHash, isTransactionID: true),
                .hash(
                    offset: 1,
                    hash: try Hash256([UInt8](repeating: 0xa5, count: 32)),
                    isTransactionID: false
                ),
            ]]
        )
        let graph = try BEEF(
            merklePaths: [singleton, conflicting],
            transactions: [.rawWithMerklePath(transaction: source, merklePathIndex: 0)],
            limits: WalletBEEFLimits.standard
        )
        let value = try parts(source: source, inputBEEF: try serialized(graph))

        XCTAssertThrowsError(
            try SignedAction(funded: value.funded, transaction: value.transaction)
        ) { error in
            XCTAssertEqual(error as? BEEFError, .conflictingMerkleRoot(blockHeight: 900_002))
        }
    }

    func test_allowsAStandaloneSubjectWithoutFundedInputs() throws {
        let transaction = Transaction(outputs: [TransactionOutput(
            satoshis: 0,
            lockingScript: try Script.falseReturn(
                [], maximumByteCount: 1_000, maximumPartByteCount: 1_000
            )
        )])
        let funded = StorageCreateActionResult(
            reference: "standalone",
            version: 1,
            lockTime: 0,
            outputs: [],
            inputs: [],
            inputBEEF: nil,
            derivationPrefix: nil
        )

        let action = try SignedAction(funded: funded, transaction: transaction)
        let parsed = try AtomicBEEF(
            bytes: action.atomicBEEF(), limits: WalletBEEFLimits.standard
        )

        XCTAssertEqual(parsed.beef.transactions, [BEEFTransaction.raw(transaction)])
    }
}
