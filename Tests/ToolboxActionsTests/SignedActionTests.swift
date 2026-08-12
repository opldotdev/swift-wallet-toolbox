import XCTest
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage
@testable import ToolboxActions

/// Packaging a signed transaction for storage to broadcast.
final class SignedActionTests: XCTestCase {

    private let prefix = "Pr=="
    private let suffix = "Su=="

    private func key(_ byte: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [byte])
    }

    /// The transaction our payment spends from, locked to the BRC-29 key.
    private func sourceTransaction() throws -> Transaction {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let spending = try BRC29.receivingPrivateKey(
            recipient: identity, sender: sender, prefix: prefix, suffix: suffix
        )
        return Transaction(
            version: 1,
            inputs: [],
            outputs: [
                TransactionOutput(
                    satoshis: 5_000,
                    lockingScript: try BRC29.lockingScript(for: spending.publicKey)
                )
            ],
            lockTime: 0
        )
    }

    /// A real signed transaction, built the way the signer builds one.
    private func signedTransaction() throws -> Transaction {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let spending = try BRC29.receivingPrivateKey(
            recipient: identity, sender: sender, prefix: prefix, suffix: suffix
        )
        let script = try BRC29.lockingScript(for: spending.publicKey)
        let source = try sourceTransaction()
        let sourceID = try source.transactionID(limits: WalletTransactionLimits.standard)
        let requested = [
            try WalletCreateActionOutput(
                lockingScript: [0x76, 0xa9], satoshis: 1_000, outputDescription: "payment"
            )
        ]
        let action = StorageCreateActionResult(
            reference: "ref", version: 1, lockTime: 0, outputs: requested,
            inputs: [
                StorageActionInput(
                    sourceTXID: sourceID.displayHex,
                    sourceVout: 0, sourceSatoshis: 5_000,
                    sourceLockingScript: script.bytes, unlockingScriptLength: 108,
                    derivationPrefix: prefix, derivationSuffix: suffix
                )
            ],
            inputBEEF: nil, derivationPrefix: prefix
        )
        return try ActionSigner.sign(
            action, requested: requested, identityKey: identity, senderPublicKey: sender
        )
    }

    func test_aSignedActionKnowsItsTransactionID() throws {
        let action = try SignedAction(reference: "ref", transaction: try signedTransaction())

        XCTAssertFalse(action.transactionID.displayHex.isEmpty)
        XCTAssertEqual(action.reference, "ref")
    }

    /// Storage matches a signed transaction to the inputs it reserved by reference. Losing it
    /// would leave those inputs reserved and the transaction unattributable.
    func test_theReferenceTravelsWithTheRequest() throws {
        let action = try SignedAction(reference: "abc123", transaction: try signedTransaction())

        XCTAssertEqual(action.processRequest().reference, "abc123")
        XCTAssertTrue(action.processRequest().isNewTx)
        XCTAssertFalse(action.processRequest().isSendWith)
    }

    func test_sendWithMarksTheRequestAsABatch() throws {
        let action = try SignedAction(reference: "r", transaction: try signedTransaction())

        let request = action.processRequest(sendWith: ["aa", "bb"])

        XCTAssertTrue(request.isSendWith)
        XCTAssertEqual(request.sendWith, ["aa", "bb"])
    }

    // MARK: - The envelope

    /// BRC-95 names the subject transaction in a prefix, so a reader knows which of the
    /// transactions inside is the one being presented.
    func test_theEnvelopeIsAtomicBEEF() throws {
        let action = try SignedAction(reference: "r", transaction: try signedTransaction())

        let envelope = try action.atomicBEEF(sourceTransactions: [try sourceTransaction()])

        XCTAssertEqual(
            Array(envelope.prefix(4)), [0x01, 0x01, 0x01, 0x01],
            "the BRC-95 atomic prefix"
        )
    }

    /// The envelope must round-trip through the SDK's own reader, and name our transaction as its
    /// subject. Producing bytes nobody can read back would fail only at the far end.
    func test_theEnvelopeReadsBackNamingOurTransaction() throws {
        let transaction = try signedTransaction()
        let action = try SignedAction(reference: "r", transaction: transaction)

        let envelope = try action.atomicBEEF(sourceTransactions: [try sourceTransaction()])
        let parsed = try AtomicBEEF(bytes: envelope, limits: WalletBEEFLimits.standard)

        XCTAssertEqual(parsed.subjectTransactionID, action.transactionID)
    }

    /// A verifier cannot check an input it cannot see, so supplied source transactions travel
    /// inside the envelope alongside the subject.
    func test_sourceTransactionsAreCarried() throws {
        let transaction = try signedTransaction()
        let action = try SignedAction(reference: "r", transaction: transaction)
        let envelope = try action.atomicBEEF(sourceTransactions: [try sourceTransaction()])
        let parsed = try AtomicBEEF(bytes: envelope, limits: WalletBEEFLimits.standard)

        XCTAssertEqual(parsed.beef.transactions.count, 2)
        XCTAssertEqual(parsed.subjectTransactionID, action.transactionID)
    }
}
