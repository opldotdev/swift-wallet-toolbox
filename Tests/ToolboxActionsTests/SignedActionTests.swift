import XCTest
import BSVKeys
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

    /// The proof graph storage returns, holding the source transaction.
    private func inputBEEF() throws -> [UInt8] {
        try BEEF(
            merklePaths: [], transactions: [.raw(try sourceTransaction())],
            limits: WalletBEEFLimits.standard
        ).serialized(limits: WalletBEEFLimits.standard)
    }

    /// A funded action with its proof graph, signed.
    private func signed(reference: String = "ref") throws -> SignedAction {
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
            inputBEEF: try inputBEEF(), derivationPrefix: prefix
        )
        let transaction = try ActionSigner.sign(
            funded, requested: requested, identityKey: identity, senderPublicKey: sender,
            maximumFee: 1_000_000
        )
        return try SignedAction(funded: funded, transaction: transaction)
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
}
