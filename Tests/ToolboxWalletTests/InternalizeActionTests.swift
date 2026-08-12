import XCTest
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxActions
import ToolboxBRC29
import ToolboxStorage
import ToolboxStorageClient
@testable import ToolboxWallet

/// The receive side of BRC-29: claiming an incoming output only when the wallet can prove it owns it.
///
/// Both rejections happen before storage is ever called, so they run without a live server. The
/// accept path forwards to storage and is exercised by the live storage tests.
final class InternalizeActionTests: XCTestCase {

    private func key(_ b: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [b])
    }

    private func wallet(root: PrivateKey) throws -> RemoteWallet {
        let identity = root.publicKey.compressedBytes.map { String(format: "%02x", $0) }.joined()
        // The endpoint is never reached: every case here is refused before storage is called.
        let storage = try RemoteStorage.client(
            at: XCTUnwrap(URL(string: "https://storage.invalid")),
            wallet: ProtoWallet(rootKey: root)
        )
        return RemoteWallet(storage: storage, identityKey: root, auth: AuthID(identityKey: identity))
    }

    /// A subject transaction with one output carrying `script`, wrapped as Atomic BEEF.
    private func atomicBEEF(outputScript script: [UInt8]) throws -> AtomicBEEF {
        let output = TransactionOutput(
            satoshis: 1_000,
            lockingScript: try Script(bytes: script, maximumByteCount: 1_000)
        )
        let tx = Transaction(version: 1, inputs: [], outputs: [output], lockTime: 0)
        let beef = try BEEF(
            merklePaths: [], transactions: [.raw(tx)], limits: WalletBEEFLimits.standard
        )
        let id = try tx.transactionID(limits: WalletTransactionLimits.standard)
        return try AtomicBEEF(subjectTransactionID: id, beef: beef, limits: WalletBEEFLimits.standard)
    }

    private func request(
        beef: AtomicBEEF, outputIndex: UInt32, sender: PublicKey
    ) throws -> WalletInternalizeActionRequest {
        let remittance = try WalletPaymentRemittance(
            derivationPrefix: try WalletBase64Data(base64: "cHJlZml4"),
            derivationSuffix: try WalletBase64Data(base64: "c3VmZml4"),
            senderIdentityKey: sender
        )
        let output = try WalletInternalizeOutput(
            outputIndex: outputIndex, protocol: .walletPayment, paymentRemittance: remittance
        )
        return try WalletInternalizeActionRequest(
            transaction: beef, description: "incoming", outputs: [output]
        )
    }

    func test_rejectsAnOutputThatIsNotThisWalletsBRC29Payment() async throws {
        let root = try key(1)
        let sender = try key(2).publicKey
        // A P2PKH to an unrelated key hash, not the one this wallet derives for that sender.
        let bogus: [UInt8] = [0x76, 0xa9, 0x14] + [UInt8](repeating: 0x11, count: 20) + [0x88, 0xac]
        let req = try request(beef: try atomicBEEF(outputScript: bogus), outputIndex: 0, sender: sender)

        do {
            _ = try await wallet(root: root).internalizeAction(req)
            XCTFail("an output this wallet cannot spend must be refused")
        } catch let error as WalletError {
            XCTAssertEqual(error, .outputIsNotBRC29Payment(outputIndex: 0))
        }
    }

    func test_acceptsTheScriptItActuallyDerives() async throws {
        // The positive control: with the correctly derived script the ownership check passes, so the
        // only thing left to fail is the (unreachable) storage call — never `outputIsNotBRC29Payment`.
        let root = try key(1)
        let sender = try key(2)
        let derived = try BRC29.receivingPrivateKey(
            recipient: root, sender: sender.publicKey, prefix: "cHJlZml4", suffix: "c3VmZml4"
        )
        let script = try BRC29.lockingScript(for: derived.publicKey).bytes
        let req = try request(
            beef: try atomicBEEF(outputScript: script), outputIndex: 0, sender: sender.publicKey
        )

        do {
            _ = try await wallet(root: root).internalizeAction(req)
        } catch let error as WalletError {
            XCTFail("the derived script must pass the ownership check, got \(error)")
        } catch {
            // A storage/transport error is expected: the endpoint is unreachable. The point is that
            // the ownership check did not reject it.
        }
    }

    func test_rejectsAnOutputIndexOutOfRange() async throws {
        let root = try key(1)
        let sender = try key(2).publicKey
        let req = try request(beef: try atomicBEEF(outputScript: [0x51]), outputIndex: 5, sender: sender)

        do {
            _ = try await wallet(root: root).internalizeAction(req)
            XCTFail("an out-of-range output index must be refused")
        } catch let error as WalletError {
            XCTAssertEqual(error, .internalizeOutputOutOfRange(outputIndex: 5))
        }
    }
}
