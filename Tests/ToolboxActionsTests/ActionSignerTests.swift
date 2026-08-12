import XCTest
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage
@testable import ToolboxActions

/// Signing the inputs a funded action spends.
///
/// The inputs here are built the way a real one is: a BRC-29 key is derived, an output is locked
/// to it, and the signer must rediscover that key from the prefix and suffix alone. A test that
/// locked the output to a key it handed the signer directly would pass without the derivation
/// being right, which is the only part that can go wrong quietly.
final class ActionSignerTests: XCTestCase {

    private let sourceTXID =
        "8ac7230489e80000000000000000000000000000000000000000000000000001"
    private let prefix = "Pr=="
    private let suffix = "Su=="

    private func key(_ byte: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [byte])
    }

    private func output(satoshis: UInt64) throws -> WalletCreateActionOutput {
        try WalletCreateActionOutput(
            lockingScript: [0x76, 0xa9], satoshis: satoshis, outputDescription: "payment"
        )
    }

    /// An input locked to the BRC-29 key that `prefix` and `suffix` really produce.
    private func brc29Input(
        identity: PrivateKey, sender: PublicKey, satoshis: Int64 = 5_000,
        suffix inputSuffix: String? = nil
    ) throws -> StorageActionInput {
        // The script is locked with the same suffix the input records. Locking with one and
        // recording another is exactly the mismatch the signer refuses, and it is not what this
        // helper is for.
        let usedSuffix = inputSuffix ?? suffix
        let spending = try BRC29.receivingPrivateKey(
            recipient: identity, sender: sender, prefix: prefix, suffix: usedSuffix
        )
        let script = try BRC29.lockingScript(for: spending.publicKey)
        return StorageActionInput(
            sourceTXID: sourceTXID, sourceVout: 0, sourceSatoshis: satoshis,
            sourceLockingScript: script.bytes, unlockingScriptLength: 108,
            derivationPrefix: prefix, derivationSuffix: usedSuffix
        )
    }

    private func funded(
        outputs: [WalletCreateActionOutput], inputs: [StorageActionInput]
    ) -> StorageCreateActionResult {
        StorageCreateActionResult(
            reference: "ref", version: 1, lockTime: 0, outputs: outputs, inputs: inputs,
            inputBEEF: nil, derivationPrefix: prefix
        )
    }

    // MARK: - Signing

    func test_aBRC29InputIsSigned() throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let requested = [try output(satoshis: 1_000)]
        let action = funded(
            outputs: requested, inputs: [try brc29Input(identity: identity, sender: sender)]
        )

        let signed = try ActionSigner.sign(
            action, requested: requested, identityKey: identity, senderPublicKey: sender
        )

        XCTAssertFalse(signed.inputs[0].unlockingScript.bytes.isEmpty,
                       "the input must carry an unlocking script once signed")
    }

    /// The signer must rediscover the key from the derivation alone. The SDK refuses to sign when
    /// the key does not hash to the script being unlocked, so reaching a signature proves the
    /// derivation agreed with the output.
    func test_theKeyIsFoundFromTheDerivationAlone() throws {
        let identity = try key(7)
        let sender = try key(9).publicKey
        let requested = [try output(satoshis: 100)]
        let action = funded(
            outputs: requested,
            inputs: [try brc29Input(identity: identity, sender: sender, satoshis: 900)]
        )

        XCTAssertNoThrow(
            try ActionSigner.sign(
                action, requested: requested, identityKey: identity, senderPublicKey: sender
            )
        )
    }

    func test_everyInputIsSigned() throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let requested = [try output(satoshis: 1_000)]
        let action = funded(outputs: requested, inputs: [
            try brc29Input(identity: identity, sender: sender),
            try brc29Input(identity: identity, sender: sender, suffix: "Other=="),
        ])

        let signed = try ActionSigner.sign(
            action, requested: requested, identityKey: identity, senderPublicKey: sender
        )

        XCTAssertEqual(signed.inputs.count, 2)
        XCTAssertTrue(signed.inputs.allSatisfy { !$0.unlockingScript.bytes.isEmpty })
    }

    // MARK: - Refusals

    /// Nothing is signed if the outputs were altered. This is the check being on the path rather
    /// than beside it.
    func test_alteredOutputsStopSigning() throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let requested = [try output(satoshis: 1_000)]
        let tampered = [
            try WalletCreateActionOutput(
                lockingScript: [0xde, 0xad], satoshis: 1_000, outputDescription: "payment"
            )
        ]
        let action = funded(
            outputs: tampered, inputs: [try brc29Input(identity: identity, sender: sender)]
        )

        XCTAssertThrowsError(
            try ActionSigner.sign(
                action, requested: requested, identityKey: identity, senderPublicKey: sender
            )
        ) {
            XCTAssertEqual($0 as? ActionError,
                           .storageAlteredOutputs("storage altered output 0"))
        }
    }

    /// A partly signed transaction looks like success and spends nothing, so a missing derivation
    /// stops the whole thing.
    func test_anInputWithNoDerivationIsRefused() throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let requested = [try output(satoshis: 1_000)]
        var input = try brc29Input(identity: identity, sender: sender)
        input = StorageActionInput(
            sourceTXID: input.sourceTXID, sourceVout: input.sourceVout,
            sourceSatoshis: input.sourceSatoshis,
            sourceLockingScript: input.sourceLockingScript,
            unlockingScriptLength: input.unlockingScriptLength,
            derivationPrefix: prefix, derivationSuffix: nil
        )
        let action = funded(outputs: requested, inputs: [input])

        XCTAssertThrowsError(
            try ActionSigner.sign(
                action, requested: requested, identityKey: identity, senderPublicKey: sender
            )
        )
    }

    /// The wrong sender derives a different key, which cannot open the output. Signing anyway
    /// would produce a transaction the network rejects, so it is refused here where the reason is
    /// still known.
    func test_theWrongSenderIsRefused() throws {
        let identity = try key(1)
        let realSender = try key(2).publicKey
        let wrongSender = try key(3).publicKey
        let requested = [try output(satoshis: 1_000)]
        let action = funded(
            outputs: requested, inputs: [try brc29Input(identity: identity, sender: realSender)]
        )

        XCTAssertThrowsError(
            try ActionSigner.sign(
                action, requested: requested, identityKey: identity,
                senderPublicKey: wrongSender
            )
        )
    }

    func test_theWrongIdentityIsRefused() throws {
        let identity = try key(1)
        let other = try key(4)
        let sender = try key(2).publicKey
        let requested = [try output(satoshis: 1_000)]
        let action = funded(
            outputs: requested, inputs: [try brc29Input(identity: identity, sender: sender)]
        )

        XCTAssertThrowsError(
            try ActionSigner.sign(
                action, requested: requested, identityKey: other, senderPublicKey: sender
            )
        )
    }
}
