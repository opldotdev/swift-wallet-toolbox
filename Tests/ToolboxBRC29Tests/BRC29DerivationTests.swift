import XCTest
import BSVKeys
@testable import ToolboxBRC29

/// BRC-29 derivation, checked against the Go toolbox's own vectors.
///
/// The keys, prefix, suffix and expected addresses below are taken verbatim from
/// `go-wallet-toolbox/pkg/brc29/fixtures_test.go`. That matters more than usual here: a wrong
/// derivation produces an address that looks perfectly valid and that no key can open, so money
/// sent to it is gone with nothing to debug. Agreeing with another implementation is the only
/// check worth having.
final class BRC29DerivationTests: XCTestCase {

    private let senderPrivateKeyHex =
        "143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c"
    private let recipientPrivateKeyHex =
        "0000000000000000000000000000000000000000000000000000000000000001"
    private let recipientPublicKeyHex =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    private let prefix = "Pr=="
    private let suffix = "Su=="
    private let expectedAddress = "19bxE1pRYYtjZeQm7P8e2Ws5zMkm8NNuxx"
    private let expectedTestnetAddress = "mp7uX4uQMaKzLktNpx71rS5QrMMTzDP12u"

    private func key(_ hex: String) throws -> PrivateKey {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(try XCTUnwrap(UInt8(hex[index..<next], radix: 16)))
            index = next
        }
        return try PrivateKey(bytes)
    }

    // MARK: - Agreement with the Go toolbox

    /// The payer's derivation must land on the address the Go toolbox computes.
    func test_thePayersDerivationMatchesTheGoToolbox() throws {
        let sender = try key(senderPrivateKeyHex)
        let recipient = try PublicKey(
            Array(recipientPublicKeyHex.dropFirst(0)).chunked()
        )

        let paying = try BRC29.payingPublicKey(
            recipient: recipient, sender: sender, prefix: prefix, suffix: suffix
        )

        XCTAssertEqual(BRC29.address(for: paying).description, expectedAddress)
    }

    /// The payee's derivation must land on the same address, from the other side.
    func test_thePayeesDerivationMatchesTheGoToolbox() throws {
        let recipient = try key(recipientPrivateKeyHex)
        let sender = try key(senderPrivateKeyHex).publicKey

        let receiving = try BRC29.receivingPrivateKey(
            recipient: recipient, sender: sender, prefix: prefix, suffix: suffix
        )

        XCTAssertEqual(
            BRC29.address(for: receiving.publicKey).description, expectedAddress
        )
    }

    func test_theTestnetAddressMatchesTheGoToolbox() throws {
        let recipient = try key(recipientPrivateKeyHex)
        let sender = try key(senderPrivateKeyHex).publicKey

        let receiving = try BRC29.receivingPrivateKey(
            recipient: recipient, sender: sender, prefix: prefix, suffix: suffix
        )

        XCTAssertEqual(
            BRC29.address(for: receiving.publicKey, network: .testnet).description,
            expectedTestnetAddress
        )
    }

    // MARK: - The property that makes money spendable

    /// Both sides must reach the same key. If they do not, the payer pays an address the payee
    /// holds no key for, and the coin is unspendable forever.
    func test_bothSidesDeriveTheSameKey() throws {
        let sender = try key(senderPrivateKeyHex)
        let recipient = try key(recipientPrivateKeyHex)

        let paying = try BRC29.payingPublicKey(
            recipient: recipient.publicKey, sender: sender, prefix: prefix, suffix: suffix
        )
        let receiving = try BRC29.receivingPrivateKey(
            recipient: recipient, sender: sender.publicKey, prefix: prefix, suffix: suffix
        )

        XCTAssertEqual(receiving.publicKey.compressedBytes, paying.compressedBytes)
    }

    /// A different suffix is a different address. This is what stops one payment's key opening
    /// another's, and it is why both halves are stored per output.
    func test_adifferentSuffixGivesAdifferentKey() throws {
        let recipient = try key(recipientPrivateKeyHex)
        let sender = try key(senderPrivateKeyHex).publicKey

        let first = try BRC29.receivingPrivateKey(
            recipient: recipient, sender: sender, prefix: prefix, suffix: suffix
        )
        let second = try BRC29.receivingPrivateKey(
            recipient: recipient, sender: sender, prefix: prefix, suffix: "Other=="
        )

        XCTAssertNotEqual(first.publicKey.compressedBytes, second.publicKey.compressedBytes)
    }

    /// The counterparty is part of the derivation. The same prefix and suffix from a different
    /// payer give a different key, which is why an output records who paid it.
    func test_adifferentSenderGivesAdifferentKey() throws {
        let recipient = try key(recipientPrivateKeyHex)
        let sender = try key(senderPrivateKeyHex).publicKey
        let other = try key(
            "0000000000000000000000000000000000000000000000000000000000000002"
        ).publicKey

        let first = try BRC29.receivingPrivateKey(
            recipient: recipient, sender: sender, prefix: prefix, suffix: suffix
        )
        let second = try BRC29.receivingPrivateKey(
            recipient: recipient, sender: other, prefix: prefix, suffix: suffix
        )

        XCTAssertNotEqual(first.publicKey.compressedBytes, second.publicKey.compressedBytes)
    }

    /// The locking script is plain P2PKH over the derived key — BRC-29 changes which key is used,
    /// never how the output is locked.
    func test_theLockingScriptIsPayToPublicKeyHash() throws {
        let recipient = try key(recipientPrivateKeyHex)
        let sender = try key(senderPrivateKeyHex).publicKey
        let receiving = try BRC29.receivingPrivateKey(
            recipient: recipient, sender: sender, prefix: prefix, suffix: suffix
        )

        let script = try BRC29.lockingScript(for: receiving.publicKey)

        XCTAssertEqual(script.bytes.first, 0x76, "OP_DUP")
        XCTAssertEqual(script.bytes.count, 25)
    }
}

private extension Array where Element == Character {
    /// Pairs of hex characters as bytes.
    func chunked() -> [UInt8] {
        var bytes: [UInt8] = []
        var index = 0
        while index + 1 < count {
            bytes.append(UInt8(String(self[index...index + 1]), radix: 16) ?? 0)
            index += 2
        }
        return bytes
    }
}
