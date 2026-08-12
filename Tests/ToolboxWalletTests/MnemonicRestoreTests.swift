import XCTest
import BSVKeys
@testable import ToolboxWallet

/// Restoring keys from a recovery phrase, checked against the reference libraries.
///
/// The expected values below were produced by `@bsv/sdk`'s `Mnemonic`/`HD` and the BRC-29
/// derivation, from the standard BIP-39 test phrase. A wrong path or a wrong derivation produces a
/// valid-looking wallet holding none of the original money, so agreeing with the reference is the
/// only check worth having — the same reason the BRC-29 vectors exist.
final class MnemonicRestoreTests: XCTestCase {

    private let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private func address(_ key: PrivateKey) -> String {
        Address(publicKey: key.publicKey, network: .mainnet).description
    }

    func test_theIdentityKeyMatchesTheReference() throws {
        let identity = try MnemonicRestore.identityKey(fromPhrase: phrase)

        XCTAssertEqual(address(identity), "16UeyS7TvuQDwYreJpZqZceEKWbjzt4JW4")
    }

    func test_allThreeKeysMatchTheReference() throws {
        let keys = try MnemonicRestore.keys(fromPhrase: phrase)

        XCTAssertEqual(address(keys.identity), "16UeyS7TvuQDwYreJpZqZceEKWbjzt4JW4")
        XCTAssertEqual(address(keys.wallet), "125GFsvYsDtyzGkExfsX8DoHuXu2UsMUEZ")
        XCTAssertEqual(address(keys.ord), "18pBoqRpHUYf9udsab5G9LT3vQUPxEyMFf")
    }

    /// A passphrase changes the seed, so it changes every key. This proves the twenty-fifth word
    /// is actually applied rather than ignored.
    func test_apassphraseChangesTheKeys() throws {
        let plain = try MnemonicRestore.identityKey(fromPhrase: phrase)
        let salted = try MnemonicRestore.identityKey(fromPhrase: phrase, passphrase: "trezor")

        XCTAssertNotEqual(address(plain), address(salted))
    }

    func test_annonsenseWordIsRefused() {
        XCTAssertThrowsError(try MnemonicRestore.identityKey(fromPhrase: "not a real phrase at all"))
    }
}
