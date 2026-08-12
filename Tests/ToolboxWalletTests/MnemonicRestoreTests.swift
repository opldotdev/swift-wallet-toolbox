import XCTest
import BSVKeys
@testable import ToolboxWallet

/// Restoring the identity key from a recovery phrase, checked against `@bsv/sdk`.
///
/// The scheme is the BSV Association reference (`bsv-desktop`): the identity key is the mnemonic's
/// key material directly — 24-word entropy, or the first 32 bytes of a 12-word seed. The expected
/// addresses were produced by `@bsv/sdk` from the same phrases, so agreeing with them proves this
/// wallet and the official wallet recover the same key from the same words.
final class MnemonicRestoreTests: XCTestCase {

    private let twelveWord =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let twentyFourWord =
        "adapt explain ecology dinner glare old unfair empty expect road off suggest "
        + "dash dolphin captain version oval census uncover inform arrest trash first nice"

    private func address(_ key: PrivateKey) -> String {
        Address(publicKey: key.publicKey, network: .mainnet).description
    }

    /// 12-word: first 32 bytes of the seed.
    func test_aTwelveWordPhraseMatchesTheReference() throws {
        let identity = try MnemonicRestore.identityKey(fromPhrase: twelveWord)

        XCTAssertEqual(address(identity), "1HtadDVwWvHrvvDY1uXSvwT4GJ6sTCAgLH")
    }

    /// 24-word: the 32-byte entropy is the key directly.
    func test_aTwentyFourWordPhraseMatchesTheReference() throws {
        let identity = try MnemonicRestore.identityKey(fromPhrase: twentyFourWord)

        XCTAssertEqual(address(identity), "1PtwUZ9uDfV4SBCngptH8i1WDK4x6Mt7S8")
    }

    /// The two lengths take different code paths and must both work.
    func test_bothPhraseLengthsProduceValidKeys() throws {
        XCTAssertNoThrow(try MnemonicRestore.identityKey(fromPhrase: twelveWord))
        XCTAssertNoThrow(try MnemonicRestore.identityKey(fromPhrase: twentyFourWord))
    }

    func test_annonsenseWordIsRefused() {
        XCTAssertThrowsError(try MnemonicRestore.identityKey(fromPhrase: "not a real phrase at all"))
    }
}
