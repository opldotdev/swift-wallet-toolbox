import XCTest
import BSVKeys
import ToolboxBRC29
@testable import ToolboxWallet

/// Deriving receiving addresses the way the live 1Sat ecosystem does.
///
/// The expected addresses come from the same reference derivation: self-derivation under protocol [0, "p 1sat"] with keyID
/// "1sat <index>" — the current @1sat/actions deriveDepositAddresses convention. If these drift, the wallet shows different
/// addresses than the live ecosystem and received money is invisible.
final class ReceiveAddressTests: XCTestCase {

    private let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private func identity() throws -> PrivateKey {
        try MnemonicRestore.identityKey(fromPhrase: phrase)
    }

    func test_receivingAddressesMatchTheReference() throws {
        let identity = try identity()

        XCTAssertEqual(
            try OneSatDeposit.address(identity: identity, index: 0).description,
            "18Dg5KjZsS4fTPZYTvNP9z76WySuB8XSLc"
        )
        XCTAssertEqual(
            try OneSatDeposit.address(identity: identity, index: 1).description,
            "1JKT82gZGUCMo9PU7Hjrqa9rKBtcj9khPz"
        )
        XCTAssertEqual(
            try OneSatDeposit.address(identity: identity, index: 2).description,
            "1BdMVZzcu9G67hrfQFMnae6EFkrzJCDC9y"
        )
    }

    /// A restored wallet regenerates the same address set from the phrase alone — the whole point
    /// of a deterministic receive address.
    func test_aRestoredWalletRegeneratesTheSameAddresses() throws {
        let wallet = try RemoteWallet.restore(fromPhrase: phrase)

        XCTAssertEqual(try wallet.receiveAddress(index: 0), "18Dg5KjZsS4fTPZYTvNP9z76WySuB8XSLc")
        XCTAssertEqual(
            try wallet.receiveAddresses(startIndex: 0, count: 3),
            [
                "18Dg5KjZsS4fTPZYTvNP9z76WySuB8XSLc",
                "1JKT82gZGUCMo9PU7Hjrqa9rKBtcj9khPz",
                "1BdMVZzcu9G67hrfQFMnae6EFkrzJCDC9y",
            ]
        )
    }

    /// Each index is a different address, or the wallet would reuse one and leak its history.
    func test_eachIndexIsAdifferentAddress() throws {
        let addresses = try RemoteWallet.restore(fromPhrase: phrase)
            .receiveAddresses(startIndex: 0, count: 5)

        XCTAssertEqual(Set(addresses).count, 5)
    }
}
