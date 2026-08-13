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

    /// bun `@bsv/sdk` KeyDeriver protocol `[0, "p 1sat"]` keyID `"1sat <i>"` counterparty self forSelf; abandon identity `5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1`; 2026-08-13.
    private let depositAddresses = [
        "18Dg5KjZsS4fTPZYTvNP9z76WySuB8XSLc",
        "1JKT82gZGUCMo9PU7Hjrqa9rKBtcj9khPz",
        "1BdMVZzcu9G67hrfQFMnae6EFkrzJCDC9y",
        "1Ao2nLUR9r1gyfwWVtex5SbRpEkPUo147C",
        "13UNnQTCcRsSRjTSTX27CUZ1PZBQyee14o",
        "1P52KZuMLJhXYLc8rmULvf3swsY1h24pea",
        "19A5k4UXqaqwzhY4qmbk5SCZh8MHsD6p9E",
        "197U2wbdyaTb2i8MkCgeCJmsffgbASaj61",
        "18YComjX76MyjgnnsrHUixgvT3m3DbEPjU",
        "18r2S3wm1UA1rxTWW1DfmHXfiJUtHYFrz5",
    ]

    /// A restored wallet regenerates the same address set from the phrase alone — the whole point
    /// of a deterministic receive address.
    func test_aRestoredWalletRegeneratesTheSameAddresses() throws {
        let wallet = try RemoteWallet.restore(fromPhrase: phrase)

        XCTAssertEqual(try wallet.receiveAddress(index: 0), depositAddresses[0])
        XCTAssertEqual(
            try wallet.receiveAddresses(startIndex: 0, count: 10),
            depositAddresses
        )
    }

    /// Each index is a different address, or the wallet would reuse one and leak its history.
    func test_eachIndexIsAdifferentAddress() throws {
        let addresses = try RemoteWallet.restore(fromPhrase: phrase)
            .receiveAddresses(startIndex: 0, count: 5)

        XCTAssertEqual(Set(addresses).count, 5)
    }
}
