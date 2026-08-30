import XCTest
import BSVKeys
import ToolboxBRC29
@testable import ToolboxWallet

/// Deriving receiving addresses the way the live 1Sat ecosystem does.
///
/// The expected addresses come from the same reference derivation: self-derivation under protocol [0, "onesat"] with keyID
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
            "1QJvLPW2fRZsFqcncVfS3p4PaeMMCcrwnx"
        )
        XCTAssertEqual(
            try OneSatDeposit.address(identity: identity, index: 1).description,
            "1ACGfnV2DrzzY3cBUWvN6BZae8s9AU3YhH"
        )
        XCTAssertEqual(
            try OneSatDeposit.address(identity: identity, index: 2).description,
            "1KWFd6YZghV2kZHWwFhKodVH7eocbpZ3fA"
        )
    }

    /// bun `@bsv/sdk` KeyDeriver protocol `[0, "onesat"]` keyID `"1sat <i>"` counterparty self forSelf; abandon identity `5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1`; 2026-08-28.
    private let depositAddresses = [
        "1QJvLPW2fRZsFqcncVfS3p4PaeMMCcrwnx",
        "1ACGfnV2DrzzY3cBUWvN6BZae8s9AU3YhH",
        "1KWFd6YZghV2kZHWwFhKodVH7eocbpZ3fA",
        "1EyBKgtgkd4X4EQqxJX18Yi8huTsbHH2QX",
        "1AYA2Qgr5Lyq3Utf8GHnKUPhRz5fB5qrjH",
        "1LV3J6GpPDm4G8rT5itKbQAiu1rw1CRMnT",
        "1Lnj566VgNguoSZJwpqNo1BCcY2p3aiYM7",
        "1CRGL1tNfwKXzz69Wcpz7WYbxgAM9jdFmB",
        "141sNrPhVAU4FzMY9pGKnhU36opmVkUFoP",
        "18MQLhTfJM8yA59dHxdfchKzgPPF4CqEaK",
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
