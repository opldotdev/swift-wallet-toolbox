import XCTest
import BSVKeys
import ToolboxBRC29
@testable import ToolboxWallet

/// Deriving receiving addresses the way Yours Wallet does.
///
/// The expected addresses come from the same reference derivation: BRC-29 self-derivation with the
/// fixed prefix "yours receive" and the index as the suffix. If these drift, a wallet restored from
/// a Yours backup would show different addresses and the received money would be invisible.
final class ReceiveAddressTests: XCTestCase {

    private let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private func identity() throws -> PrivateKey {
        try MnemonicRestore.identityKey(fromPhrase: phrase)
    }

    func test_receivingAddressesMatchTheReference() throws {
        let identity = try identity()

        XCTAssertEqual(
            try BRC29.receivingAddress(identity: identity, index: 0).description,
            "1MaNmyMfDuBSt2Mr4eFXFTxMib6HFYA41p"
        )
        XCTAssertEqual(
            try BRC29.receivingAddress(identity: identity, index: 1).description,
            "12poj5zbiiDfJ6Ne7AUcQxMfL1ohRTVa2u"
        )
        XCTAssertEqual(
            try BRC29.receivingAddress(identity: identity, index: 2).description,
            "16xvb4oLXmwgCNX99ewZJ8fySRkoeQDRLe"
        )
    }

    /// A restored wallet regenerates the same address set from the phrase alone — the whole point
    /// of a deterministic receive address.
    func test_aRestoredWalletRegeneratesTheSameAddresses() throws {
        let wallet = try RemoteWallet.restore(fromPhrase: phrase)

        XCTAssertEqual(try wallet.receiveAddress(index: 0), "1MaNmyMfDuBSt2Mr4eFXFTxMib6HFYA41p")
        XCTAssertEqual(
            try wallet.receiveAddresses(startIndex: 0, count: 3),
            [
                "1MaNmyMfDuBSt2Mr4eFXFTxMib6HFYA41p",
                "12poj5zbiiDfJ6Ne7AUcQxMfL1ohRTVa2u",
                "16xvb4oLXmwgCNX99ewZJ8fySRkoeQDRLe",
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
