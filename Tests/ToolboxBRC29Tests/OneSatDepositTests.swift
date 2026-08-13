import XCTest
import BSVKeys
@testable import ToolboxBRC29

/// The toolbox copy of 1Sat deposit derivation, locked without `ToolboxWallet`.
///
/// Expected addresses are `@1sat/actions` `deriveDepositAddresses` under prefix `"1sat"`,
/// from the abandon-phrase identity (`MnemonicRestore`: first 32 bytes of the BIP-39 seed).
final class OneSatDepositTests: XCTestCase {

    /// BIP-39 seed prefix for
    /// `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`.
    private let abandonIdentityHex =
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"

    private func identity() throws -> PrivateKey {
        try PrivateKey(hexBytes(abandonIdentityHex))
    }

    private func hexBytes(_ hex: String) throws -> [UInt8] {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(try XCTUnwrap(UInt8(hex[index..<next], radix: 16)))
            index = next
        }
        return bytes
    }

    func test_invoiceNumberMatchesThe1SatKeyID() {
        XCTAssertEqual(OneSatDeposit.invoiceNumber(index: 0), "0-p 1sat-1sat 0")
    }

    func test_addressesMatchThe1SatReference() throws {
        let identity = try identity()
        // @1sat/actions deriveDepositAddresses, prefix "1sat"
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
}
