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

    /// bun `@bsv/sdk` KeyDeriver protocol `[0, "onesat"]` keyID `"1sat <i>"` counterparty self forSelf; abandon identity `5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1`; 2026-08-28.
    private let depositPublicKeys = [
        "020c778686118af71d0e0a11e63cec2357640ae7c2100f4969c3d2336b99aa0a87",
        "02635ca4953a033aad8c69ad9780fd0f2b31ffa14d887185701ee688c9289f197f",
        "02c31e6433acb6c6b0b22e0443dccc91c931a16ff873e1cbcd60355c8f9ee22905",
        "0331c1dac77f7e2acc2049e9fc7d534e6a62cb3941284aa816bec8424705b58f35",
        "03ff7b751ad251d1e7d53b54fb59a81fa124e9d2d0ea38fa42051bd3ddf8ef14f8",
        "023a524765f66e554e7c39b0c1105f37465f16f682ccc84a35fcc49fcc8069f6d9",
        "035db554a3710aa3a4749216763cb43d8efa05980b0c3f5ae2bb608ceb6a0fc3bd",
        "02c40df6fbb72bd57efdf5213d346561048cd582292af4409f33cb8c881fa3ee2a",
        "02c721f01dd5ba4c87e7c50c3e8a5689e0e6569a1ed6226910bcec6de8b3979491",
        "0242b8fffda863c1703355da4306b664aef0eec67ef490e8439131efba1da6a79c",
    ]

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
        XCTAssertEqual(OneSatDeposit.invoiceNumber(index: 0), "0-onesat-1sat 0")
        XCTAssertEqual(OneSatDeposit.invoiceNumber(index: 1), "0-onesat-1sat 1")
        XCTAssertEqual(OneSatDeposit.invoiceNumber(index: 9), "0-onesat-1sat 9")
    }

    func test_addressesMatchThe1SatReference() throws {
        let identity = try identity()
        // @1sat/actions deriveDepositAddresses, prefix "1sat"
        for index in 0..<10 {
            XCTAssertEqual(
                try OneSatDeposit.address(identity: identity, index: index).description,
                depositAddresses[index]
            )
            XCTAssertEqual(
                try OneSatDeposit.key(identity: identity, index: index).publicKey.compressedBytes,
                try hexBytes(depositPublicKeys[index])
            )
        }
    }
}
