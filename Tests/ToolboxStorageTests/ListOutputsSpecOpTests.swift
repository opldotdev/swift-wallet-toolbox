import XCTest
import ToolboxStorage

/// The special-operation names are `@bsv/wallet-toolbox`'s `src/sdk/types.ts` values. Storage
/// matches them byte for byte, so a typo here would list an empty basket instead of running the
/// operation.
final class ListOutputsSpecOpTests: XCTestCase {

    func test_valuesMatchTheReference() {
        XCTAssertEqual(
            ListOutputsSpecOp.basketPrefixOutputs,
            "b9184a72141e6a4d3d148c67a6d0ad92864a4d85290579ea5bef8bd62eb01b6f"
        )
        XCTAssertEqual(
            ListOutputsSpecOp.walletBalance,
            "893b7646de0e1c9f741bd6e9169b76a8847ae34adef7bef1e6a285371206d2e8"
        )
        XCTAssertEqual(
            ListOutputsSpecOp.walletManagedUtxos,
            "284570a6213a74ba861c38b1cf790e1e400d9cf9324454b76ea98860b6031c1a"
        )
        XCTAssertEqual(
            ListOutputsSpecOp.invalidChange,
            "5a76fd430a311f8bc0553859061710a4475c19fed46e2ff95969aa918e612e57"
        )
        XCTAssertEqual(
            ListOutputsSpecOp.setWalletChangeParams,
            "a4979d28ced8581e9c1c92f1001cc7cb3aabf8ea32e10888ad898f0a509a3929"
        )
    }

    func test_containsMatchesOnlyTheReservedNames() {
        XCTAssertEqual(ListOutputsSpecOp.all.count, 5)
        for name in ListOutputsSpecOp.all { XCTAssertTrue(ListOutputsSpecOp.contains(name)) }
        XCTAssertFalse(ListOutputsSpecOp.contains("default"))
        XCTAssertFalse(ListOutputsSpecOp.contains("p color"))
        XCTAssertFalse(ListOutputsSpecOp.contains(ListOutputsSpecOp.basketPrefixOutputs.uppercased()))
    }
}
