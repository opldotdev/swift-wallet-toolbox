import XCTest
import BSVSPV
@testable import ToolboxServices

final class ChainBlockHeaderTests: XCTestCase {
    private let genesisHex =
        "01000000" +
        String(repeating: "00", count: 32) +
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
        "29ab5f49ffff001d1dac2b7c"

    private func bytes(_ hex: String) -> [UInt8] {
        stride(from: 0, to: hex.count, by: 2).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 2)
            return UInt8(hex[start..<end], radix: 16)!
        }
    }

    func test_genesisRetainsCanonicalEightyByteHeader() throws {
        let serialized = bytes(genesisHex)

        let positioned = try ChainBlockHeader(height: 0, serializedBytes: serialized)

        XCTAssertEqual(serialized.count, BlockHeader.byteCount)
        XCTAssertEqual(positioned.height, 0)
        XCTAssertEqual(positioned.serializedBytes, serialized)
        XCTAssertEqual(
            positioned.hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        )
        XCTAssertEqual(positioned.merkleRoot.count, 32)
    }

    func test_serializedInitializerRequiresExactlyEightyBytes() {
        XCTAssertThrowsError(
            try ChainBlockHeader(height: 1, serializedBytes: [UInt8](repeating: 0, count: 79))
        )
        XCTAssertThrowsError(
            try ChainBlockHeader(height: 1, serializedBytes: [UInt8](repeating: 0, count: 81))
        )
    }

    func test_summaryInitializerPreservesLegacyFieldsWithoutFabricatingBytes() {
        let hash = "provider-format-hash"
        let merkleRoot: [UInt8] = [1, 2, 3]

        let summary = ChainBlockHeader(height: 12, hash: hash, merkleRoot: merkleRoot)

        XCTAssertEqual(summary.height, 12)
        XCTAssertEqual(summary.hash, hash)
        XCTAssertEqual(summary.merkleRoot, merkleRoot)
        XCTAssertNil(summary.header)
        XCTAssertNil(summary.serializedBytes)
    }

    func test_providerHashMustMatchHeader() throws {
        let header = try BlockHeader(hex: genesisHex)
        let wrongHash = String(repeating: "11", count: 32)

        XCTAssertThrowsError(
            try ChainBlockHeader(height: 0, hash: wrongHash, header: header)
        ) { error in
            XCTAssertEqual(
                error as? ChainBlockHeaderError,
                .hashMismatch(declared: wrongHash, computed: header.hash.displayHex)
            )
        }
    }
}
