import XCTest
@testable import ToolboxPortable

final class BRC39Tests: XCTestCase {
    func test_parsesCanonicalHeaderAndSplitsEnvelope() throws {
        let file = makeFile(ciphertext: [1, 2, 3])
        let envelope = try BRC39Envelope.parse(file)

        XCTAssertEqual(envelope.header.iterations, 7)
        XCTAssertEqual(envelope.header.memoryKiB, 131_072)
        XCTAssertEqual(envelope.header.parallelism, 1)
        XCTAssertEqual(envelope.salt, [UInt8](repeating: 7, count: 32))
        XCTAssertEqual(envelope.nonce, [UInt8](repeating: 9, count: 32))
        XCTAssertEqual(envelope.ciphertext, [1, 2, 3])
        XCTAssertEqual(envelope.authenticationTag, [UInt8](repeating: 11, count: 16))
    }

    func test_rejectsInvalidConstantsReservedBytesAndEmptyCiphertext() throws {
        XCTAssertThrowsError(try BRC39Envelope.parse(replacing(makeFile(), at: 0, with: 0))) {
            XCTAssertEqual($0 as? BRC39Error, .badMagic)
        }
        XCTAssertThrowsError(try BRC39Envelope.parse(replacing(makeFile(), at: 8, with: 1))) {
            XCTAssertEqual($0 as? BRC39Error, .invalidFlags)
        }
        XCTAssertThrowsError(try BRC39Envelope.parse(replacing(makeFile(), at: 4, with: 2))) {
            XCTAssertEqual($0 as? BRC39Error, .unsupportedFormatVersion)
        }
        XCTAssertThrowsError(try BRC39Envelope.parse(replacing(makeFile(), at: 5, with: 2))) {
            XCTAssertEqual($0 as? BRC39Error, .unsupportedProtectorType)
        }
        XCTAssertThrowsError(try BRC39Envelope.parse(replacing(makeFile(), at: 6, with: 39))) {
            XCTAssertEqual($0 as? BRC39Error, .unsupportedInnerFormat)
        }
        XCTAssertThrowsError(try BRC39Envelope.parse(replacing(makeFile(), at: 7, with: 2))) {
            XCTAssertEqual($0 as? BRC39Error, .unsupportedKDF)
        }
        XCTAssertThrowsError(try BRC39Envelope.parse(replacing(makeFile(), at: 21, with: 1))) {
            XCTAssertEqual($0 as? BRC39Error, .nonzeroReservedBytes)
        }
        XCTAssertThrowsError(try BRC39Envelope.parse(makeFile(ciphertext: []))) {
            XCTAssertEqual($0 as? BRC39Error, .invalidCiphertext)
        }
    }

    func test_rejectsHostileKDFParametersBeforePasswordWork() throws {
        let excessiveMemory = replacing(makeFile(), range: 15 ..< 19, with: [0x00, 0x20, 0x00, 0x00])
        XCTAssertThrowsError(try BRC39Envelope.parse(excessiveMemory)) {
            XCTAssertEqual($0 as? BRC39Error, .memoryTooLarge)
        }
        XCTAssertThrowsError(try BRC39Envelope.parse(
            makeFile(),
            limits: BRC39Limits(
                maximumFileByteCount: 10,
                maximumIterations: 32,
                maximumMemoryKiB: 1_048_576,
                maximumParallelism: 16
            )
        )) {
            XCTAssertEqual($0 as? BRC39Error, .fileTooLarge(maximumByteCount: 10))
        }
    }

    private func makeFile(ciphertext: [UInt8] = [1]) -> [UInt8] {
        var file = [UInt8](repeating: 0, count: 33)
        file.replaceSubrange(0 ..< 4, with: [0x57, 0x44, 0x41, 0x54])
        file[4] = 1
        file[5] = 1
        file[6] = 38
        file[7] = 1
        file[9] = 32
        file[10] = 32
        file.replaceSubrange(11 ..< 15, with: [0, 0, 0, 7])
        file.replaceSubrange(15 ..< 19, with: [0, 2, 0, 0])
        file[19] = 1
        file[20] = 32
        return file + [UInt8](repeating: 7, count: 32) + [UInt8](repeating: 9, count: 32)
            + ciphertext + [UInt8](repeating: 11, count: 16)
    }

    private func replacing(_ bytes: [UInt8], at index: Int, with byte: UInt8) -> [UInt8] {
        var copy = bytes
        copy[index] = byte
        return copy
    }

    private func replacing(
        _ bytes: [UInt8],
        range: Range<Int>,
        with replacement: [UInt8]
    ) -> [UInt8] {
        var copy = bytes
        copy.replaceSubrange(range, with: replacement)
        return copy
    }
}
