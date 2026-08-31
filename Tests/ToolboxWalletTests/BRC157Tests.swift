import BSVCompat
import BSVKeys
import XCTest

@testable import ToolboxWallet

final class BRC157Tests: XCTestCase {
    private let workedPhrase =
        "legal winner thank year wave sausage worth useful legal winner thank yellow"

    func test_workedBRC157VectorMatchesExactly() throws {
        let subject = try BRC157Entropy(mnemonicPhrase: workedPhrase)

        XCTAssertEqual(hex(subject.entropy), "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        XCTAssertEqual(
            hex(subject.paddedEntropy),
            "000000000000000000000000000000007f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
        )
        XCTAssertEqual(subject.mnemonic.phrase, workedPhrase)
        XCTAssertEqual(
            hex(try subject.rootKey().bytes),
            "27e442c8015fc055789d6628f3b30461e8b2598aff74dc87ceef00dd8e670e55"
        )
    }

    func test_profilesMatchTheLiveTypeScriptReference() throws {
        let subject = try BRC157Entropy(mnemonicPhrase: workedPhrase)

        XCTAssertEqual(
            hex(try subject.profileKey(index: 0).bytes),
            "27e442c8015fc055789d6628f3b30461e8b2598aff74dc87ceef00dd8e670e55"
        )
        XCTAssertEqual(
            hex(try subject.profileKey(index: 1).bytes),
            "8d5bd9de4d42da1ee10fa7d09f14ba13512b4725844e9f936bdc35b9cb9e17dc"
        )
        XCTAssertEqual(
            hex(try subject.profileKey(index: 2).bytes),
            "5874796bb9d0fc8fc4dfa18452d4eb5f2547970b6a31e9cd655b5b636cbb5d37"
        )
        XCTAssertEqual(
            hex(try subject.profileKey(index: 2_147_483_647).bytes),
            "9ece45ac5d727eeb582b9fb52045034c4f6c6b97cddb11d79f94758172af45fe"
        )
        XCTAssertThrowsError(try subject.profileKey(index: 2_147_483_648)) { error in
            XCTAssertEqual(error as? BRC157Error, .invalidProfileIndex(2_147_483_648))
        }
    }

    func test_allBIP39WordCountsRoundTripAndDeriveExactReferenceRoots() throws {
        let cases: [(bytes: Int, words: Int, phrase: String, root: String)] = [
            (
                16,
                12,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon actual",
                "da1dbaa371674aad9b55a22a89f60b04c182db6ff44df2cb25f7a4547e98b667"
            ),
            (
                20,
                15,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon amateur",
                "77d42e1062e7a5944c31da26a907a0da1cacdd4942a721c1dff70080a326368d"
            ),
            (
                24,
                18,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon author",
                "0f3415c8818ddaa27dc6c90f30befa06322205b3fc799c70f6ceabdeb874f012"
            ),
            (
                28,
                21,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon breeze",
                "0b593dc1498156ecf001b1c9c86bdd1aac86f5b6047131d4a6902737576391f9"
            ),
            (
                32,
                24,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel",
                "8049e464f17f071c20cbc3eb61d0aae4b3239b69df8d59524569b24e45b97229"
            ),
        ]

        for value in cases {
            var entropy = [UInt8](repeating: 0, count: value.bytes)
            entropy[value.bytes - 1] = 1
            let fromEntropy = try BRC157Entropy(entropy: entropy)
            let fromWords = try BRC157Entropy(mnemonicPhrase: value.phrase)

            XCTAssertEqual(fromEntropy.mnemonic.phrase, value.phrase)
            XCTAssertEqual(fromWords.entropy, entropy)
            XCTAssertEqual(fromWords.mnemonic.words.count, value.words)
            XCTAssertEqual(fromWords.entropyByteCount, value.bytes)
            XCTAssertEqual(fromWords.paddedEntropy.count, 32)
            XCTAssertEqual(hex(try fromWords.rootKey().bytes), value.root)
        }
    }

    func test_mnemonicValidationErrorsRemainTyped() throws {
        XCTAssertThrowsError(
            try BRC157Entropy(
                mnemonicPhrase:
                    "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            )
        ) { error in
            XCTAssertEqual(error as? MnemonicError, .unknownWord("notaword"))
        }
        XCTAssertThrowsError(
            try BRC157Entropy(
                mnemonicPhrase:
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            )
        ) { error in
            XCTAssertEqual(error as? MnemonicError, .checksumMismatch)
        }
        XCTAssertThrowsError(
            try BRC157Entropy(mnemonicPhrase: "abandon abandon abandon")
        ) { error in
            XCTAssertEqual(error as? MnemonicError, .invalidWordCount(3))
        }
    }

    func test_zeroScalarIsRejectedAtEverySupportedMnemonicLength() throws {
        for byteCount in [16, 20, 24, 28, 32] {
            let zero = [UInt8](repeating: 0, count: byteCount)
            let validZeroMnemonic = try Mnemonic(entropy: zero)

            XCTAssertThrowsError(try BRC157Entropy(entropy: zero)) { error in
                XCTAssertEqual(error as? BRC157Error, .invalidEntropyScalar)
            }
            XCTAssertThrowsError(try BRC157Entropy(mnemonic: validZeroMnemonic)) { error in
                XCTAssertEqual(error as? BRC157Error, .invalidEntropyScalar)
            }
        }
    }

    func test_scalarOrderBoundaryIsExact() throws {
        let order = bytes(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        )
        var orderMinusOne = order
        orderMinusOne[31] -= 1
        let orderMnemonic = try Mnemonic(entropy: order)

        XCTAssertNoThrow(try BRC157Entropy(entropy: orderMinusOne))
        XCTAssertThrowsError(try BRC157Entropy(entropy: order)) { error in
            XCTAssertEqual(error as? BRC157Error, .invalidEntropyScalar)
        }
        XCTAssertThrowsError(try BRC157Entropy(mnemonic: orderMnemonic)) { error in
            XCTAssertEqual(error as? BRC157Error, .invalidEntropyScalar)
        }
    }

    func test_entropyLengthValidationIsExact() {
        for byteCount in [0, 1, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33] {
            XCTAssertThrowsError(
                try BRC157Entropy(entropy: [UInt8](repeating: 1, count: byteCount))
            ) { error in
                XCTAssertEqual(error as? BRC157Error, .invalidEntropyByteCount(byteCount))
            }
        }
    }

    func test_shareRecoveryRestoresTheRecordedOriginalWords() throws {
        let original = try BRC157Entropy(mnemonicPhrase: workedPhrase)
        let shares = try original.backupShares(threshold: 2, shareCount: 3)
        let recovered = try BRC157Entropy.recover(
            from: [shares[0], shares[2]],
            entropyByteCount: 16
        )
        let inferred = try BRC157Entropy.recoverUsingInferredByteCount(
            from: [shares[1], shares[2]]
        )

        XCTAssertEqual(recovered.entropy, original.entropy)
        XCTAssertEqual(recovered.mnemonic.phrase, workedPhrase)
        XCTAssertEqual(try recovered.rootKey(), try original.rootKey())
        XCTAssertEqual(inferred.entropy, original.entropy)
        XCTAssertEqual(inferred.mnemonic.phrase, workedPhrase)

        let wrongTwentyFourWords = try Mnemonic(entropy: original.paddedEntropy)
        XCTAssertEqual(
            wrongTwentyFourWords.phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                + "abandon abstract wave sausage worth useful legal winner thank year wave sausage "
                + "worth upgrade"
        )
        XCTAssertNotEqual(wrongTwentyFourWords.phrase, recovered.mnemonic.phrase)
    }

    func test_recoveryRefusesToDiscardNonzeroBytesForAWrongLength() throws {
        let entropyKey = try PrivateKey([UInt8](repeating: 1, count: 32))

        XCTAssertThrowsError(
            try BRC157Entropy(recoveredEntropyKey: entropyKey, entropyByteCount: 16)
        ) { error in
            XCTAssertEqual(
                error as? BRC157Error,
                .recoveredEntropyDoesNotFitByteCount(16)
            )
        }
        XCTAssertThrowsError(
            try BRC157Entropy(recoveredEntropyKey: entropyKey, entropyByteCount: 18)
        ) { error in
            XCTAssertEqual(error as? BRC157Error, .invalidEntropyByteCount(18))
        }
    }

    func test_newWalletGenerationAlwaysProducesA24WordValidScalar() throws {
        for _ in 0..<8 {
            let generated = try BRC157Entropy.generate()

            XCTAssertEqual(generated.entropyByteCount, 32)
            XCTAssertEqual(generated.mnemonic.words.count, 24)
            XCTAssertEqual(generated.paddedEntropy, generated.entropy)
            XCTAssertNoThrow(try PrivateKey(generated.entropy))
        }
    }

    func test_diagnosticsNeverRevealEntropyOrWords() throws {
        let subject = try BRC157Entropy(mnemonicPhrase: workedPhrase)
        var dumped = ""
        dump(subject, to: &dumped)

        for diagnostic in [String(describing: subject), String(reflecting: subject), dumped] {
            XCTAssertFalse(diagnostic.contains("legal"))
            XCTAssertFalse(diagnostic.contains("7f7f"))
        }
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func bytes(_ hex: String) -> [UInt8] {
        stride(from: 0, to: hex.count, by: 2).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 2)
            return UInt8(hex[start..<end], radix: 16)!
        }
    }
}
