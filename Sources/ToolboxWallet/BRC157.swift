import BSVCompat
import BSVKeys

/// Stable validation failures specific to BRC-157 entropy handling.
public enum BRC157Error: Error, Equatable, Sendable {
    /// BIP-39 entropy is exactly 16, 20, 24, 28, or 32 bytes.
    case invalidEntropyByteCount(Int)
    /// The entropy, after left-padding to 32 bytes, is not in secp256k1's `[1, n - 1]` range.
    case invalidEntropyScalar
    /// A recovered 32-byte entropy key has nonzero bytes outside the recorded original length.
    case recoveredEntropyDoesNotFitByteCount(Int)
    /// Hardened BIP-32 profile indices are restricted to 31 bits.
    case invalidProfileIndex(UInt32)
}

/// A validated BRC-157 entropy backup and its canonical BIP-39 representation.
///
/// This is deliberately separate from ``MnemonicRestore``. That compatibility helper implements
/// the older `bsv-desktop` identity scheme, while BRC-157 derives every operational profile through
/// hardened BIP-32 path `m/0'/i'`.
///
/// The original entropy length is retained so imported 12-, 15-, 18-, and 21-word mnemonics can
/// round-trip through a 32-byte BRC-140 entropy key without becoming a different 24-word mnemonic.
/// The entropy key is exposed only through share operations; it must never sign or serve directly
/// as a wallet root key.
public struct BRC157Entropy:
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable
{
    /// BIP-39 entropy byte counts corresponding to 12, 15, 18, 21, and 24 words.
    public static let supportedByteCounts: Set<Int> = [16, 20, 24, 28, 32]

    private static let scalarByteCount = 32
    private static let secp256k1Order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]

    /// The exact unpadded BIP-39 entropy. This is secret material.
    public let entropy: [UInt8]

    /// The canonical English BIP-39 mnemonic for ``entropy``. This is secret material.
    public let mnemonic: Mnemonic

    /// The original entropy length that must accompany BRC-140 shares for exact word recovery.
    public var entropyByteCount: Int { entropy.count }

    /// The entropy left-padded to exactly 32 bytes for BRC-140 sharing.
    ///
    /// This is the backup subject, not an operational signing key.
    public var paddedEntropy: [UInt8] {
        [UInt8](repeating: 0, count: Self.scalarByteCount - entropy.count) + entropy
    }

    /// Creates and validates BRC-157 entropy at any BIP-39-supported word length.
    public init(entropy: [UInt8]) throws {
        guard Self.supportedByteCounts.contains(entropy.count) else {
            throw BRC157Error.invalidEntropyByteCount(entropy.count)
        }
        let padded = [UInt8](repeating: 0, count: Self.scalarByteCount - entropy.count) + entropy
        guard padded.contains(where: { $0 != 0 }),
            padded.lexicographicallyPrecedes(Self.secp256k1Order)
        else {
            throw BRC157Error.invalidEntropyScalar
        }

        self.entropy = entropy
        mnemonic = try Mnemonic(entropy: entropy)
    }

    /// Parses a strict English BIP-39 phrase, then applies BRC-157 scalar validation.
    ///
    /// `MnemonicError` is preserved for word-count, word-list, checksum, and phrase failures.
    public init(mnemonicPhrase: String) throws {
        try self.init(mnemonic: Mnemonic(mnemonicPhrase))
    }

    /// Applies BRC-157 scalar validation to an already validated mnemonic.
    public init(mnemonic: Mnemonic) throws {
        try self.init(entropy: mnemonic.entropy)
    }

    /// Generates the required uniformly random 32-byte secp256k1 scalar for a new wallet.
    public static func generate() throws -> Self {
        try Self(entropy: PrivateKey.random().bytes)
    }

    /// Restores the original entropy length from a recovered 32-byte BRC-140 entropy key.
    ///
    /// The caller should pass the length recorded with the wallet or share-vault metadata. A
    /// mismatched length is rejected rather than silently discarding nonzero high-order bytes.
    public init(recoveredEntropyKey: PrivateKey, entropyByteCount: Int) throws {
        guard Self.supportedByteCounts.contains(entropyByteCount) else {
            throw BRC157Error.invalidEntropyByteCount(entropyByteCount)
        }
        let paddingCount = Self.scalarByteCount - entropyByteCount
        guard recoveredEntropyKey.bytes.prefix(paddingCount).allSatisfy({ $0 == 0 }) else {
            throw BRC157Error.recoveredEntropyDoesNotFitByteCount(entropyByteCount)
        }
        try self.init(entropy: Array(recoveredEntropyKey.bytes.suffix(entropyByteCount)))
    }

    /// Splits the padded entropy key with the standard BRC-140 implementation.
    public func backupShares(threshold: Int, shareCount: Int) throws -> [KeyShare] {
        try KeySharing.split(
            PrivateKey(paddedEntropy),
            threshold: threshold,
            shareCount: shareCount
        )
    }

    /// Recovers entropy from BRC-140 shares using the recorded original entropy length.
    public static func recover(
        from shares: [KeyShare],
        entropyByteCount: Int
    ) throws -> Self {
        try Self(
            recoveredEntropyKey: KeySharing.recover(shares),
            entropyByteCount: entropyByteCount
        )
    }

    /// Recovers entropy using BRC-157's last-resort leading-zero heuristic.
    ///
    /// Prefer ``recover(from:entropyByteCount:)``. This fallback can misidentify genuine entropy
    /// beginning with four or more zero bytes, as noted by BRC-157.
    public static func recoverUsingInferredByteCount(from shares: [KeyShare]) throws -> Self {
        let recovered = try KeySharing.recover(shares)
        return try Self(
            recoveredEntropyKey: recovered,
            entropyByteCount: inferredEntropyByteCount(from: recovered.bytes)
        )
    }

    /// Derives profile `i` at the required hardened BIP-32 path `m/0'/i'`.
    ///
    /// Profile zero is the BRC-100 wallet root key. An empty BIP-39 passphrase is the interoperable
    /// default; callers supporting a non-empty passphrase must back it up as a separate secret.
    public func profileKey(index: UInt32, passphrase: String = "") throws -> PrivateKey {
        guard index < HDChildNumber.hardenedOffset else {
            throw BRC157Error.invalidProfileIndex(index)
        }
        let seed = try mnemonic.seed(passphrase: passphrase)
        let master = try ExtendedPrivateKey(seed: seed.bytes, network: .mainnet)
        let profiles = try master.derived(.hardened(0))
        return try profiles.derived(.hardened(index)).key
    }

    /// Derives profile zero, the private counterparty to the BRC-100 identity key.
    public func rootKey(passphrase: String = "") throws -> PrivateKey {
        try profileKey(index: 0, passphrase: passphrase)
    }

    /// A redacted description safe for interpolation and diagnostic logging.
    public var description: String { "<redacted BRC-157 entropy>" }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(reflecting: description) }

    private static func inferredEntropyByteCount(from paddedEntropy: [UInt8]) -> Int {
        let leadingZeroCount = paddedEntropy.prefix(while: { $0 == 0 }).count
        let significantByteCount = Self.scalarByteCount - leadingZeroCount
        let rounded = ((significantByteCount + 3) / 4) * 4
        return min(Self.scalarByteCount, max(16, rounded))
    }
}
