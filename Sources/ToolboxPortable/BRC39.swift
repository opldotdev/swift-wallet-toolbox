/// Resource and KDF bounds applied before a BRC-39 importer allocates memory or decrypts data.
public struct BRC39Limits: Equatable, Sendable {
    public let maximumFileByteCount: Int
    public let maximumIterations: UInt32
    public let maximumMemoryKiB: UInt32
    public let maximumParallelism: UInt8

    public init(
        maximumFileByteCount: Int,
        maximumIterations: UInt32,
        maximumMemoryKiB: UInt32,
        maximumParallelism: UInt8
    ) {
        self.maximumFileByteCount = maximumFileByteCount
        self.maximumIterations = maximumIterations
        self.maximumMemoryKiB = maximumMemoryKiB
        self.maximumParallelism = maximumParallelism
    }

    public static let standard = BRC39Limits(
        maximumFileByteCount: (64 << 20) + 97 + 16,
        maximumIterations: 32,
        maximumMemoryKiB: 1_048_576,
        maximumParallelism: 16
    )
}

public struct BRC39Header: Equatable, Sendable {
    public static let byteCount = 33
    public static let authenticationTagByteCount = 16
    public static let defaultIterations: UInt32 = 7
    public static let defaultMemoryKiB: UInt32 = 131_072
    public static let defaultParallelism: UInt8 = 1
    public static let derivedKeyByteCount: UInt8 = 32
    public static let defaultSaltByteCount: UInt8 = 32
    public static let defaultNonceByteCount: UInt8 = 32

    public let saltByteCount: UInt8
    public let nonceByteCount: UInt8
    public let iterations: UInt32
    public let memoryKiB: UInt32
    public let parallelism: UInt8
    public let derivedKeyByteCount: UInt8
}

/// A parsed BRC-39 password-protected BRC-38 envelope.
///
/// Parsing performs no password work. Callers can reject hostile sizes and KDF parameters before
/// invoking Argon2id or AES-GCM.
public struct BRC39Envelope: Equatable, Sendable {
    public let header: BRC39Header
    public let salt: [UInt8]
    public let nonce: [UInt8]
    public let ciphertext: [UInt8]
    public let authenticationTag: [UInt8]

    public static func parse(
        _ file: [UInt8],
        limits: BRC39Limits = .standard
    ) throws -> BRC39Envelope {
        guard limits.maximumFileByteCount > 0, file.count <= limits.maximumFileByteCount else {
            throw BRC39Error.fileTooLarge(maximumByteCount: limits.maximumFileByteCount)
        }
        guard file.count >= BRC39Header.byteCount else { throw BRC39Error.tooShort }
        guard Array(file[0 ..< 4]) == [0x57, 0x44, 0x41, 0x54] else {
            throw BRC39Error.badMagic
        }
        guard file[4] == 1 else { throw BRC39Error.unsupportedFormatVersion }
        guard file[5] == 1 else { throw BRC39Error.unsupportedProtectorType }
        guard file[6] == 38 else { throw BRC39Error.unsupportedInnerFormat }
        guard file[7] == 1 else { throw BRC39Error.unsupportedKDF }
        guard file[8] == 0 else { throw BRC39Error.invalidFlags }
        guard file[21 ..< BRC39Header.byteCount].allSatisfy({ $0 == 0 }) else {
            throw BRC39Error.nonzeroReservedBytes
        }

        let saltByteCount = file[9]
        let nonceByteCount = file[10]
        let iterations = uint32(file, at: 11)
        let memoryKiB = uint32(file, at: 15)
        let parallelism = file[19]
        let derivedKeyByteCount = file[20]
        guard saltByteCount > 0 else { throw BRC39Error.invalidSaltLength }
        guard nonceByteCount > 0 else { throw BRC39Error.invalidNonceLength }
        guard iterations > 0 else { throw BRC39Error.invalidIterations }
        guard memoryKiB > 0 else { throw BRC39Error.invalidMemory }
        guard parallelism > 0 else { throw BRC39Error.invalidParallelism }
        guard derivedKeyByteCount == 32 else { throw BRC39Error.invalidDerivedKeyLength }
        guard iterations <= limits.maximumIterations else { throw BRC39Error.iterationsTooLarge }
        guard memoryKiB <= limits.maximumMemoryKiB else { throw BRC39Error.memoryTooLarge }
        guard parallelism <= limits.maximumParallelism else { throw BRC39Error.parallelismTooLarge }

        let saltStart = BRC39Header.byteCount
        let nonceStart = saltStart + Int(saltByteCount)
        let payloadStart = nonceStart + Int(nonceByteCount)
        guard file.count > payloadStart + BRC39Header.authenticationTagByteCount else {
            throw BRC39Error.invalidCiphertext
        }
        let tagStart = file.count - BRC39Header.authenticationTagByteCount
        return BRC39Envelope(
            header: BRC39Header(
                saltByteCount: saltByteCount,
                nonceByteCount: nonceByteCount,
                iterations: iterations,
                memoryKiB: memoryKiB,
                parallelism: parallelism,
                derivedKeyByteCount: derivedKeyByteCount
            ),
            salt: Array(file[saltStart ..< nonceStart]),
            nonce: Array(file[nonceStart ..< payloadStart]),
            ciphertext: Array(file[payloadStart ..< tagStart]),
            authenticationTag: Array(file[tagStart...])
        )
    }

    private static func uint32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24
            | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8
            | UInt32(bytes[offset + 3])
    }
}

public enum BRC39Error: Error, Equatable, Sendable {
    case fileTooLarge(maximumByteCount: Int)
    case tooShort
    case badMagic
    case unsupportedFormatVersion
    case unsupportedProtectorType
    case unsupportedInnerFormat
    case unsupportedKDF
    case invalidFlags
    case nonzeroReservedBytes
    case invalidSaltLength
    case invalidNonceLength
    case invalidIterations
    case invalidMemory
    case invalidParallelism
    case invalidDerivedKeyLength
    case iterationsTooLarge
    case memoryTooLarge
    case parallelismTooLarge
    case invalidCiphertext
}
