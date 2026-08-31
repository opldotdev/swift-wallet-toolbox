import Foundation
import ToolboxCore

/// A bounded lexical pass that rejects duplicate object names before `JSONDecoder` loses them in a
/// Swift dictionary. RFC 8785 requires I-JSON input, whose object names are unique.
struct StrictJSONPreflight {
    private let bytes: [UInt8]
    private var offset = 0

    static func validate(_ bytes: [UInt8]) throws {
        var parser = StrictJSONPreflight(bytes: bytes)
        try parser.value(depth: 0)
        parser.whitespace()
        guard parser.offset == bytes.count else { throw BRC38Error.invalidJSON }
    }

    private mutating func value(depth: Int) throws {
        guard depth <= JSONValue.maximumDepth else { throw BRC38Error.invalidJSON }
        whitespace()
        guard let byte = peek else { throw BRC38Error.invalidJSON }
        switch byte {
        case 0x7b: try object(depth: depth + 1) // {
        case 0x5b: try array(depth: depth + 1) // [
        case 0x22: _ = try string()
        case 0x74: try literal([0x74, 0x72, 0x75, 0x65]) // true
        case 0x66: try literal([0x66, 0x61, 0x6c, 0x73, 0x65]) // false
        case 0x6e: try literal([0x6e, 0x75, 0x6c, 0x6c]) // null
        case 0x2d, 0x30 ... 0x39: try number()
        default: throw BRC38Error.invalidJSON
        }
    }

    private mutating func object(depth: Int) throws {
        try consume(0x7b)
        whitespace()
        if take(0x7d) { return }

        var rawNames = Set<[UInt16]>()
        var swiftNames = Set<String>()
        while true {
            whitespace()
            let name = try string()
            let rawName = Array(name.utf16)
            guard rawNames.insert(rawName).inserted else {
                throw BRC38Error.duplicateJSONKey(name)
            }
            // Swift String equality is normalization-aware. Reject a pair that Foundation would
            // collapse even though its UTF-16 names differ rather than silently losing a value.
            guard swiftNames.insert(name).inserted else {
                throw BRC38Error.ambiguousJSONKey(name)
            }
            whitespace()
            try consume(0x3a)
            try value(depth: depth)
            whitespace()
            if take(0x7d) { return }
            try consume(0x2c)
        }
    }

    private mutating func array(depth: Int) throws {
        try consume(0x5b)
        whitespace()
        if take(0x5d) { return }
        while true {
            try value(depth: depth)
            whitespace()
            if take(0x5d) { return }
            try consume(0x2c)
        }
    }

    /// Returns the decoded JSON string so escaped and literal spellings of one object name compare
    /// identically. Foundation performs the Unicode and surrogate validation for this one token.
    private mutating func string() throws -> String {
        let start = offset
        try consume(0x22)
        var escaped = false
        while let byte = peek {
            offset += 1
            if escaped {
                escaped = false
                continue
            }
            if byte == 0x5c {
                escaped = true
            } else if byte == 0x22 {
                let token = Data(bytes[start ..< offset])
                guard let decoded = try? JSONDecoder().decode(String.self, from: token) else {
                    throw BRC38Error.invalidJSON
                }
                return decoded
            } else if byte < 0x20 {
                throw BRC38Error.invalidJSON
            }
        }
        throw BRC38Error.invalidJSON
    }

    private mutating func number() throws {
        _ = take(0x2d)
        guard let first = peek else { throw BRC38Error.invalidJSON }
        if first == 0x30 {
            offset += 1
            if let next = peek, next >= 0x30, next <= 0x39 { throw BRC38Error.invalidJSON }
        } else {
            guard first >= 0x31, first <= 0x39 else { throw BRC38Error.invalidJSON }
            digits()
        }
        if take(0x2e) {
            guard let next = peek, next >= 0x30, next <= 0x39 else {
                throw BRC38Error.invalidJSON
            }
            digits()
        }
        if take(0x65) || take(0x45) {
            _ = take(0x2b) || take(0x2d)
            guard let next = peek, next >= 0x30, next <= 0x39 else {
                throw BRC38Error.invalidJSON
            }
            digits()
        }
    }

    private mutating func digits() {
        while let byte = peek, byte >= 0x30, byte <= 0x39 { offset += 1 }
    }

    private mutating func literal(_ expected: [UInt8]) throws {
        guard offset + expected.count <= bytes.count,
              Array(bytes[offset ..< offset + expected.count]) == expected
        else { throw BRC38Error.invalidJSON }
        offset += expected.count
    }

    private mutating func whitespace() {
        while let byte = peek, byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0d {
            offset += 1
        }
    }

    private var peek: UInt8? { offset < bytes.count ? bytes[offset] : nil }

    private mutating func take(_ byte: UInt8) -> Bool {
        guard peek == byte else { return false }
        offset += 1
        return true
    }

    private mutating func consume(_ byte: UInt8) throws {
        guard take(byte) else { throw BRC38Error.invalidJSON }
    }
}
