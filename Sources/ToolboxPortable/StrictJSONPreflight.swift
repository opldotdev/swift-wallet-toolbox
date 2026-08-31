import Foundation

/// A bounded JSON parser for the portable-data boundary.
///
/// Structural counters are checked before an array element, object member, or value is decoded and
/// before an object name enters the duplicate-detection set. This avoids asking Foundation to
/// allocate an unbounded object graph and preserves RFC 8785 property identity as raw UTF-16.
struct StrictJSONPreflight {
    private let bytes: [UInt8]
    private let limits: BRC38Limits
    private var offset = 0
    private var valueCount = 0
    private var objectMemberCount = 0
    private var arrayElementCount = 0

    static func decode(_ bytes: [UInt8], limits: BRC38Limits) throws -> BRC38JSONValue {
        var parser = StrictJSONPreflight(bytes: bytes, limits: limits)
        let value = try parser.value(depth: 0)
        parser.whitespace()
        guard parser.offset == bytes.count else { throw BRC38Error.invalidJSON }
        return value
    }

    private mutating func value(depth: Int) throws -> BRC38JSONValue {
        guard depth <= BRC38JSONValue.maximumDepth else { throw BRC38Error.invalidJSON }
        try countValue()
        whitespace()
        guard let byte = peek else { throw BRC38Error.invalidJSON }
        switch byte {
        case 0x7b: return .object(try object(depth: depth + 1)) // {
        case 0x5b: return .array(try array(depth: depth + 1)) // [
        case 0x22: return .string(try string())
        case 0x74:
            try literal([0x74, 0x72, 0x75, 0x65])
            return .bool(true)
        case 0x66:
            try literal([0x66, 0x61, 0x6c, 0x73, 0x65])
            return .bool(false)
        case 0x6e:
            try literal([0x6e, 0x75, 0x6c, 0x6c])
            return .null
        case 0x2d, 0x30 ... 0x39:
            return .number(try number())
        default:
            throw BRC38Error.invalidJSON
        }
    }

    private mutating func object(depth: Int) throws -> BRC38JSONObject {
        try consume(0x7b)
        whitespace()
        if take(0x7d) { return BRC38JSONObject(uncheckedMembers: []) }

        var rawNames = Set<[UInt16]>()
        var members: [BRC38JSONMember] = []
        while true {
            whitespace()
            try countObjectMember()
            let name = try string()
            let rawName = Array(name.utf16)
            guard rawNames.insert(rawName).inserted else {
                throw BRC38Error.duplicateJSONKey(name)
            }
            whitespace()
            try consume(0x3a)
            let child = try value(depth: depth)
            members.append(BRC38JSONMember(
                property: BRC38JSONProperty(name: name, utf16: rawName),
                value: child
            ))
            whitespace()
            if take(0x7d) { return BRC38JSONObject(uncheckedMembers: members) }
            try consume(0x2c)
        }
    }

    private mutating func array(depth: Int) throws -> [BRC38JSONValue] {
        try consume(0x5b)
        whitespace()
        if take(0x5d) { return [] }

        var values: [BRC38JSONValue] = []
        while true {
            try countArrayElement()
            values.append(try value(depth: depth))
            whitespace()
            if take(0x5d) { return values }
            try consume(0x2c)
        }
    }

    /// Foundation performs Unicode and surrogate validation for this single string token.
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

    private mutating func number() throws -> Double {
        let start = offset
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
        guard let value = Double(String(decoding: bytes[start ..< offset], as: UTF8.self)),
              value.isFinite
        else { throw BRC38Error.invalidJSON }
        return value
    }

    private mutating func countValue() throws {
        guard valueCount < limits.maximumTotalValueCount else {
            throw BRC38Error.tooManyJSONValues(maximum: limits.maximumTotalValueCount)
        }
        valueCount += 1
    }

    private mutating func countObjectMember() throws {
        guard objectMemberCount < limits.maximumTotalObjectMemberCount else {
            throw BRC38Error.tooManyJSONObjectMembers(maximum: limits.maximumTotalObjectMemberCount)
        }
        objectMemberCount += 1
    }

    private mutating func countArrayElement() throws {
        guard arrayElementCount < limits.maximumTotalArrayElementCount else {
            throw BRC38Error.tooManyJSONArrayElements(maximum: limits.maximumTotalArrayElementCount)
        }
        arrayElementCount += 1
    }

    private mutating func digits() {
        while let byte = peek, byte >= 0x30, byte <= 0x39 { offset += 1 }
    }

    private mutating func literal(_ expected: [UInt8]) throws {
        guard expected.count <= bytes.count - offset,
              bytes[offset ..< offset + expected.count].elementsEqual(expected)
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
