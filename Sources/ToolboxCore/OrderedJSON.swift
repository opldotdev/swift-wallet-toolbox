import Foundation

/// A JSON value whose object members keep the order they were written in.
///
/// `JSONValue` models an object as a dictionary, which is right for reading a response and wrong
/// for anything whose bytes are hashed. The action-batch manifest is one: storage recomputes its
/// digest from `JSON.stringify` of the manifest *as it received it*, so the key order this client
/// sends for each planned input, output and metadata object must be the key order it hashed.
/// A dictionary cannot promise that; this type can.
///
/// `serialized()` writes exactly what ECMAScript's `JSON.stringify` writes for the same value: no
/// whitespace, members in insertion order, the same string escapes, and integral numbers without
/// a fraction or exponent.
public enum OrderedJSON: Equatable, Sendable {
    case null
    case bool(Bool)
    /// An integer, written in plain decimal. Wallet amounts, indexes and lengths all fit.
    case integer(Int64)
    /// Any other number. Integral values within ±1e21 are written as integers, as JavaScript does.
    case number(Double)
    case string(String)
    case array([OrderedJSON])
    case object([Member])

    public struct Member: Equatable, Sendable {
        public let key: String
        public let value: OrderedJSON

        public init(_ key: String, _ value: OrderedJSON) {
            self.key = key
            self.value = value
        }
    }

    /// How deep a parsed document may nest, matching `JSONValue`.
    public static let maximumDepth = JSONValue.maximumDepth
}

// MARK: - Building

public extension OrderedJSON {
    /// An object from `(key, value)` pairs, in order. A `nil` value is left out, which is what
    /// `JSON.stringify` does with a member whose value is `undefined`.
    static func record(_ pairs: KeyValuePairs<String, OrderedJSON?>) -> OrderedJSON {
        .object(pairs.compactMap { pair in pair.value.map { Member(pair.key, $0) } })
    }

    static func int<T: BinaryInteger>(_ value: T) -> OrderedJSON {
        .integer(Int64(value))
    }

    static func strings(_ values: [String]) -> OrderedJSON {
        .array(values.map { .string($0) })
    }

    /// Bytes the way the storage protocol carries them: a JSON array of numbers.
    static func bytes(_ values: [UInt8]) -> OrderedJSON {
        .array(values.map { .integer(Int64($0)) })
    }

    var members: [Member]? {
        if case .object(let members) = self { return members }
        return nil
    }

    var arrayValue: [OrderedJSON]? {
        if case .array(let values) = self { return values }
        return nil
    }

    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    var int64Value: Int64? {
        switch self {
        case .integer(let value): value
        case .number(let value): Int64(exactly: value)
        default: nil
        }
    }

    /// The value of the first member named `key`.
    subscript(key: String) -> OrderedJSON? {
        members?.first(where: { $0.key == key })?.value
    }

    /// JavaScript's `{ ...object, [key]: value }`.
    ///
    /// An existing member keeps its position and takes the new value; a new member goes last. A
    /// `nil` value is `undefined`: the member stays in place in the JavaScript object but
    /// `JSON.stringify` leaves it out, so here it is removed. Applying this to a non-object
    /// returns the value unchanged.
    func setting(_ key: String, _ value: OrderedJSON?) -> OrderedJSON {
        guard case .object(var members) = self else { return self }
        if let index = members.firstIndex(where: { $0.key == key }) {
            if let value {
                members[index] = Member(key, value)
            } else {
                members.remove(at: index)
            }
        } else if let value {
            members.append(Member(key, value))
        }
        return .object(members)
    }

    /// Converts an unordered value, with members in the order `JSON.stringify(JSON.parse(text))`
    /// writes them back.
    ///
    /// A JavaScript object lists array-index keys (`"0"`, `"7"`, `"10"`) first, ascending by value,
    /// whatever order they were parsed in; the other keys keep their parse order. So the index
    /// keys come first here too, and the rest are sorted so the result is stable. A server that
    /// re-serialises what it parsed then writes exactly these bytes.
    init(_ value: JSONValue) {
        switch value {
        case .null: self = .null
        case .bool(let flag): self = .bool(flag)
        case .number(let number):
            if let integral = Int64(exactly: number) {
                self = .integer(integral)
            } else {
                self = .number(number)
            }
        case .string(let text): self = .string(text)
        case .array(let values): self = .array(values.map(OrderedJSON.init))
        case .object(let members):
            self = .object(Self.javaScriptKeyOrder(members.keys).map {
                Member($0, OrderedJSON(members[$0]!))
            })
        }
    }

    /// ECMAScript `OrdinaryOwnPropertyKeys`: array indexes (canonical decimal below 2³² − 1)
    /// ascending by value, then every other key. With no parse order to keep, those are sorted.
    static func javaScriptKeyOrder(_ keys: some Collection<String>) -> [String] {
        var indexes: [(UInt32, String)] = []
        var names: [String] = []
        for key in keys {
            if let index = UInt32(key), index != .max, String(index) == key {
                indexes.append((index, key))
            } else {
                names.append(key)
            }
        }
        return indexes.sorted { $0.0 < $1.0 }.map { $0.1 } + names.sorted()
    }

    /// The unordered form, for code that reads values by key.
    var jsonValue: JSONValue {
        switch self {
        case .null: .null
        case .bool(let flag): .bool(flag)
        case .integer(let value): .number(Double(value))
        case .number(let value): .number(value)
        case .string(let text): .string(text)
        case .array(let values): .array(values.map(\.jsonValue))
        case .object(let members):
            .object(Dictionary(members.map { ($0.key, $0.value.jsonValue) }) { first, _ in first })
        }
    }
}

// MARK: - Writing

public extension OrderedJSON {
    /// The `JSON.stringify` text of this value.
    func serialized() -> String {
        var output = ""
        write(into: &output)
        return output
    }

    /// The UTF-8 bytes of `serialized()`, which is what the manifest digest hashes.
    func utf8Bytes() -> [UInt8] {
        Array(serialized().utf8)
    }

    private func write(into output: inout String) {
        switch self {
        case .null:
            output += "null"
        case .bool(let flag):
            output += flag ? "true" : "false"
        case .integer(let value):
            output += String(value)
        case .number(let value):
            output += Self.javaScriptNumber(value)
        case .string(let text):
            Self.writeString(text, into: &output)
        case .array(let values):
            output += "["
            for (index, value) in values.enumerated() {
                if index > 0 { output += "," }
                value.write(into: &output)
            }
            output += "]"
        case .object(let members):
            output += "{"
            for (index, member) in members.enumerated() {
                if index > 0 { output += "," }
                Self.writeString(member.key, into: &output)
                output += ":"
                member.value.write(into: &output)
            }
            output += "}"
        }
    }

    /// ECMAScript `QuoteJSONString`: the two-character escapes for `"`, `\`, backspace, form
    /// feed, newline, carriage return and tab; `\u00xx` in lowercase hex for every other control
    /// character; everything else, `/` and non-ASCII included, written as itself.
    private static func writeString(_ text: String, into output: inout String) {
        output += "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": output += "\\\""
            case "\\": output += "\\\\"
            case "\u{08}": output += "\\b"
            case "\u{0C}": output += "\\f"
            case "\n": output += "\\n"
            case "\r": output += "\\r"
            case "\t": output += "\\t"
            default:
                if scalar.value < 0x20 {
                    let hex = String(scalar.value, radix: 16)
                    output += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
                } else {
                    output.unicodeScalars.append(scalar)
                }
            }
        }
        output += "\""
    }

    /// `Number::toString` (ECMA-262 6.1.6.1.20), as `JSON.stringify` writes numbers. Non-finite
    /// numbers are `null`, as `JSON.stringify` writes them.
    ///
    /// The shortest round-trip digits come from Swift's own description, which picks the same
    /// digits as JavaScript; only the layout (where the decimal point goes, and when an exponent
    /// is used) is JavaScript's.
    private static func javaScriptNumber(_ value: Double) -> String {
        guard value.isFinite else { return "null" }
        if value == 0 { return "0" }
        let text = "\(value.magnitude)"
        var mantissa = Substring(text)
        var exponent = 0
        if let marker = text.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            mantissa = text[..<marker]
            exponent = Int(text[text.index(after: marker)...]) ?? 0
        }
        let parts = mantissa.split(separator: ".", omittingEmptySubsequences: false)
        let integral = parts.first.map(String.init) ?? ""
        let fraction = parts.count > 1 ? String(parts[1]) : ""
        var digits = Array(integral + fraction)
        // value = 0.digits × 10^n, as the specification states it.
        var n = integral.count + exponent
        while digits.first == "0" {
            digits.removeFirst()
            n -= 1
        }
        while digits.last == "0" { digits.removeLast() }
        let k = digits.count
        let sign = value < 0 ? "-" : ""
        let all = String(digits)
        if k <= n, n <= 21 {
            return sign + all + String(repeating: "0", count: n - k)
        }
        if 0 < n, n <= 21 {
            return sign + String(digits[..<n]) + "." + String(digits[n...])
        }
        if -6 < n, n <= 0 {
            return sign + "0." + String(repeating: "0", count: -n) + all
        }
        let e = n - 1
        let exponentText = (e < 0 ? "-" : "+") + String(e.magnitude)
        if k == 1 { return sign + all + "e" + exponentText }
        return sign + String(digits[0]) + "." + String(digits[1...]) + "e" + exponentText
    }
}

// MARK: - Parsing

public extension OrderedJSON {
    /// Parses JSON text, keeping object members in document order.
    ///
    /// Depth-bounded like `JSONValue`. Numbers without a fraction or exponent that fit in 64 bits
    /// are integers; the rest are doubles.
    static func parse(_ bytes: [UInt8]) throws -> OrderedJSON {
        var parser = OrderedJSONParser(bytes: bytes)
        parser.skipWhitespace()
        let value = try parser.parseValue(depth: 0)
        parser.skipWhitespace()
        guard parser.isAtEnd else { throw OrderedJSONError.trailingData }
        return value
    }

    static func parse(_ text: String) throws -> OrderedJSON {
        try parse(Array(text.utf8))
    }
}

public enum OrderedJSONError: Error, Equatable, Sendable {
    case tooDeep
    case unexpectedEnd
    case unexpectedByte(offset: Int)
    case invalidString(offset: Int)
    case invalidNumber(offset: Int)
    case trailingData
}

private struct OrderedJSONParser {
    let bytes: [UInt8]
    var position = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    var isAtEnd: Bool { position >= bytes.count }

    mutating func skipWhitespace() {
        while position < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[position]) {
            position += 1
        }
    }

    mutating func parseValue(depth: Int) throws -> OrderedJSON {
        guard depth <= OrderedJSON.maximumDepth else { throw OrderedJSONError.tooDeep }
        guard position < bytes.count else { throw OrderedJSONError.unexpectedEnd }
        switch bytes[position] {
        case UInt8(ascii: "{"): return try parseObject(depth: depth)
        case UInt8(ascii: "["): return try parseArray(depth: depth)
        case UInt8(ascii: "\""): return .string(try parseString())
        case UInt8(ascii: "t"): try expect("true"); return .bool(true)
        case UInt8(ascii: "f"): try expect("false"); return .bool(false)
        case UInt8(ascii: "n"): try expect("null"); return .null
        default: return try parseNumber()
        }
    }

    mutating func expect(_ literal: String) throws {
        let expected = Array(literal.utf8)
        guard position + expected.count <= bytes.count,
              Array(bytes[position..<position + expected.count]) == expected else {
            throw OrderedJSONError.unexpectedByte(offset: position)
        }
        position += expected.count
    }

    mutating func parseObject(depth: Int) throws -> OrderedJSON {
        position += 1
        var members: [OrderedJSON.Member] = []
        skipWhitespace()
        if position < bytes.count, bytes[position] == UInt8(ascii: "}") {
            position += 1
            return .object(members)
        }
        while true {
            skipWhitespace()
            guard position < bytes.count, bytes[position] == UInt8(ascii: "\"") else {
                throw OrderedJSONError.unexpectedByte(offset: position)
            }
            let key = try parseString()
            skipWhitespace()
            guard position < bytes.count, bytes[position] == UInt8(ascii: ":") else {
                throw OrderedJSONError.unexpectedByte(offset: position)
            }
            position += 1
            skipWhitespace()
            members.append(OrderedJSON.Member(key, try parseValue(depth: depth + 1)))
            skipWhitespace()
            guard position < bytes.count else { throw OrderedJSONError.unexpectedEnd }
            if bytes[position] == UInt8(ascii: ",") { position += 1; continue }
            if bytes[position] == UInt8(ascii: "}") { position += 1; return .object(members) }
            throw OrderedJSONError.unexpectedByte(offset: position)
        }
    }

    mutating func parseArray(depth: Int) throws -> OrderedJSON {
        position += 1
        var values: [OrderedJSON] = []
        skipWhitespace()
        if position < bytes.count, bytes[position] == UInt8(ascii: "]") {
            position += 1
            return .array(values)
        }
        while true {
            skipWhitespace()
            values.append(try parseValue(depth: depth + 1))
            skipWhitespace()
            guard position < bytes.count else { throw OrderedJSONError.unexpectedEnd }
            if bytes[position] == UInt8(ascii: ",") { position += 1; continue }
            if bytes[position] == UInt8(ascii: "]") { position += 1; return .array(values) }
            throw OrderedJSONError.unexpectedByte(offset: position)
        }
    }

    mutating func parseString() throws -> String {
        let start = position
        position += 1
        var scalars = String.UnicodeScalarView()
        var raw: [UInt8] = []
        func flush() throws {
            guard !raw.isEmpty else { return }
            guard let text = String(bytes: raw, encoding: .utf8) else {
                throw OrderedJSONError.invalidString(offset: start)
            }
            scalars.append(contentsOf: text.unicodeScalars)
            raw.removeAll(keepingCapacity: true)
        }
        while true {
            guard position < bytes.count else { throw OrderedJSONError.unexpectedEnd }
            let byte = bytes[position]
            position += 1
            switch byte {
            case UInt8(ascii: "\""):
                try flush()
                return String(scalars)
            case UInt8(ascii: "\\"):
                try flush()
                guard position < bytes.count else { throw OrderedJSONError.unexpectedEnd }
                let escape = bytes[position]
                position += 1
                switch escape {
                case UInt8(ascii: "\""): scalars.append("\"")
                case UInt8(ascii: "\\"): scalars.append("\\")
                case UInt8(ascii: "/"): scalars.append("/")
                case UInt8(ascii: "b"): scalars.append("\u{08}")
                case UInt8(ascii: "f"): scalars.append("\u{0C}")
                case UInt8(ascii: "n"): scalars.append("\n")
                case UInt8(ascii: "r"): scalars.append("\r")
                case UInt8(ascii: "t"): scalars.append("\t")
                case UInt8(ascii: "u"):
                    var unit = try hexUnit(start: start)
                    if (0xD800...0xDBFF).contains(unit) {
                        guard position + 1 < bytes.count, bytes[position] == UInt8(ascii: "\\"),
                              bytes[position + 1] == UInt8(ascii: "u") else {
                            throw OrderedJSONError.invalidString(offset: start)
                        }
                        position += 2
                        let low = try hexUnit(start: start)
                        guard (0xDC00...0xDFFF).contains(low) else {
                            throw OrderedJSONError.invalidString(offset: start)
                        }
                        unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                    }
                    guard let scalar = Unicode.Scalar(unit) else {
                        throw OrderedJSONError.invalidString(offset: start)
                    }
                    scalars.append(scalar)
                default:
                    throw OrderedJSONError.invalidString(offset: start)
                }
            default:
                guard byte >= 0x20 else { throw OrderedJSONError.invalidString(offset: start) }
                raw.append(byte)
            }
        }
    }

    mutating func hexUnit(start: Int) throws -> UInt32 {
        guard position + 4 <= bytes.count,
              let text = String(bytes: bytes[position..<position + 4], encoding: .ascii),
              let unit = UInt32(text, radix: 16) else {
            throw OrderedJSONError.invalidString(offset: start)
        }
        position += 4
        return unit
    }

    mutating func parseNumber() throws -> OrderedJSON {
        let start = position
        while position < bytes.count,
              "+-0123456789.eE".utf8.contains(bytes[position]) {
            position += 1
        }
        guard Self.isJSONNumber(bytes[start..<position]),
              let text = String(bytes: bytes[start..<position], encoding: .ascii) else {
            throw OrderedJSONError.invalidNumber(offset: start)
        }
        if !text.contains(where: { $0 == "." || $0 == "e" || $0 == "E" }),
           let integral = Int64(text) {
            return .integer(integral)
        }
        guard let number = Double(text), number.isFinite else {
            throw OrderedJSONError.invalidNumber(offset: start)
        }
        return .number(number)
    }

    /// RFC 8259 `number`: `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
    static func isJSONNumber(_ text: ArraySlice<UInt8>) -> Bool {
        var index = text.startIndex
        func digits() -> Int {
            let first = index
            while index < text.endIndex, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(text[index]) {
                index += 1
            }
            return index - first
        }
        if index < text.endIndex, text[index] == UInt8(ascii: "-") { index += 1 }
        guard index < text.endIndex else { return false }
        if text[index] == UInt8(ascii: "0") {
            index += 1
        } else if digits() == 0 {
            return false
        }
        if index < text.endIndex, text[index] == UInt8(ascii: ".") {
            index += 1
            guard digits() > 0 else { return false }
        }
        if index < text.endIndex, text[index] == UInt8(ascii: "e") || text[index] == UInt8(ascii: "E") {
            index += 1
            if index < text.endIndex, text[index] == UInt8(ascii: "+") || text[index] == UInt8(ascii: "-") {
                index += 1
            }
            guard digits() > 0 else { return false }
        }
        return index == text.endIndex
    }
}
