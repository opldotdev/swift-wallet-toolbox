import Foundation

/// Reading a storage response written with the binary JSON encoding (`BinaryJson.ts`).
///
/// A store that receives `X-BSV-Binary-Encoding: base64` writes the response with
/// `JSON.stringify(payload, binaryJsonReplacer)` and echoes the header. Bytes then arrive as
/// `{"$bsvBinary":"base64","data":<base64>}`, and an object that would itself read as one of those
/// markers arrives escaped as `{"$bsvBinary":"escaped","entries":[[key, value], ...]}`. The
/// reference client reads such a body with `parseJsonRpc(text, true)`, which applies
/// `binaryJsonReviver` bottom-up: children first, then the value holding them.
public extension JSONValue {
    /// This value with the binary encoding's markers read back, as `parseJsonRpc(text, true)` does.
    ///
    /// Bytes come back as the array of numbers the storage protocol always carried them as, so
    /// every reader of a byte field reads either encoding. An escaped object comes back as the
    /// object it stood for, and that object is not read again: a literal value shaped like a
    /// marker stays the literal value. A tagged value whose data is not padded, canonical base64
    /// is refused, as `fromBase64` refuses it.
    func decodingBinary() throws -> JSONValue {
        switch self {
        case .array(let values):
            return .array(try values.map { try $0.decodingBinary() })
        case .object(let members):
            var revived: [String: JSONValue] = [:]
            revived.reserveCapacity(members.count)
            for (key, value) in members {
                revived[key] = try value.decodingBinary()
            }
            if let bytes = try Self.taggedBytes(revived) {
                return .array(bytes.map { .number(Double($0)) })
            }
            if let restored = Self.escapedObject(revived) {
                return .object(restored)
            }
            return .object(revived)
        case .null, .bool, .number, .string:
            return self
        }
    }

    /// The marker key of the binary encoding.
    private static let binaryTag = "$bsvBinary"

    /// `isTaggedBinary` then `fromBase64`: exactly two members, the tag `base64` and string data.
    private static func taggedBytes(_ members: [String: JSONValue]) throws -> [UInt8]? {
        guard members.count == 2, members[binaryTag] == .string("base64"),
              case .string(let data)? = members["data"] else {
            return nil
        }
        guard let bytes = BinaryJSONBase64.decode(data) else {
            throw BinaryJSONError.invalidBase64
        }
        return bytes
    }

    /// `isEscapedJson` then `Object.fromEntries`: exactly two members, the tag `escaped` and an
    /// array of `[string, value]` pairs. A repeated key keeps its last value, as `fromEntries` does.
    private static func escapedObject(_ members: [String: JSONValue]) -> [String: JSONValue]? {
        guard members.count == 2, members[binaryTag] == .string("escaped"),
              case .array(let entries)? = members["entries"] else {
            return nil
        }
        var restored: [String: JSONValue] = [:]
        for entry in entries {
            guard case .array(let pair) = entry, pair.count == 2,
                  case .string(let key) = pair[0] else {
                return nil
            }
            restored[key] = pair[1]
        }
        return restored
    }
}

public enum BinaryJSONError: Error, Equatable, Sendable, LocalizedError {
    /// A `{"$bsvBinary":"base64"}` value whose data is not padded, canonical base64.
    case invalidBase64

    public var errorDescription: String? {
        switch self {
        case .invalidBase64: "Invalid base64 binary JSON value"
        }
    }
}

/// `validateBase64` and `fromBase64` from `BinaryJson.ts`.
enum BinaryJSONBase64 {
    /// Each byte's value in the standard alphabet, or -1.
    private static let values: [Int] = {
        var table = [Int](repeating: -1, count: 256)
        for (value, character) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .utf8.enumerated() {
            table[Int(character)] = value
        }
        return table
    }()
    private static let equals = UInt8(ascii: "=")

    /// The bytes of `text`, or `nil` unless it is a multiple of four characters from the standard
    /// alphabet, padded with at most two `=`, whose unused trailing bits are zero.
    static func decode(_ text: String) -> [UInt8]? {
        let characters = Array(text.utf8)
        guard characters.count % 4 == 0 else { return nil }
        var padding = 0
        if characters.count >= 2, characters[characters.count - 1] == equals,
           characters[characters.count - 2] == equals {
            padding = 2
        } else if characters.last == equals {
            padding = 1
        }
        let content = characters.count - padding
        var last = 0
        for index in 0..<content {
            let value = values[Int(characters[index])]
            guard value >= 0 else { return nil }
            last = value
        }
        if padding == 1, last & 3 != 0 { return nil }
        if padding == 2, last & 15 != 0 { return nil }
        guard let data = Data(base64Encoded: text) else { return nil }
        return Array(data)
    }
}
