import Foundation

/// RFC 8785 JSON Canonicalization Scheme serialization for the toolbox's JSON value type.
enum JCS {
    static func serialize(_ value: BRC38JSONValue) throws -> String {
        switch value {
        case .null:
            return "null"
        case .bool(let value):
            return value ? "true" : "false"
        case .number(let value):
            return try number(value)
        case .string(let value):
            return string(value)
        case .array(let values):
            return "[" + (try values.map(serialize)).joined(separator: ",") + "]"
        case .object(let object):
            let entries = try object.canonicalMembers.map { member in
                string(member.property.name) + ":" + (try serialize(member.value))
            }
            return "{" + entries.joined(separator: ",") + "}"
        }
    }

    private static func string(_ value: String) -> String {
        var result = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x08: result += "\\b"
            case 0x09: result += "\\t"
            case 0x0a: result += "\\n"
            case 0x0c: result += "\\f"
            case 0x0d: result += "\\r"
            case 0x22: result += "\\\""
            case 0x5c: result += "\\\\"
            case 0x00 ... 0x1f:
                result += String(format: "\\u%04x", scalar.value)
            default:
                result.unicodeScalars.append(scalar)
            }
        }
        return result + "\""
    }

    /// Swift and ECMAScript both use shortest-round-trip binary64 formatting. Their only material
    /// difference here is decimal/scientific notation selection and exponent spelling.
    private static func number(_ value: Double) throws -> String {
        guard value.isFinite else { throw BRC38Error.canonicalization }
        if value == 0 { return "0" }

        let description = String(value)
        guard let exponentIndex = description.firstIndex(where: { $0 == "e" || $0 == "E" }) else {
            return description.hasSuffix(".0") ? String(description.dropLast(2)) : description
        }

        let mantissa = String(description[..<exponentIndex])
        guard let exponent = Int(description[description.index(after: exponentIndex)...]) else {
            throw BRC38Error.canonicalization
        }
        if exponent >= -6 && exponent < 21 {
            return decimal(mantissa: mantissa, exponent: exponent)
        }
        let normalizedMantissa = mantissa.hasSuffix(".0") ? String(mantissa.dropLast(2)) : mantissa
        return normalizedMantissa + "e" + (exponent >= 0 ? "+" : "") + String(exponent)
    }

    private static func decimal(mantissa: String, exponent: Int) -> String {
        let negative = mantissa.hasPrefix("-")
        let unsigned = negative ? String(mantissa.dropFirst()) : mantissa
        let digits = unsigned.replacingOccurrences(of: ".", with: "")
        let point = exponent + 1
        let result: String
        if point <= 0 {
            result = "0." + String(repeating: "0", count: -point) + digits
        } else if point >= digits.count {
            result = digits + String(repeating: "0", count: point - digits.count)
        } else {
            let index = digits.index(digits.startIndex, offsetBy: point)
            result = String(digits[..<index]) + "." + String(digits[index...])
        }
        return negative ? "-" + result : result
    }

    static func utf16Less(_ left: String, _ right: String) -> Bool {
        Array(left.utf16).lexicographicallyPrecedes(Array(right.utf16))
    }
}
