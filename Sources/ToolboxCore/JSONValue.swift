import Foundation

/// A JSON value.
///
/// The storage protocol passes positional parameters of mixed type, which `[Any]` would model at
/// the cost of being neither `Sendable` nor `Codable`. This is the same thing with the types kept.
///
/// Decoding is depth-bounded. Server responses are untrusted input, and a document nested a
/// million levels deep is a stack overflow rather than a parse error — `swift-sdk` has no
/// unbounded decode path and this library does not introduce the first one.
public enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    /// JSON has one number type. Splitting it into integer and double cases would make
    /// `1` and `1.0` different values, and a server is free to send either.
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    /// How deep a decoded document may nest.
    public static let maximumDepth = 64
}

// MARK: - Convenience

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral,
                     ExpressibleByBooleanLiteral, ExpressibleByNilLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(nilLiteral: ()) { self = .null }
}

public extension JSONValue {
    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var intValue: Int? {
        guard case .number(let value) = self, value.rounded() == value else { return nil }
        return Int(value)
    }

    var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    subscript(key: String) -> JSONValue? { objectValue?[key] }
}

// MARK: - Coding

extension JSONValue: Codable {
    public init(from decoder: Decoder) throws {
        guard decoder.codingPath.count <= Self.maximumDepth else {
            throw JSONValueError.tooDeep
        }
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw JSONValueError.unrepresentable
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

public enum JSONValueError: Error, Equatable, Sendable {
    case tooDeep
    case unrepresentable
}
