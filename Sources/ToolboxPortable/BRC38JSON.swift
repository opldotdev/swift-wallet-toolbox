/// A BRC-38 JSON property name whose identity is its unescaped UTF-16 sequence.
///
/// Swift `String` equality applies Unicode canonical equivalence. RFC 8785 does not: it preserves
/// strings as-is and orders object names by raw UTF-16 code units. Keeping the units alongside the
/// convenient `String` spelling prevents distinct names such as `"é"` and `"e\u{301}"` from
/// collapsing.
public struct BRC38JSONProperty: Equatable, Sendable {
    public let name: String
    let utf16: [UInt16]

    public init(_ name: String) {
        self.name = name
        self.utf16 = Array(name.utf16)
    }

    init(name: String, utf16: [UInt16]) {
        self.name = name
        self.utf16 = utf16
    }

    public static func == (left: Self, right: Self) -> Bool {
        left.utf16 == right.utf16
    }
}

public struct BRC38JSONMember: Equatable, Sendable {
    public let property: BRC38JSONProperty
    public let value: BRC38JSONValue

    public init(property: BRC38JSONProperty, value: BRC38JSONValue) {
        self.property = property
        self.value = value
    }

    public init(name: String, value: BRC38JSONValue) {
        self.init(property: BRC38JSONProperty(name), value: value)
    }
}

/// An RFC 8785-compatible JSON object.
///
/// Members are kept in raw UTF-16 order, making equality deterministic without relying on Swift's
/// normalization-aware dictionaries. Duplicate raw names are rejected by the untrusted parser.
public struct BRC38JSONObject: Equatable, Sendable, ExpressibleByDictionaryLiteral, Sequence {
    private let members: [BRC38JSONMember]

    public init(dictionaryLiteral elements: (String, BRC38JSONValue)...) {
        self.init(uncheckedMembers: elements.map { BRC38JSONMember(name: $0.0, value: $0.1) })
    }

    public init(_ values: [String: BRC38JSONValue]) {
        self.init(uncheckedMembers: values.map { BRC38JSONMember(name: $0.key, value: $0.value) })
    }

    /// Creates an object without passing through a normalization-aware Swift dictionary.
    public init(members: [BRC38JSONMember]) throws {
        var names = Set<[UInt16]>()
        for member in members {
            guard names.insert(member.property.utf16).inserted else {
                throw BRC38Error.duplicateJSONKey(member.property.name)
            }
        }
        self.init(uncheckedMembers: members)
    }

    init(uncheckedMembers: [BRC38JSONMember]) {
        var names = Set<[UInt16]>()
        precondition(
            uncheckedMembers.allSatisfy { names.insert($0.property.utf16).inserted },
            "BRC-38 JSON object names must be unique by raw UTF-16"
        )
        members = uncheckedMembers.sorted {
            $0.property.utf16.lexicographicallyPrecedes($1.property.utf16)
        }
    }

    public var keys: [String] { members.map(\.property.name) }

    public subscript(_ name: String) -> BRC38JSONValue? {
        let units = Array(name.utf16)
        return members.first(where: { $0.property.utf16 == units })?.value
    }

    public struct Iterator: IteratorProtocol {
        private let members: [BRC38JSONMember]
        private var index = 0

        fileprivate init(_ members: [BRC38JSONMember]) { self.members = members }

        public mutating func next() -> (String, BRC38JSONValue)? {
            guard index < members.count else { return nil }
            defer { index += 1 }
            let member = members[index]
            return (member.property.name, member.value)
        }
    }

    public func makeIterator() -> Iterator { Iterator(members) }

    var canonicalMembers: [BRC38JSONMember] { members }
}

/// JSON values used at the BRC-38 portability boundary.
public indirect enum BRC38JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([BRC38JSONValue])
    case object(BRC38JSONObject)

    static let maximumDepth = 64
}

extension BRC38JSONValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral,
                          ExpressibleByBooleanLiteral, ExpressibleByNilLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(nilLiteral: ()) { self = .null }
}

public extension BRC38JSONValue {
    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var intValue: Int? {
        guard case .number(let value) = self else { return nil }
        return Int(exactly: value)
    }

    var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    var objectValue: BRC38JSONObject? {
        if case .object(let value) = self { return value }
        return nil
    }

    var arrayValue: [BRC38JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    subscript(key: String) -> BRC38JSONValue? { objectValue?[key] }
}
