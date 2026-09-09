import Foundation
import ToolboxCore

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Resolves paymail capabilities and delivers payments to the recipient's host.
///
/// Capability documents are cached by paymail domain on this instance. The cache is isolated in
/// an actor because callers may resolve more than one payment concurrently.
public struct Paymail: Sendable {
    private static let destinationCapability = "2a40af698840"
    private static let receiveBEEFCapability = "5c55a7fdb7bb"
    private static let maximumJSONBytes = 16 << 20
    private static let maximumHexCharacters = 32 << 20

    private let http: any PaymailHTTP
    private let cache: CapabilityCache

    public init(http: any PaymailHTTP = URLSessionPaymailHTTP()) {
        self.http = http
        self.cache = CapabilityCache()
    }

    public static func isPaymail(_ text: String) -> Bool {
        text.range(
            of: #"^[^\s@]+@[^\s@]+\.[^\s@]+$"#,
            options: .regularExpression
        ) != nil
    }

    /// Read-only recipient discovery. Does not request outputs or submit a transaction.
    /// The public-profile capability supplies name/avatar; PKI is the fallback
    /// for providers without public profiles. A network failure is never a valid recipient.
    public func validateRecipient(paymail: String) async throws -> String? {
        try await recipientProfile(paymail: paymail).name
    }

    public func recipientProfile(paymail: String) async throws -> PaymailProfile {
        let address = try Self.parse(paymail)
        let capabilities = try await capabilities(for: address)
        let profile = capabilities["f12f968c92d6"]
        guard let template = profile ?? capabilities["pki"] else {
            throw PaymailError.capabilityUnsupported(domain: address.domain, capability: "recipient verification")
        }
        let response = try await http.get(Self.capabilityURL(template: template, address: address))
        guard (200..<300).contains(response.status) else {
            throw PaymailError.httpFailure(statusCode: response.status)
        }
        guard response.body.count <= Self.maximumJSONBytes,
              let value = try? JSONDecoder().decode(JSONValue.self, from: Data(response.body)) else {
            throw PaymailError.unreadableResponse
        }
        if profile != nil {
            guard let name = value["name"]?.stringValue,
                  !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw PaymailError.unreadableResponse
            }
            let avatar = value["avatar"]?.stringValue
                .flatMap { URL(string: $0.replacingOccurrences(of: "{?s}", with: "?s=180")) }
                .flatMap { $0.scheme?.lowercased() == "https" && $0.host != nil ? $0 : nil }
            return PaymailProfile(name: name, avatar: avatar)
        }
        guard let key = value["pubkey"]?.stringValue,
              key.count == 66, key.hasPrefix("02") || key.hasPrefix("03"),
              key.allSatisfy({ $0.isHexDigit }) else {
            throw PaymailError.unreadableResponse
        }
        return PaymailProfile(name: nil, avatar: nil)
    }

    /// Resolves outputs to pay `paymail` for `satoshis`. The returned reference must be used when
    /// the signed transaction is delivered.
    public func paymentDestination(
        paymail: String,
        satoshis: UInt64
    ) async throws -> PaymentDestination {
        let address = try Self.parse(paymail)
        let capabilities = try await capabilities(for: address)
        guard let template = capabilities[Self.destinationCapability] else {
            throw PaymailError.capabilityUnsupported(
                domain: address.domain,
                capability: Self.destinationCapability
            )
        }

        let url = try Self.capabilityURL(template: template, address: address)
        let body = try JSONEncoder().encode(SatoshisRequest(satoshis: satoshis))
        let response = try await http.post(url, json: Array(body))
        guard (200..<300).contains(response.status) else {
            throw PaymailError.httpFailure(statusCode: response.status)
        }
        return try Self.decodeDestination(response.body)
    }

    /// Delivers an Atomic BEEF transaction to the recipient's paymail host.
    ///
    /// Only the receive-BEEF capability is used. The older receive-transaction capability
    /// (`5f1323cddf31`) takes a different request — the raw transaction under `hex`, with a metadata
    /// object — not the BEEF this method holds, so sending the BEEF body there always fails. A host
    /// that does not advertise receive-BEEF is refused here rather than sent a request it cannot
    /// accept.
    public func deliver(beef: [UInt8], to paymail: String, reference: String) async throws {
        let address = try Self.parse(paymail)
        let capabilities = try await capabilities(for: address)
        guard let template = capabilities[Self.receiveBEEFCapability] else {
            throw PaymailError.capabilityUnsupported(
                domain: address.domain,
                capability: Self.receiveBEEFCapability
            )
        }

        let url = try Self.capabilityURL(template: template, address: address)
        let request = DeliveryRequest(beef: Self.hex(beef), reference: reference)
        let body = try JSONEncoder().encode(request)
        let response = try await http.post(url, json: Array(body))
        guard (200..<300).contains(response.status) else {
            throw PaymailError.deliveryFailed(statusCode: response.status)
        }
    }

    private func capabilities(for address: Address) async throws -> [String: String] {
        if let cached = await cache.value(for: address.domain) {
            return cached
        }

        let endpoint = try await serviceEndpoint(for: address.domain)
        let url = try Self.httpsURL(
            host: endpoint.host,
            port: endpoint.port,
            path: "/.well-known/bsvalias"
        )
        let response = try await http.get(url)
        guard (200..<300).contains(response.status) else {
            throw PaymailError.httpFailure(statusCode: response.status)
        }
        let capabilities = try Self.decodeCapabilities(response.body)
        await cache.store(capabilities, for: address.domain)
        return capabilities
    }

    private func serviceEndpoint(for domain: String) async throws -> ServiceEndpoint {
        guard var components = URLComponents(string: "https://dns.google.com/resolve") else {
            throw PaymailError.unreadableResponse
        }
        components.queryItems = [
            URLQueryItem(name: "name", value: "_bsvalias._tcp.\(domain)"),
            URLQueryItem(name: "type", value: "SRV"),
            URLQueryItem(name: "cd", value: "0"),
        ]
        guard let url = components.url else {
            throw PaymailError.unreadableResponse
        }

        let response = try await http.get(url)
        guard (200..<300).contains(response.status) else {
            throw PaymailError.httpFailure(statusCode: response.status)
        }
        guard response.body.count <= Self.maximumJSONBytes,
              let value = try? JSONDecoder().decode(JSONValue.self, from: Data(response.body)),
              let status = value["Status"]?.intValue else {
            throw PaymailError.unreadableResponse
        }

        let fallback = ServiceEndpoint(host: domain, port: 443)
        if status == 3 {
            return fallback
        }
        guard let answerValue = value["Answer"] else {
            return fallback
        }
        guard let answers = answerValue.arrayValue else {
            throw PaymailError.unreadableResponse
        }
        guard let first = answers.first else {
            return fallback
        }
        guard let data = first["data"]?.stringValue else {
            throw PaymailError.unreadableResponse
        }

        let fields = data.split(separator: " ")
        guard fields.count >= 4, let port = Int(fields[2]) else {
            throw PaymailError.unreadableResponse
        }
        let target = Self.withoutTrailingDot(String(fields[3])).lowercased()
        let originalDomain = Self.withoutTrailingDot(domain).lowercased()
        let dnssecValidated = value["AD"]?.boolValue == true
        // Paymail Host Discovery permits unsigned records only for the domain
        // itself or www.domain, not arbitrary subdomains or suffix matches.
        guard dnssecValidated || target == originalDomain || target == "www.\(originalDomain)" else {
            return fallback
        }
        return ServiceEndpoint(host: target, port: port)
    }

    private static func parse(_ paymail: String) throws -> Address {
        guard isPaymail(paymail), let separator = paymail.firstIndex(of: "@") else {
            throw PaymailError.notAPaymail(paymail)
        }
        let alias = String(paymail[..<separator])
        let domain = String(paymail[paymail.index(after: separator)...]).lowercased()
        return Address(alias: alias, domain: domain)
    }

    private static func decodeCapabilities(_ body: [UInt8]) throws -> [String: String] {
        guard body.count <= maximumJSONBytes,
              let value = try? JSONDecoder().decode(JSONValue.self, from: Data(body)),
              let object = value["capabilities"]?.objectValue else {
            throw PaymailError.unreadableResponse
        }

        var capabilities: [String: String] = [:]
        capabilities.reserveCapacity(object.count)
        for (identifier, value) in object {
            // BRFC extensions may contain flags or structured configuration.
            // This resolver consumes endpoint templates only; unrelated values
            // must not invalidate the standard endpoints.
            guard let template = value.stringValue else { continue }
            capabilities[identifier] = template
        }
        return capabilities
    }

    private static func decodeDestination(_ body: [UInt8]) throws -> PaymentDestination {
        guard body.count <= maximumJSONBytes,
              let value = try? JSONDecoder().decode(JSONValue.self, from: Data(body)),
              let reference = value["reference"]?.stringValue,
              !reference.isEmpty,
              let rows = value["outputs"]?.arrayValue else {
            throw PaymailError.unreadableResponse
        }

        let outputs = try rows.map { row in
            guard let script = row["script"]?.stringValue,
                  let amount = row["satoshis"]?.doubleValue,
                  amount.isFinite,
                  let satoshis = UInt64(exactly: amount) else {
                throw PaymailError.unreadableResponse
            }
            return PaymailOutput(lockingScript: try decodeHex(script), satoshis: satoshis)
        }
        return PaymentDestination(reference: reference, outputs: outputs)
    }

    private static func decodeHex(_ text: String) throws -> [UInt8] {
        let characters = text.utf8
        guard characters.count <= maximumHexCharacters, characters.count.isMultiple(of: 2) else {
            throw PaymailError.unreadableResponse
        }

        var result: [UInt8] = []
        result.reserveCapacity(characters.count / 2)
        var iterator = characters.makeIterator()
        while let highCharacter = iterator.next() {
            guard let lowCharacter = iterator.next(),
                  let high = hexNibble(highCharacter),
                  let low = hexNibble(lowCharacter) else {
                throw PaymailError.unreadableResponse
            }
            result.append((high << 4) | low)
        }
        return result
    }

    private static func hexNibble(_ character: UInt8) -> UInt8? {
        switch character {
        case 48...57: character - 48
        case 65...70: character - 55
        case 97...102: character - 87
        default: nil
        }
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        let alphabet = Array("0123456789abcdef".utf8)
        var result = [UInt8]()
        result.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            result.append(alphabet[Int(byte >> 4)])
            result.append(alphabet[Int(byte & 0x0f)])
        }
        return String(decoding: result, as: UTF8.self)
    }

    private static func capabilityURL(template: String, address: Address) throws -> URL {
        let rendered = template
            .replacingOccurrences(of: "{alias}", with: address.alias)
            .replacingOccurrences(of: "{domain.tld}", with: address.domain)
        guard let url = URL(string: rendered), url.scheme?.lowercased() == "https",
              url.host != nil, url.user == nil, url.password == nil else {
            throw PaymailError.unreadableResponse
        }
        return url
    }

    private static func httpsURL(host: String, port: Int, path: String) throws -> URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.port = port
        components.path = path
        guard let url = components.url else {
            throw PaymailError.unreadableResponse
        }
        return url
    }

    private static func withoutTrailingDot(_ value: String) -> String {
        value.last == "." ? String(value.dropLast()) : value
    }
}

public struct PaymailProfile: Equatable, Sendable {
    public let name: String?
    public let avatar: URL?
}

/// A resolved destination and the server reference required for later delivery.
public struct PaymentDestination: Equatable, Sendable {
    public let reference: String
    public let outputs: [PaymailOutput]
}

/// One output returned by a paymail payment-destination capability.
public struct PaymailOutput: Equatable, Sendable {
    public let lockingScript: [UInt8]
    public let satoshis: UInt64
}

/// GET and JSON POST operations, injectable so resolution can be tested without a network.
public protocol PaymailHTTP: Sendable {
    func get(_ url: URL) async throws -> (status: Int, body: [UInt8])
    func post(_ url: URL, json: [UInt8]) async throws -> (status: Int, body: [UInt8])
}

/// `URLSession` HTTP with bounded response bodies.
public struct URLSessionPaymailHTTP: PaymailHTTP {
    private let session: URLSession
    private let maximumResponseBytes: Int

    public init(session: URLSession = .shared, maximumResponseBytes: Int = 16 << 20) {
        self.session = session
        self.maximumResponseBytes = maximumResponseBytes
    }

    public func get(_ url: URL) async throws -> (status: Int, body: [UInt8]) {
#if canImport(Darwin)
        let (stream, response) = try await session.bytes(from: url)
        return try await read(stream: stream, response: response)
#else
        let (data, response) = try await session.data(from: url)
        return try read(data: data, response: response)
#endif
    }

    public func post(_ url: URL, json: [UInt8]) async throws -> (status: Int, body: [UInt8]) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(json)
#if canImport(Darwin)
        let (stream, response) = try await session.bytes(for: request)
        return try await read(stream: stream, response: response)
#else
        let (data, response) = try await session.data(for: request)
        return try read(data: data, response: response)
#endif
    }

#if canImport(Darwin)
    private func read(
        stream: URLSession.AsyncBytes,
        response: URLResponse
    ) async throws -> (status: Int, body: [UInt8]) {
        var body: [UInt8] = []
        body.reserveCapacity(min(maximumResponseBytes, 64 << 10))
        for try await byte in stream {
            body.append(byte)
            if body.count > maximumResponseBytes {
                throw PaymailError.unreadableResponse
            }
        }
        return ((response as? HTTPURLResponse)?.statusCode ?? 0, body)
    }
#else
    private func read(
        data: Data,
        response: URLResponse
    ) throws -> (status: Int, body: [UInt8]) {
        guard data.count <= maximumResponseBytes else {
            throw PaymailError.unreadableResponse
        }
        return ((response as? HTTPURLResponse)?.statusCode ?? 0, Array(data))
    }
#endif
}

public enum PaymailError: Error, Equatable, Sendable, LocalizedError {
    case notAPaymail(String)
    case capabilityUnsupported(domain: String, capability: String)
    case unreadableResponse
    case httpFailure(statusCode: Int)
    case deliveryFailed(statusCode: Int)

    public var errorDescription: String? {
        switch self {
        case .notAPaymail: "Enter a valid paymail address."
        case .capabilityUnsupported(let domain, let capability):
            "\(domain) does not advertise the required paymail service (\(capability))."
        case .unreadableResponse:
            "The paymail provider returned a response the wallet could not read."
        case .httpFailure(let status) where status == 404:
            "The paymail provider could not find that recipient or service. Check the address."
        case .httpFailure(let status):
            "The paymail provider could not complete the lookup (HTTP \(status)). Try again."
        case .deliveryFailed(let status):
            "The paymail provider did not accept the transaction delivery (HTTP \(status))."
        }
    }
}

private actor CapabilityCache {
    private var values: [String: [String: String]] = [:]

    func value(for domain: String) -> [String: String]? {
        values[domain]
    }

    func store(_ capabilities: [String: String], for domain: String) {
        values[domain] = capabilities
    }
}

private struct Address: Sendable {
    let alias: String
    let domain: String
}

private struct ServiceEndpoint: Sendable {
    let host: String
    let port: Int
}

private struct SatoshisRequest: Encodable, Sendable {
    let satoshis: UInt64
}

private struct DeliveryRequest: Encodable, Sendable {
    let beef: String
    let reference: String
}
