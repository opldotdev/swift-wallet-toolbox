import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Somewhere to send bytes.
///
/// Declared here rather than taken from the SDK because the SDK's equivalent types are
/// `package`-scoped and deliberately not public. That is the SDK's decision to make; ours is not to
/// reach around it.
///
/// It is a protocol so a test can answer without a network. Every interesting failure in
/// authentication — a peer that refuses, a signature that does not verify, a reply to the wrong
/// request — has to be reproducible offline, and a concrete `URLSession` call is not.
public protocol HTTPTransport: Sendable {
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}

public struct HTTPRequest: Equatable, Sendable {
    public let method: String
    public let url: URL
    public let headers: [String: String]
    public let body: [UInt8]?

    public init(method: String, url: URL, headers: [String: String] = [:], body: [UInt8]? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

public struct HTTPResponse: Equatable, Sendable {
    public let statusCode: Int
    public let headers: [String: String]
    public let body: [UInt8]

    public init(statusCode: Int, headers: [String: String] = [:], body: [UInt8]) {
        self.statusCode = statusCode
        self.headers = headers
        self.body = body
    }

    /// Header lookup is case-insensitive, because HTTP header names are and a server is free to
    /// send `X-Bsv-Auth-Nonce` where the specification writes `x-bsv-auth-nonce`.
    public func header(_ name: String) -> String? {
        let wanted = name.lowercased()
        return headers.first { $0.key.lowercased() == wanted }?.value
    }
}

/// The real transport.
public struct URLSessionHTTPTransport: HTTPTransport {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        if let body = request.body {
            urlRequest.httpBody = Data(body)
        }

        let (data, response) = try await session.data(for: urlRequest)
        guard let http = response as? HTTPURLResponse else {
            throw AuthTransportError.transportFailed("the response was not HTTP")
        }
        var headers: [String: String] = [:]
        for (name, value) in http.allHeaderFields {
            if let name = name as? String, let value = value as? String {
                headers[name] = value
            }
        }
        return HTTPResponse(statusCode: http.statusCode, headers: headers, body: Array(data))
    }
}
