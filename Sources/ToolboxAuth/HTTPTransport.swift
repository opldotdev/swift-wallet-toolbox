import Foundation
import ToolboxCore

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
    private let maximumResponseBytes: Int

    /// - Parameter maximumResponseBytes: the response body is refused once it exceeds this. A
    ///   hostile or broken server can otherwise stream gigabytes, and the decoder's own limit
    ///   only applies after the whole thing has been buffered. 16 MiB is the reference
    ///   `SimplifiedFetchTransport`'s `DEFAULT_SIMPLIFIED_FETCH_MAX_RESPONSE_BYTES`, so a reply
    ///   the TypeScript client reads is one this one reads too.
    public init(session: URLSession = .shared, maximumResponseBytes: Int = 16 << 20) {
        self.session = session
        self.maximumResponseBytes = maximumResponseBytes
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

        // Darwin streams so an oversized body is cut off as it arrives. FoundationNetworking
        // does not expose AsyncBytes, so Linux uses its data API and enforces the same decoded cap.
#if canImport(Darwin)
        let (stream, response) = try await session.bytes(for: urlRequest)
#else
        let (data, response) = try await session.data(for: urlRequest)
#endif
        let call = "\(request.method) \(ErrorDetail.hostPath(request.url))"
        guard let http = response as? HTTPURLResponse else {
            throw Self.logged(.transportFailed("\(call): the response was not HTTP"))
        }

#if canImport(Darwin)
        var bytes: [UInt8] = []
        bytes.reserveCapacity(min(maximumResponseBytes, 64 << 10))
        do {
            for try await byte in stream {
                bytes.append(byte)
                if bytes.count > maximumResponseBytes {
                    throw Self.logged(.transportFailed(
                        "\(call): the response exceeded \(maximumResponseBytes) bytes"
                    ))
                }
            }
        }
#else
        guard data.count <= maximumResponseBytes else {
            throw Self.logged(.transportFailed(
                "\(call): the response exceeded \(maximumResponseBytes) bytes"
            ))
        }
        let bytes = Array(data)
#endif

        var headers: [String: String] = [:]
        for (name, value) in http.allHeaderFields {
            if let name = name as? String, let value = value as? String {
                headers[name] = value
            }
        }
        return HTTPResponse(statusCode: http.statusCode, headers: headers, body: bytes)
    }

    private static func logged(_ error: AuthTransportError) -> AuthTransportError {
        ToolboxLog.error("ToolboxAuth", ErrorDetail.describe(error))
        return error
    }
}
