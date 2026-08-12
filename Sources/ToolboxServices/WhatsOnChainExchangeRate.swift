import Foundation
import ToolboxCore

/// WhatsOnChain supplies the USD rate so applications do not need their own network client.
public struct WhatsOnChainExchangeRate: Sendable {
    private static let maximumResponseBytes = 1 << 20
    private let http: any HTTPGet

    public init(http: any HTTPGet = URLSessionHTTPGet()) {
        self.http = http
    }

    /// The USD price of one whole BSV comes from WhatsOnChain's mainnet rate feed.
    public func usdPerBSV() async throws -> Double {
        guard let url = URL(
            string: "https://api.whatsonchain.com/v1/bsv/main/exchangerate"
        ) else {
            throw ExchangeRateError.unreadableResponse
        }

        let (status, body) = try await http.get(url)
        guard (200..<300).contains(status) else {
            throw ExchangeRateError.httpFailure(statusCode: status)
        }

        guard body.count <= Self.maximumResponseBytes,
              let value = try? JSONDecoder().decode(JSONValue.self, from: Data(body)),
              let rate = value["rate"]?.doubleValue,
              rate.isFinite, rate > 0 else {
            throw ExchangeRateError.unreadableResponse
        }
        return rate
    }
}

/// Exchange-rate failures stay typed so callers can distinguish bad data from provider downtime.
public enum ExchangeRateError: Error, Equatable, Sendable {
    case unreadableResponse
    case httpFailure(statusCode: Int)
}
