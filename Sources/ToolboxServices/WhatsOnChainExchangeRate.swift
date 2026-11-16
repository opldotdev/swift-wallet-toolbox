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
            Self.log(url, status, body, "error status")
            throw ExchangeRateError.httpFailure(statusCode: status)
        }

        // A body that does not decode is reported as unreadable, with the body logged.
        guard body.count <= Self.maximumResponseBytes,
              let value = try? JSONDecoder().decode(JSONValue.self, from: Data(body)),
              let rate = value["rate"]?.doubleValue,
              rate.isFinite, rate > 0 else {
            Self.log(url, status, body, "no positive rate")
            throw ExchangeRateError.unreadableResponse
        }
        return rate
    }
}

extension WhatsOnChainExchangeRate {
    static func log(_ url: URL, _ status: Int, _ body: [UInt8], _ why: String) {
        ToolboxLog.error("ToolboxServices", "exchange rate: GET \(ErrorDetail.hostPath(url)) answered "
            + "HTTP \(status) (\(why)); body: \(ErrorDetail.bodyPreview(body))")
    }
}

/// Exchange-rate failures stay typed so callers can distinguish bad data from provider downtime.
public enum ExchangeRateError: Error, Equatable, Sendable, LocalizedError {
    case unreadableResponse
    case httpFailure(statusCode: Int)

    public var errorDescription: String? {
        switch self {
        case .unreadableResponse:
            "WhatsOnChain sent an exchange rate this wallet could not read."
        case .httpFailure(let status):
            "WhatsOnChain could not provide the exchange rate (HTTP \(status)). Try again later."
        }
    }
}
