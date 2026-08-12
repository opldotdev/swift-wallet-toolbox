import XCTest
@testable import ToolboxServices

/// Exchange-rate decoding is tested offline so malformed provider responses stay deterministic.
final class WhatsOnChainExchangeRateTests: XCTestCase {

    /// A fixed response keeps provider tests independent of the network.
    private struct StubHTTP: HTTPGet {
        let status: Int
        let body: [UInt8]
        func get(_ url: URL) async throws -> (status: Int, body: [UInt8]) { (status, body) }
    }

    func test_aValidRateIsDecoded() async throws {
        let source = WhatsOnChainExchangeRate(
            http: StubHTTP(
                status: 200,
                body: Array(#"{"currency":"USD","rate":63.12,"time":0}"#.utf8)
            )
        )

        let rate = try await source.usdPerBSV()
        XCTAssertEqual(rate, 63.12)
    }

    func test_amissingRateIsRefused() async throws {
        let source = WhatsOnChainExchangeRate(
            http: StubHTTP(status: 200, body: Array(#"{"currency":"USD"}"#.utf8))
        )

        do {
            _ = try await source.usdPerBSV()
            XCTFail("a response without a rate must be refused")
        } catch let error as ExchangeRateError {
            XCTAssertEqual(error, .unreadableResponse)
        }
    }

    func test_anonnumericRateIsRefused() async throws {
        let source = WhatsOnChainExchangeRate(
            http: StubHTTP(status: 200, body: Array(#"{"rate":"not-a-rate"}"#.utf8))
        )

        do {
            _ = try await source.usdPerBSV()
            XCTFail("a non-numeric rate must be refused")
        } catch let error as ExchangeRateError {
            XCTAssertEqual(error, .unreadableResponse)
        }
    }

    func test_anHTTPErrorIsReported() async throws {
        let source = WhatsOnChainExchangeRate(http: StubHTTP(status: 503, body: []))

        do {
            _ = try await source.usdPerBSV()
            XCTFail("a 503 is not an exchange rate")
        } catch let error as ExchangeRateError {
            XCTAssertEqual(error, .httpFailure(statusCode: 503))
        }
    }

    /// The live feed is checked only when requested so the normal suite remains offline.
    func test_liveRateIsPositive() async throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["TEST_RUNNER_LIVE_CHAIN"] != nil,
            "set TEST_RUNNER_LIVE_CHAIN to hit the real WhatsOnChain API"
        )

        let rate = try await WhatsOnChainExchangeRate().usdPerBSV()
        XCTAssertGreaterThan(rate, 0)
    }
}
