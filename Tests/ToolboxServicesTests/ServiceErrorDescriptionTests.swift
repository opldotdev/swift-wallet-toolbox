import XCTest
@testable import ToolboxServices

/// Chain-service failures name the provider and say whether trying again can help.
final class ServiceErrorDescriptionTests: XCTestCase {

    func test_utxoSourceDescriptions() {
        XCTAssertEqual(
            UTXOSourceError.httpFailure(provider: "whatsonchain", statusCode: 503).localizedDescription,
            "whatsonchain could not list the coins (HTTP 503). Try again later."
        )
        XCTAssertEqual(
            UTXOSourceError.httpFailure(provider: "whatsonchain", statusCode: 404).localizedDescription,
            "whatsonchain refused to list the coins (HTTP 404)."
        )
        XCTAssertEqual(
            UTXOSourceError.invalidAddress("x").localizedDescription,
            "That is not an address coins can be listed for."
        )
    }

    func test_allProvidersFailedNamesEachProvider() {
        let error = ServiceError.allProvidersFailed([
            (provider: "whatsonchain", reason: "HTTP 503"), (provider: "bitails", reason: "timeout"),
        ])
        XCTAssertEqual(
            error.localizedDescription,
            "No chain service could answer (whatsonchain, bitails). Try again later."
        )
        XCTAssertEqual(
            ServiceError.allProvidersFailed([]).localizedDescription,
            "No chain service is set up to answer this."
        )
    }

    func test_exchangeRateDescriptions() {
        XCTAssertEqual(
            ExchangeRateError.httpFailure(statusCode: 502).localizedDescription,
            "WhatsOnChain could not provide the exchange rate (HTTP 502). Try again later."
        )
    }
}
