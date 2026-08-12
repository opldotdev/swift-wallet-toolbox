import Foundation
import XCTest
@testable import ToolboxPaymail

/// Paymail discovery and output parsing use canned HTTP responses; only the explicitly gated test
/// reaches the network.
final class PaymailTests: XCTestCase {
    private static let destinationCapability = "2a40af698840"
    private static let receiveBEEFCapability = "5c55a7fdb7bb"
    private static let receiveTransactionCapability = "5f1323cddf31"

    private struct StubResponse: Sendable {
        let status: Int
        let body: [UInt8]

        init(status: Int = 200, body: String) {
            self.status = status
            self.body = Array(body.utf8)
        }
    }

    private enum StubError: Error {
        case unexpectedGET(String)
        case unexpectedPOST(String)
    }

    /// Responses are keyed by the complete URL so host, port, and URL-template substitution are
    /// observable parts of every test.
    private actor StubHTTP: PaymailHTTP {
        let getResponses: [String: StubResponse]
        let postResponses: [String: StubResponse]
        private var getCounts: [String: Int] = [:]
        private var postBodies: [String: [[UInt8]]] = [:]

        init(
            getResponses: [String: StubResponse],
            postResponses: [String: StubResponse] = [:]
        ) {
            self.getResponses = getResponses
            self.postResponses = postResponses
        }

        func get(_ url: URL) async throws -> (status: Int, body: [UInt8]) {
            let key = url.absoluteString
            guard let response = getResponses[key] else {
                throw StubError.unexpectedGET(key)
            }
            getCounts[key, default: 0] += 1
            return (response.status, response.body)
        }

        func post(_ url: URL, json: [UInt8]) async throws -> (status: Int, body: [UInt8]) {
            let key = url.absoluteString
            guard let response = postResponses[key] else {
                throw StubError.unexpectedPOST(key)
            }
            postBodies[key, default: []].append(json)
            return (response.status, response.body)
        }

        func getCount(for url: String) -> Int {
            getCounts[url, default: 0]
        }

        func postedBody(to url: String) -> [UInt8]? {
            postBodies[url]?.last
        }
    }

    private let domain = "example.com"
    private let paymail = "alice@example.com"
    private let dnsURL =
        "https://dns.google.com/resolve?name=_bsvalias._tcp.example.com&type=SRV&cd=0"
    private let fallbackCapabilitiesURL = "https://example.com:443/.well-known/bsvalias"
    private let destinationURL = "https://pay.example.com/alice/example.com/destination"

    func test_isPaymailRecognizesOnlyPaymailShape() {
        XCTAssertTrue(Paymail.isPaymail("a@b.com"))
        XCTAssertFalse(Paymail.isPaymail("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
        XCTAssertFalse(Paymail.isPaymail("not-a-paymail"))
    }

    func test_srvDiscoveryUsesTargetHostAndPort() async throws {
        let capabilitiesURL = "https://pay.example.com:8443/.well-known/bsvalias"
        let stub = StubHTTP(getResponses: [
            dnsURL: StubResponse(
                body: #"{"Status":0,"AD":false,"Answer":[{"data":"10 5 8443 pay.example.com."}]}"#
            ),
            capabilitiesURL: StubResponse(body: capabilitiesJSON()),
        ], postResponses: [
            destinationURL: StubResponse(body: destinationJSON())
        ])

        _ = try await Paymail(http: stub).paymentDestination(paymail: paymail, satoshis: 42)

        let count = await stub.getCount(for: capabilitiesURL)
        XCTAssertEqual(count, 1)
    }

    func test_nxdomainFallsBackToDomainAndPort443() async throws {
        let stub = StubHTTP(getResponses: [
            dnsURL: StubResponse(body: #"{"Status":3}"#),
            fallbackCapabilitiesURL: StubResponse(body: capabilitiesJSON()),
        ], postResponses: [
            destinationURL: StubResponse(body: destinationJSON())
        ])

        _ = try await Paymail(http: stub).paymentDestination(paymail: paymail, satoshis: 42)

        let count = await stub.getCount(for: fallbackCapabilitiesURL)
        XCTAssertEqual(count, 1)
    }

    func test_unvalidatedCrossDomainSRVTargetFallsBack() async throws {
        let stub = StubHTTP(getResponses: [
            dnsURL: StubResponse(
                body: #"{"Status":0,"AD":false,"Answer":[{"data":"0 0 9443 unrelated.test."}]}"#
            ),
            fallbackCapabilitiesURL: StubResponse(body: capabilitiesJSON()),
        ], postResponses: [
            destinationURL: StubResponse(body: destinationJSON())
        ])

        _ = try await Paymail(http: stub).paymentDestination(paymail: paymail, satoshis: 42)

        let count = await stub.getCount(for: fallbackCapabilitiesURL)
        XCTAssertEqual(count, 1)
    }

    func test_dnssecValidatedCrossDomainSRVTargetIsAccepted() async throws {
        let capabilitiesURL = "https://pay.unrelated.test:9443/.well-known/bsvalias"
        let stub = StubHTTP(getResponses: [
            dnsURL: StubResponse(
                body: #"{"Status":0,"AD":true,"Answer":[{"data":"0 0 9443 pay.unrelated.test."}]}"#
            ),
            capabilitiesURL: StubResponse(body: capabilitiesJSON()),
        ], postResponses: [
            destinationURL: StubResponse(body: destinationJSON())
        ])

        _ = try await Paymail(http: stub).paymentDestination(paymail: paymail, satoshis: 42)

        let count = await stub.getCount(for: capabilitiesURL)
        XCTAssertEqual(count, 1)
    }

    func test_capabilitiesAreParsedAndCachedPerDomain() async throws {
        let stub = fallbackStub()
        let resolver = Paymail(http: stub)

        _ = try await resolver.paymentDestination(paymail: paymail, satoshis: 42)
        _ = try await resolver.paymentDestination(paymail: paymail, satoshis: 43)

        let discoveryCount = await stub.getCount(for: dnsURL)
        let capabilitiesCount = await stub.getCount(for: fallbackCapabilitiesURL)
        XCTAssertEqual(discoveryCount, 1)
        XCTAssertEqual(capabilitiesCount, 1)
    }

    func test_paymentDestinationDecodesOutputsAndReference() async throws {
        let destination = try await Paymail(http: fallbackStub()).paymentDestination(
            paymail: paymail,
            satoshis: 42
        )

        XCTAssertEqual(destination.reference, "payment-reference")
        XCTAssertEqual(destination.outputs.count, 2)
        XCTAssertEqual(destination.outputs[0].lockingScript, [0x76, 0xa9])
        XCTAssertEqual(destination.outputs[0].satoshis, 40)
        XCTAssertEqual(destination.outputs[1].lockingScript, [0x51])
        XCTAssertEqual(destination.outputs[1].satoshis, 2)
    }

    func test_missingDestinationCapabilityThrowsTypedError() async throws {
        let stub = StubHTTP(getResponses: [
            dnsURL: StubResponse(body: #"{"Status":3}"#),
            fallbackCapabilitiesURL: StubResponse(body: #"{"capabilities":{}}"#),
        ])

        do {
            _ = try await Paymail(http: stub).paymentDestination(paymail: paymail, satoshis: 42)
            XCTFail("a server without payment destination support cannot resolve outputs")
        } catch let error as PaymailError {
            XCTAssertEqual(
                error,
                .capabilityUnsupported(
                    domain: domain,
                    capability: Self.destinationCapability
                )
            )
        }
    }

    func test_invalidPaymailThrowsTypedErrorBeforeHTTP() async throws {
        do {
            _ = try await Paymail(http: StubHTTP(getResponses: [:]))
                .paymentDestination(paymail: "not-a-paymail", satoshis: 42)
            XCTFail("an invalid address must not start discovery")
        } catch let error as PaymailError {
            XCTAssertEqual(error, .notAPaymail("not-a-paymail"))
        }
    }

    func test_nonHexScriptIsUnreadable() async throws {
        let stub = fallbackStub(destinationBody: destinationJSON(script: "not-hex"))

        do {
            _ = try await Paymail(http: stub).paymentDestination(paymail: paymail, satoshis: 42)
            XCTFail("a locking script must be hex")
        } catch let error as PaymailError {
            XCTAssertEqual(error, .unreadableResponse)
        }
    }

    func test_missingReferenceIsUnreadable() async throws {
        let body = #"{"outputs":[{"script":"51","satoshis":42}]}"#
        let stub = fallbackStub(destinationBody: body)

        do {
            _ = try await Paymail(http: stub).paymentDestination(paymail: paymail, satoshis: 42)
            XCTFail("the reference is required for later delivery")
        } catch let error as PaymailError {
            XCTAssertEqual(error, .unreadableResponse)
        }
    }

    func test_deliverPrefersBEEFAndEncodesHexWithReference() async throws {
        let receiveURL = "https://pay.example.com/alice/example.com/beef"
        let transactionURL = "https://pay.example.com/alice/example.com/transaction"
        let stub = StubHTTP(getResponses: [
            dnsURL: StubResponse(body: #"{"Status":3}"#),
            fallbackCapabilitiesURL: StubResponse(body: capabilitiesJSON(includeReceive: true)),
        ], postResponses: [
            receiveURL: StubResponse(body: ""),
            transactionURL: StubResponse(body: ""),
        ])

        try await Paymail(http: stub).deliver(
            beef: [0x01, 0xab, 0xff],
            to: paymail,
            reference: "payment-reference"
        )

        let posted = await stub.postedBody(to: receiveURL)
        let body = try XCTUnwrap(posted)
        let object = try JSONSerialization.jsonObject(with: Data(body)) as? [String: String]
        XCTAssertEqual(object?["beef"], "01abff")
        XCTAssertEqual(object?["reference"], "payment-reference")
        let notPosted = await stub.postedBody(to: transactionURL)
        XCTAssertNil(notPosted)
    }

    func test_deliverFallsBackToReceiveTransactionCapability() async throws {
        let transactionURL = "https://pay.example.com/alice/example.com/transaction"
        let capabilities = """
            {"capabilities":{
              "\(Self.receiveTransactionCapability)":"https://pay.example.com/{alias}/{domain.tld}/transaction"
            }}
            """
        let stub = StubHTTP(getResponses: [
            dnsURL: StubResponse(body: #"{"Status":3}"#),
            fallbackCapabilitiesURL: StubResponse(body: capabilities),
        ], postResponses: [
            transactionURL: StubResponse(body: "")
        ])

        try await Paymail(http: stub).deliver(
            beef: [0x01],
            to: paymail,
            reference: "payment-reference"
        )

        let posted = await stub.postedBody(to: transactionURL)
        XCTAssertNotNil(posted)
    }

    func test_deliveryHTTPFailureUsesDeliveryError() async throws {
        let receiveURL = "https://pay.example.com/alice/example.com/beef"
        let stub = StubHTTP(getResponses: [
            dnsURL: StubResponse(body: #"{"Status":3}"#),
            fallbackCapabilitiesURL: StubResponse(body: capabilitiesJSON(includeReceive: true)),
        ], postResponses: [
            receiveURL: StubResponse(status: 503, body: "")
        ])

        do {
            try await Paymail(http: stub).deliver(
                beef: [0x01],
                to: paymail,
                reference: "payment-reference"
            )
            XCTFail("a failed delivery must not be reported as success")
        } catch let error as PaymailError {
            XCTAssertEqual(error, .deliveryFailed(statusCode: 503))
        }
    }

    /// Resolves only when explicitly requested so the normal suite remains offline.
    func test_livePaymentDestination() async throws {
        let environment = ProcessInfo.processInfo.environment
        let livePaymail = environment["TEST_RUNNER_LIVE_PAYMAIL"]
        try XCTSkipUnless(
            livePaymail != nil,
            "set TEST_RUNNER_LIVE_PAYMAIL to a real paymail address"
        )

        let destination = try await Paymail().paymentDestination(
            paymail: try XCTUnwrap(livePaymail),
            satoshis: 1
        )

        XCTAssertFalse(destination.outputs.isEmpty)
    }

    private func fallbackStub(destinationBody: String? = nil) -> StubHTTP {
        StubHTTP(getResponses: [
            dnsURL: StubResponse(body: #"{"Status":3}"#),
            fallbackCapabilitiesURL: StubResponse(body: capabilitiesJSON()),
        ], postResponses: [
            destinationURL: StubResponse(body: destinationBody ?? destinationJSON())
        ])
    }

    private func capabilitiesJSON(includeReceive: Bool = false) -> String {
        var capabilities = [
            "\"\(Self.destinationCapability)\":\"https://pay.example.com/{alias}/{domain.tld}/destination\""
        ]
        if includeReceive {
            capabilities.append(
                "\"\(Self.receiveBEEFCapability)\":\"https://pay.example.com/{alias}/{domain.tld}/beef\""
            )
            capabilities.append(
                "\"\(Self.receiveTransactionCapability)\":\"https://pay.example.com/{alias}/{domain.tld}/transaction\""
            )
        }
        return "{\"capabilities\":{\(capabilities.joined(separator: ","))}}"
    }

    private func destinationJSON(script: String = "76a9") -> String {
        """
        {"reference":"payment-reference","outputs":[
          {"script":"\(script)","satoshis":40},
          {"script":"51","satoshis":2}
        ]}
        """
    }
}
