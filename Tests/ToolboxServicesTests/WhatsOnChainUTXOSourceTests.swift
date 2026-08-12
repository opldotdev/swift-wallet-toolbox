import XCTest
import BSVKeys
import BSVScript
@testable import ToolboxServices

/// Reading spendable outputs from WhatsOnChain.
///
/// The unit tests use a canned response, so the parsing and the P2PKH-script reconstruction are
/// checked without a network. The live test confirms the shape still holds against the real API.
final class WhatsOnChainUTXOSourceTests: XCTestCase {

    /// Returns a fixed body regardless of URL.
    private struct StubHTTP: HTTPGet {
        let status: Int
        let body: [UInt8]
        func get(_ url: URL) async throws -> (status: Int, body: [UInt8]) { (status, body) }
    }

    private let address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

    /// The P2PKH script the address reconstructs to, for comparison.
    private func p2pkh(_ address: String) throws -> [UInt8] {
        try Script.payToPublicKeyHash(Address(address).publicKeyHash, maximumByteCount: 1 << 20)
            .bytes
    }

    func test_unspentOutputsDecodeWithReconstructedScripts() async throws {
        let json = """
            [{"height":450900,"tx_pos":0,"tx_hash":"c793cbdd734ff5da884064e5673f8420b7024b6d373e2cd36eb3f8775455ec14","value":148112},
             {"height":455306,"tx_pos":1,"tx_hash":"db189b025d2fe8ec50bb8f8c4eb8d428434e8fb5c8b2512ff7150f68ead15e6c","value":80000}]
            """
        let source = WhatsOnChainUTXOSource(
            http: StubHTTP(status: 200, body: Array(json.utf8))
        )

        let utxos = try await source.spendableOutputs(forAddress: address)

        XCTAssertEqual(utxos.count, 2)
        XCTAssertEqual(utxos[0].txid,
                       "c793cbdd734ff5da884064e5673f8420b7024b6d373e2cd36eb3f8775455ec14")
        XCTAssertEqual(utxos[0].vout, 0)
        XCTAssertEqual(utxos[0].satoshis, 148_112)
        XCTAssertEqual(utxos[0].lockingScript, try p2pkh(address),
                       "the script is reconstructed from the address, since WoC omits it")
        XCTAssertEqual(utxos[1].satoshis, 80_000)
    }

    func test_anEmptyAddressReturnsNothing() async throws {
        let source = WhatsOnChainUTXOSource(http: StubHTTP(status: 200, body: Array("[]".utf8)))

        let utxos = try await source.spendableOutputs(forAddress: address)

        XCTAssertTrue(utxos.isEmpty)
    }

    /// A row missing a field is refused, not skipped — a dropped UTXO is money the wallet stops
    /// seeing.
    func test_arowMissingAFieldIsRefused() async throws {
        let json = #"[{"tx_pos":0,"value":100}]"#  // no tx_hash
        let source = WhatsOnChainUTXOSource(http: StubHTTP(status: 200, body: Array(json.utf8)))

        do {
            _ = try await source.spendableOutputs(forAddress: address)
            XCTFail("a malformed UTXO row must be refused")
        } catch is UTXOSourceError {
            // refused, correct
        }
    }

    func test_anUnparseableAddressIsRefused() async throws {
        let source = WhatsOnChainUTXOSource(http: StubHTTP(status: 200, body: Array("[]".utf8)))

        do {
            _ = try await source.spendableOutputs(forAddress: "not-an-address")
            XCTFail("an address with no P2PKH script cannot yield spendable outputs")
        } catch is UTXOSourceError {
            // refused, correct
        }
    }

    func test_anHTTPErrorIsReported() async throws {
        let source = WhatsOnChainUTXOSource(http: StubHTTP(status: 503, body: []))

        do {
            _ = try await source.spendableOutputs(forAddress: address)
            XCTFail("a 503 is not an empty wallet")
        } catch let error as UTXOSourceError {
            XCTAssertEqual(error, .httpFailure(provider: "whatsonchain", statusCode: 503))
        }
    }

    /// Against the real API. Skipped unless asked for, so CI stays offline.
    func test_liveFetchAgainstARealAddress() async throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["TEST_RUNNER_LIVE_CHAIN"] != nil,
            "set TEST_RUNNER_LIVE_CHAIN to hit the real WhatsOnChain API"
        )
        let source = WhatsOnChainUTXOSource()

        let utxos = try await source.spendableOutputs(forAddress: address)

        XCTAssertFalse(utxos.isEmpty, "this address is known to hold coins")
        XCTAssertTrue(utxos.allSatisfy { $0.satoshis > 0 })
        XCTAssertTrue(utxos.allSatisfy { $0.lockingScript == (try? p2pkh(address)) })
    }
}
