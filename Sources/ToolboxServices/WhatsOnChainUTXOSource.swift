import BSVKeys
import BSVScript
import Foundation
import ToolboxCore

/// Spendable outputs from WhatsOnChain.
///
/// WhatsOnChain returns only the outpoint and amount for each unspent output — no locking script.
/// For a standard P2PKH address that is not a problem: every output paid to the address has the
/// same script, `OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG`, which this reconstructs
/// from the address itself. No per-output lookup is needed.
///
/// This adapter is therefore for **P2PKH addresses only** — the case a plain-BSV sweep or a
/// balance check needs. An output with a non-standard script (an ordinal, a token) is not knowable
/// from the address, so those come from an indexer provider or the 1Sat action layer, not here.
public struct WhatsOnChainUTXOSource: UTXOSource {
    private let network: BitcoinNetwork
    private let http: any HTTPGet

    public init(network: BitcoinNetwork = .mainnet, http: any HTTPGet = URLSessionHTTPGet()) {
        self.network = network
        self.http = http
    }

    private var chainSegment: String {
        network == .mainnet ? "main" : "test"
    }

    public func spendableOutputs(forAddress address: String) async throws -> [SpendableUTXO] {
        // The P2PKH script is derived once from the address, and refusing an address that is not
        // parseable here beats returning outputs the caller cannot sign.
        let script: [UInt8]
        do {
            let parsed = try Address(address)
            script = try Script.payToPublicKeyHash(
                parsed.publicKeyHash, maximumByteCount: 1 << 20
            ).bytes
        } catch {
            throw UTXOSourceError.unreadableResponse(provider: "whatsonchain")
        }

        guard let url = URL(
            string: "https://api.whatsonchain.com/v1/bsv/\(chainSegment)/address/\(address)/unspent"
        ) else {
            throw UTXOSourceError.unreadableResponse(provider: "whatsonchain")
        }

        let (status, body) = try await http.get(url)
        guard (200..<300).contains(status) else {
            throw UTXOSourceError.httpFailure(provider: "whatsonchain", statusCode: status)
        }

        return try Self.decode(body, lockingScript: script)
    }

    /// Reads the `[{tx_hash, tx_pos, value}]` array. A row missing a field is a refusal, not a
    /// skipped coin — a dropped UTXO is money the wallet stops seeing.
    static func decode(_ body: [UInt8], lockingScript: [UInt8]) throws -> [SpendableUTXO] {
        guard let value = try? JSONDecoder().decode(JSONValue.self, from: Data(body)),
              let rows = value.arrayValue else {
            throw UTXOSourceError.unreadableResponse(provider: "whatsonchain")
        }
        return try rows.map { row in
            guard let txid = row["tx_hash"]?.stringValue,
                  let vout = row["tx_pos"]?.intValue.flatMap({ UInt32(exactly: $0) }),
                  let satoshis = row["value"]?.intValue.flatMap({ UInt64(exactly: $0) }) else {
                throw UTXOSourceError.unreadableResponse(provider: "whatsonchain")
            }
            return SpendableUTXO(
                txid: txid, vout: vout, satoshis: satoshis, lockingScript: lockingScript
            )
        }
    }
}
