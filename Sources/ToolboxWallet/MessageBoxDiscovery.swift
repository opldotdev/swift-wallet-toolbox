import Foundation
import BSVCore
import BSVKeys
import BSVOverlay
import BSVNetwork
import BSVScript
import BSVTransaction
import ToolboxStorage

/// Matches MessageBoxClient.queryAdvertisements: resolve ls_messagebox, decode
/// the advertised PushDrop host, and use the configured fallback when absent.
public struct MessageBoxDiscovery: Sendable {
    private let resolver: any OverlayLookupResolving
    public init(resolver: any OverlayLookupResolving) { self.resolver = resolver }

    public init() throws {
        resolver = try LookupResolver(
            facilitator: HTTPSOverlayLookupFacilitator(configuration:
                OverlayHTTPConfiguration(beefLimits: StorageLimits.beef)),
            slapTrackers: ["https://overlay-us-1.bsvb.tech", "https://overlay-eu-1.bsvb.tech",
                "https://overlay-ap-1.bsvb.tech", "https://users.bapp.dev"].map {
                    try OverlayHost(rawValue: $0)
                }, beefLimits: StorageLimits.beef)
    }

    public func host(for recipient: PublicKey, fallback: URL) async throws -> URL {
        let fallback = try MessageBoxHost.configured(fallback.absoluteString)
        do {
            let query = try JSONEncoder().encode(["identityKey": Hex.encode(recipient.compressedBytes)])
            let answer = try await resolver.resolve(LookupQuestion(
                service: OverlayService(rawValue: "ls_messagebox"), query: Array(query)))
            if case .outputList(let outputs) = answer {
                for output in outputs {
                    guard let transaction = try? Self.transaction(output.beef),
                          Int(output.outputIndex) < transaction.outputs.count,
                          // TS MessageBox advertisements use PushDrop's default
                          // key-before-fields layout, not the Swift default.
                          let token = try? PushDrop.decode(transaction.outputs[Int(output.outputIndex)].lockingScript,
                              lockPosition: .beforeCompatibility),
                          token.fields.count >= 2,
                          token.fields[0] == recipient.compressedBytes,
                          let text = String(bytes: token.fields[1], encoding: .utf8),
                          let host = MessageBoxHost.advertised(text) else { continue }
                    return host
                }
            }
        } catch is CancellationError { throw CancellationError() }
        catch { /* The reference client falls back on an unavailable overlay. */ }
        try Task.checkCancellation()
        return fallback
    }

    private static func transaction(_ bytes: [UInt8]) throws -> Transaction? {
        if bytes.starts(with: [1, 1, 1, 1]) {
            let atomic = try AtomicBEEF(bytes: bytes, limits: StorageLimits.beef)
            return try atomic.beef.transaction(for: atomic.subjectTransactionID, limits: StorageLimits.transaction)
        }
        return try BEEF(bytes: bytes, limits: StorageLimits.beef).transactions.last?.transaction
    }

}
