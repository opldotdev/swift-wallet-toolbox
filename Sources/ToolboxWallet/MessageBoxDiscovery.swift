import Foundation
import BSVCore
import BSVKeys
import BSVOverlay
import BSVNetwork
import BSVScript
import BSVTransaction
import ToolboxStorage

/// Matches MessageBoxClient.queryAdvertisements: resolve ls_messagebox, keep the first
/// advertisement the recipient signed, and use the configured fallback when there is none.
public struct MessageBoxDiscovery: Sendable {
    /// `DEFAULT_SLAP_TRACKERS` in @bsv/sdk `src/overlay-tools/LookupResolver.ts`.
    public static let mainnetSLAPTrackers = ["https://overlay-us-1.bsvb.tech",
        "https://overlay-eu-1.bsvb.tech", "https://overlay-ap-1.bsvb.tech", "https://users.bapp.dev"]
    /// `DEFAULT_TESTNET_SLAP_TRACKERS` in @bsv/sdk `src/overlay-tools/LookupResolver.ts`.
    public static let testnetSLAPTrackers = ["https://testnet-users.bapp.dev"]

    /// The trackers `new LookupResolver({ networkPreset })` starts from for this network.
    public static func slapTrackers(for network: BitcoinNetwork) -> [String] {
        switch network {
        case .mainnet: mainnetSLAPTrackers
        case .testnet: testnetSLAPTrackers
        }
    }

    private let resolver: any OverlayLookupResolving
    public init(resolver: any OverlayLookupResolving) { self.resolver = resolver }

    /// As MessageBoxClient's `networkPreset`: a testnet wallet must look up
    /// advertisements on testnet trackers, or it would pay testnet BEEF to a
    /// mainnet host. The default stays mainnet, as in the reference client.
    public init(network: BitcoinNetwork = .mainnet) throws {
        try self.init(network: network, facilitator: HTTPSOverlayLookupFacilitator(configuration:
            OverlayHTTPConfiguration(beefLimits: StorageLimits.beef)))
    }

    init(network: BitcoinNetwork, facilitator: any LookupFacilitator) throws {
        resolver = try LookupResolver(facilitator: facilitator,
            slapTrackers: Self.slapTrackers(for: network).map { try OverlayHost(rawValue: $0) },
            beefLimits: StorageLimits.beef)
    }

    public func host(for recipient: PublicKey, fallback: URL) async throws -> URL {
        let fallback = try MessageBoxHost.configured(fallback.absoluteString)
        do {
            let query = try JSONEncoder().encode(["identityKey": Hex.encode(recipient.compressedBytes)])
            let answer = try await resolver.resolve(LookupQuestion(
                service: OverlayService(rawValue: "ls_messagebox"), query: Array(query)))
            if case .outputList(let outputs) = answer {
                // As TS 2.7.0 `queryAdvertisements`: only an advertisement the recipient signed
                // counts, so nobody else can route the recipient's payments to their own host.
                for output in outputs {
                    try Task.checkCancellation()
                    guard let advertisement = await MessageBoxAdvertiser.advertisement(output, identity: recipient)
                    else { continue }
                    return advertisement.host
                }
            }
        } catch is CancellationError { throw CancellationError() }
        catch { /* The reference client falls back on an unavailable overlay. */ }
        try Task.checkCancellation()
        return fallback
    }

}
