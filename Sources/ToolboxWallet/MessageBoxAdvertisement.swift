import Foundation
import BSVCore
import BSVKeys
import BSVNetwork
import BSVOverlay
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxStorage

/// One of an identity's `ls_messagebox` advertisements, as `@bsv/message-box-client`
/// `queryAdvertisements` returns an `AdvertisementToken`: the advertised host, the token's
/// outpoint and locking script, and the BEEF the overlay answered with, which spending it needs.
public struct MessageBoxAdvertisement: Sendable, Equatable {
    /// The advertised host, normalized as TS `normalizeOverlayMessageBoxHost` does.
    public let host: URL
    public let outpoint: Outpoint
    public let satoshis: UInt64
    public let lockingScript: Script
    /// The lookup answer's BEEF graph for the token's transaction.
    public let beef: BEEF

    public init(host: URL, outpoint: Outpoint, satoshis: UInt64, lockingScript: Script, beef: BEEF) {
        self.host = host; self.outpoint = outpoint; self.satoshis = satoshis
        self.lockingScript = lockingScript; self.beef = beef
    }

    /// True when this advertisement names `host`, compared as advertised hosts are normalized.
    public func names(_ host: URL) -> Bool {
        MessageBoxAdvertiser.advertisedText(host) == self.host.absoluteString
    }
}

public enum MessageBoxAdvertisementError: Error, LocalizedError, Equatable, Sendable {
    /// The host is not a public HTTPS URL, so the overlay would never hand it out
    /// (TS `normalizeOverlayMessageBoxHost` drops it).
    case invalidHost
    /// The overlay answered with something other than an output list.
    case unexpectedLookupAnswer
    /// The wallet returned no transaction to broadcast.
    case noTransaction

    public var errorDescription: String? {
        switch self {
        case .invalidHost: "A MessageBox host to advertise must be a public HTTPS URL."
        case .unexpectedLookupAnswer: "The overlay did not answer the advertisement lookup with outputs."
        case .noTransaction: "The wallet did not return the advertisement transaction."
        }
    }
}

/// The wallet calls advertising needs. The public API takes the concrete `RemoteWallet`; tests
/// use this seam.
protocol MessageBoxAdvertisingWallet: Sendable {
    /// The identity's key operations: derives the advertisement key and signs with it.
    var advertisementKeys: ProtoWallet { get }
    func listOutputs(_ request: WalletListOutputsRequest) async throws -> WalletListOutputsResult
    func createAction(_ request: WalletCreateActionRequest) async throws -> WalletCreateActionResult
    func signAction(_ request: WalletSignActionRequest) async throws -> WalletSignActionResult
    func abortAction(_ request: WalletAbortActionRequest) async throws -> WalletAbortActionResult
}

extension RemoteWallet: MessageBoxAdvertisingWallet {
    var advertisementKeys: ProtoWallet { protoWallet }
}

/// Advertises the MessageBox host an identity receives at, as `@bsv/message-box-client`
/// `MessageBoxClient.anointHost`, `revokeHostAdvertisement` and `queryAdvertisements` do.
///
/// A sender's `resolveHostForRecipient` looks the recipient up in `ls_messagebox` and, finding
/// nothing, delivers to its own default host. Advertising the host this wallet reads is what
/// makes other wallets deliver there.
///
/// The advertisement is a 1-satoshi PushDrop output in the `overlay advertisements` basket:
/// `[identity key, host UTF-8, signature]`, locked by the key derived under
/// `[1, "messagebox advertisement"]`, key ID `1`, counterparty `anyone`, `forSelf`, with the
/// lock before the fields (TS `PushDrop.lock` default). The transaction is submitted to the
/// `tm_messagebox` topic on the network's overlay. Each call creates and broadcasts a
/// transaction, so it is for an explicit user action only.
public struct MessageBoxAdvertiser: Sendable {
    public static let protocolName = "messagebox advertisement"
    public static let keyID = "1"
    public static let basket = "overlay advertisements"
    public static let topic = "tm_messagebox"
    public static let lookupService = "ls_messagebox"
    /// TS reserves 73 bytes for each PushDrop unlock (a DER signature and its hash type).
    static let unlockingScriptLength: UInt32 = 73
    /// TS `anointHost` reads up to 10,000 outputs of the basket.
    static let basketLimit: UInt32 = 10_000

    typealias Broadcast = @Sendable (AtomicBEEF) async throws -> TransactionID

    private let resolver: any OverlayLookupResolving
    private let broadcast: Broadcast

    /// As TS `networkPreset`: a testnet identity advertises on, and looks up from, testnet
    /// trackers only.
    public init(network: BitcoinNetwork = .mainnet) throws {
        let configuration = try OverlayHTTPConfiguration(beefLimits: StorageLimits.beef)
        let resolver = try LookupResolver(facilitator: HTTPSOverlayLookupFacilitator(configuration: configuration),
            slapTrackers: MessageBoxDiscovery.slapTrackers(for: network).map { try OverlayHost(rawValue: $0) },
            beefLimits: StorageLimits.beef)
        // TS `TopicBroadcaster(['tm_messagebox'], { networkPreset })`: its defaults ask no
        // acknowledgment from every host and the topic from at least one.
        let broadcaster = try OverlayTopicBroadcaster(topics: [OverlayTopic(rawValue: Self.topic)],
            facilitator: HTTPSOverlayTopicFacilitator(configuration: configuration), resolver: resolver,
            beefLimits: StorageLimits.beef)
        self.init(resolver: resolver) { atomic in try await broadcaster.broadcast(atomic).transactionID }
    }

    init(resolver: any OverlayLookupResolving, broadcast: @escaping Broadcast) {
        self.resolver = resolver
        self.broadcast = broadcast
    }

    static func protocolID() throws -> WalletProtocolID {
        try WalletProtocolID(securityLevel: .everyApp, name: protocolName)
    }

    /// The host text an advertisement carries, as TS `normalizeMessageBoxHost` writes it: the
    /// URL's origin (lowercase scheme and host, no default port) and its path without trailing
    /// slashes. Nil for a host the overlay would not hand out.
    public static func advertisedText(_ host: URL) -> String? {
        guard let url = MessageBoxHost.advertised(host.absoluteString),
              var parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let name = parts.host else { return nil }
        parts.scheme = "https"
        if !name.contains(":") { parts.host = name.lowercased() }
        if parts.port == 443 { parts.port = nil }
        return parts.url?.absoluteString
    }

    // MARK: - Locking script

    /// The advertisement's locking script, as TS `anointHost` builds it:
    /// `pushdrop.lock([identityKey, host], [1, 'messagebox advertisement'], '1', 'anyone', true)`.
    public static func lockingScript(
        host: URL, wallet: some WalletPublicKeyProviding & WalletSignatureOperations
    ) async throws -> Script {
        guard let text = advertisedText(host) else { throw MessageBoxAdvertisementError.invalidHost }
        let identity = try await wallet.getPublicKey(.init(selection: .identity)).publicKey
        return try await PushDrop.lockingScript(
            fields: [identity.compressedBytes, Array(text.utf8)], using: wallet,
            protocolID: protocolID(), keyID: WalletKeyID(keyID), counterparty: .anyone,
            forSelf: true, includeSignature: true, lockPosition: .beforeCompatibility)
    }

    // MARK: - Lookup

    /// The identity's advertisements, optionally only those naming `host`, as TS
    /// `queryAdvertisements` returns them. Each must be a PushDrop of exactly the identity key,
    /// a host and a signature that the identity made over the two; anything else is skipped.
    ///
    /// TS answers an overlay failure with no advertisements. This throws instead, so a caller
    /// can tell "not advertised" from "could not check".
    public func advertisements(of identity: PublicKey, host: URL? = nil) async throws -> [MessageBoxAdvertisement] {
        var query = ["identityKey": Hex.encode(identity.compressedBytes)]
        if let host {
            guard let text = Self.advertisedText(host) else { throw MessageBoxAdvertisementError.invalidHost }
            query["host"] = text
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let answer = try await resolver.resolve(LookupQuestion(
            service: OverlayService(rawValue: Self.lookupService), query: Array(try encoder.encode(query))))
        guard case .outputList(let outputs) = answer else { throw MessageBoxAdvertisementError.unexpectedLookupAnswer }
        var found: [MessageBoxAdvertisement] = []
        for output in outputs {
            try Task.checkCancellation()
            guard let advertisement = await Self.advertisement(output, identity: identity) else { continue }
            if found.contains(where: { $0.outpoint == advertisement.outpoint }) { continue }
            found.append(advertisement)
        }
        return found
    }

    /// One lookup output as an advertisement of `identity`, or nil when it is not a valid one.
    static func advertisement(_ output: OutputListItem, identity: PublicKey) async -> MessageBoxAdvertisement? {
        guard let beef = try? graph(output.beef),
              let transaction = try? subject(output.beef),
              let transactionID = try? transaction.transactionID(limits: StorageLimits.transaction),
              Int(output.outputIndex) < transaction.outputs.count else { return nil }
        let spent = transaction.outputs[Int(output.outputIndex)]
        guard let token = try? PushDrop.decode(spent.lockingScript, lockPosition: .beforeCompatibility),
              token.fields.count == 3,
              token.fields[0] == identity.compressedBytes,
              (1...2048).contains(token.fields[1].count),
              (1...80).contains(token.fields[2].count),
              let text = String(bytes: token.fields[1], encoding: .utf8),
              let url = URL(string: text), let normalized = advertisedText(url),
              let host = URL(string: normalized),
              let signature = try? ECDSASignature(derBytes: token.fields[2]),
              let advertisementProtocol = try? Self.protocolID(), let advertisementKey = try? WalletKeyID(Self.keyID),
              let anyone = try? PrivateKey(Array(repeating: 0, count: 31) + [1]) else { return nil }
        // TS verifies with `new ProtoWallet('anyone')` against the identity as counterparty.
        let verified = try? await ProtoWallet(rootKey: anyone).verifySignature(WalletVerifySignatureRequest(
            protocolID: advertisementProtocol, keyID: advertisementKey, counterparty: .publicKey(identity),
            payload: .data(token.fields[0] + token.fields[1]), signature: signature))
        guard verified?.valid == true else { return nil }
        return MessageBoxAdvertisement(host: host,
            outpoint: Outpoint(transactionID: transactionID, outputIndex: output.outputIndex),
            satoshis: spent.satoshis, lockingScript: spent.lockingScript, beef: beef)
    }

    /// TS `Transaction.fromBEEF`: the subject of an Atomic BEEF, else the last transaction.
    static func subject(_ bytes: [UInt8]) throws -> Transaction? {
        if bytes.starts(with: [1, 1, 1, 1]) {
            let atomic = try AtomicBEEF(bytes: bytes, limits: StorageLimits.beef)
            return try atomic.beef.transaction(for: atomic.subjectTransactionID, limits: StorageLimits.transaction)
        }
        return try BEEF(bytes: bytes, limits: StorageLimits.beef).transactions.last?.transaction
    }

    static func graph(_ bytes: [UInt8]) throws -> BEEF {
        if bytes.starts(with: [1, 1, 1, 1]) { return try AtomicBEEF(bytes: bytes, limits: StorageLimits.beef).beef }
        return try BEEF(bytes: bytes, limits: StorageLimits.beef)
    }

    // MARK: - Anoint and revoke

    /// Advertises `host` for the wallet's identity, as TS `anointHost`: one transaction that
    /// creates the new advertisement and spends every earlier one the overlay lists and the
    /// wallet holds as spendable in the basket. Returns the broadcast transaction's ID.
    ///
    /// TS goes on with no earlier advertisements to spend when the lookup fails. This throws
    /// instead, so a failed lookup never leaves an older advertisement live beside the new one.
    public func anoint(_ host: URL, wallet: RemoteWallet) async throws -> TransactionID {
        try await anoint(host, using: wallet)
    }

    /// Spends one advertisement without replacing it, as TS `revokeHostAdvertisement`.
    public func revoke(_ advertisement: MessageBoxAdvertisement, wallet: RemoteWallet) async throws -> TransactionID {
        try await revoke(advertisement, using: wallet)
    }

    func anoint(_ host: URL, using wallet: some MessageBoxAdvertisingWallet) async throws -> TransactionID {
        guard Self.advertisedText(host) != nil else { throw MessageBoxAdvertisementError.invalidHost }
        let keys = wallet.advertisementKeys
        let identity = try await keys.getPublicKey(.init(selection: .identity)).publicKey
        let listed = try await advertisements(of: identity)
        let basket = try await wallet.listOutputs(WalletListOutputsRequest(basket: Self.basket,
            pagination: WalletPagination(limit: Self.basketLimit)))
        let spendable = Set(basket.outputs.filter(\.spendable).map(\.outpoint))
        let spending = listed.filter { spendable.contains($0.outpoint) }

        let script = try await Self.lockingScript(host: host, wallet: keys)
        var inputBEEF: BEEF?
        for advertisement in spending {
            inputBEEF = try inputBEEF.map { try $0.merging(advertisement.beef, limits: StorageLimits.beef) }
                ?? advertisement.beef
        }
        let inputs = try spending.map {
            try WalletCreateActionInput(outpoint: $0.outpoint,
                inputDescription: "Revoking advertisement for \($0.host.absoluteString)",
                unlockingScriptLength: Self.unlockingScriptLength)
        }
        try Task.checkCancellation()
        let created = try await wallet.createAction(WalletCreateActionRequest(
            description: "Anoint host for overlay routing",
            inputBEEF: inputBEEF,
            inputs: inputs.isEmpty ? nil : inputs,
            outputs: [try WalletCreateActionOutput(lockingScript: script.bytes, satoshis: 1,
                outputDescription: "Overlay advertisement output", basket: Self.basket)],
            options: WalletCreateActionOptions(acceptDelayedBroadcast: false, randomizeOutputs: false)))
        return try await finish(created, spending: spending, using: wallet)
    }

    func revoke(_ advertisement: MessageBoxAdvertisement, using wallet: some MessageBoxAdvertisingWallet) async throws -> TransactionID {
        let created = try await wallet.createAction(WalletCreateActionRequest(
            description: "Revoke MessageBox host advertisement",
            inputBEEF: advertisement.beef,
            inputs: [try WalletCreateActionInput(outpoint: advertisement.outpoint,
                inputDescription: "Revoking host advertisement token",
                unlockingScriptLength: Self.unlockingScriptLength)]))
        return try await finish(created, spending: [advertisement], using: wallet)
    }

    /// Signs the advertisements the action spends, has the wallet finish and broadcast it, then
    /// submits it to `tm_messagebox`.
    private func finish(
        _ created: WalletCreateActionResult, spending: [MessageBoxAdvertisement],
        using wallet: some MessageBoxAdvertisingWallet
    ) async throws -> TransactionID {
        guard let signable = created.signableTransaction else {
            guard let transaction = created.transaction, spending.isEmpty else {
                throw MessageBoxAdvertisementError.noTransaction
            }
            return try await broadcast(transaction)
        }
        let spends: [UInt32: WalletSignActionSpend]
        do {
            spends = try await Self.spends(signable.transaction, spending: spending, keys: wallet.advertisementKeys)
        } catch {
            _ = try? await wallet.abortAction(WalletAbortActionRequest(reference: signable.reference))
            throw error
        }
        let signed = try await wallet.signAction(WalletSignActionRequest(reference: signable.reference,
            spends: spends, options: WalletSignActionOptions(acceptDelayedBroadcast: false)))
        guard let transaction = signed.transaction else { throw MessageBoxAdvertisementError.noTransaction }
        return try await broadcast(transaction)
    }

    /// The unlocking script for each spent advertisement, at the input index the wallet put it
    /// (BRC-100 puts caller inputs first, in request order), as TS
    /// `pushdrop.unlock([1, 'messagebox advertisement'], '1', 'anyone', 'all', false, satoshis, script)`.
    static func spends(
        _ partial: AtomicBEEF, spending: [MessageBoxAdvertisement], keys: some WalletSignatureOperations
    ) async throws -> [UInt32: WalletSignActionSpend] {
        guard var transaction = try partial.beef.transaction(for: partial.subjectTransactionID,
                limits: StorageLimits.transaction),
              transaction.inputs.count >= spending.count else {
            throw MessageBoxAdvertisementError.noTransaction
        }
        for (index, advertisement) in spending.enumerated() {
            guard transaction.inputs[index].previousOutput == advertisement.outpoint else {
                throw MessageBoxAdvertisementError.noTransaction
            }
            transaction.inputs[index].sourceOutput = TransactionOutput(
                satoshis: advertisement.satoshis, lockingScript: advertisement.lockingScript)
        }
        var spends: [UInt32: WalletSignActionSpend] = [:]
        for index in spending.indices {
            try await transaction.signPushDropInput(at: index, using: keys, protocolID: protocolID(),
                keyID: WalletKeyID(keyID), counterparty: .anyone, lockPosition: .beforeCompatibility,
                hashType: .all, limits: StorageLimits.transaction)
            spends[UInt32(index)] = try WalletSignActionSpend(unlockingScript: transaction.inputs[index].unlockingScript.bytes)
        }
        return spends
    }
}
