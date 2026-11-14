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

/// What submitting an advertisement transaction to `tm_messagebox` did, as TS `TopicBroadcaster`
/// settles it: the interested hosts that took it, and those that failed or answered with nothing.
/// One host taking it is enough.
public struct MessageBoxAdvertisementBroadcast: Sendable, Equatable {
    public let transactionID: TransactionID
    public let acceptedHosts: [OverlayHost]
    public let failedHosts: [OverlayHost]

    public init(transactionID: TransactionID, acceptedHosts: [OverlayHost], failedHosts: [OverlayHost]) {
        self.transactionID = transactionID
        self.acceptedHosts = acceptedHosts
        self.failedHosts = failedHosts
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
    /// No SHIP host advertises `tm_messagebox` (TS `ERR_NO_HOSTS_INTERESTED`).
    case noInterestedHosts
    /// Every interested host failed or answered with nothing (TS `ERR_ALL_HOSTS_REJECTED`).
    case allHostsRejected
    /// No host that took the transaction admitted it to `tm_messagebox`
    /// (TS `ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED`).
    case notAcknowledged

    public var errorDescription: String? {
        switch self {
        case .invalidHost: "A MessageBox host to advertise must be a public HTTPS URL."
        case .unexpectedLookupAnswer: "The overlay did not answer the advertisement lookup with outputs."
        case .noTransaction: "The wallet did not return the advertisement transaction."
        case .noInterestedHosts: "No overlay host takes MessageBox advertisements on this network."
        case .allHostsRejected: "Every overlay host rejected the advertisement transaction."
        case .notAcknowledged: "No overlay host admitted the advertisement."
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

    typealias Broadcast = @Sendable (AtomicBEEF) async throws -> MessageBoxAdvertisementBroadcast

    private let resolver: any OverlayLookupResolving
    private let broadcast: Broadcast

    /// As TS `networkPreset`: a testnet identity advertises on, and looks up from, testnet
    /// trackers only.
    public init(network: BitcoinNetwork = .mainnet) throws {
        let configuration = try OverlayHTTPConfiguration(beefLimits: StorageLimits.beef)
        let resolver = try LookupResolver(facilitator: HTTPSOverlayLookupFacilitator(configuration: configuration),
            slapTrackers: MessageBoxDiscovery.slapTrackers(for: network).map { try OverlayHost(rawValue: $0) },
            beefLimits: StorageLimits.beef)
        self.init(resolver: resolver, facilitator: HTTPSOverlayTopicFacilitator(configuration: configuration))
    }

    /// Submits through `facilitator` to the SHIP hosts `resolver` finds for `tm_messagebox`.
    init(resolver: any OverlayLookupResolving, facilitator: any TopicFacilitator) {
        self.init(resolver: resolver) { atomic in
            try await MessageBoxAdvertiser.submit(atomic, resolver: resolver, facilitator: facilitator)
        }
    }

    init(resolver: any OverlayLookupResolving, broadcast: @escaping Broadcast) {
        self.resolver = resolver
        self.broadcast = broadcast
    }

    /// TS `TopicBroadcaster(['tm_messagebox'], { networkPreset }).broadcast`: submits to every
    /// SHIP host advertising the topic at once and keeps the hosts that answered with
    /// instructions; a host that failed, or answered with none, is dropped and reported. It
    /// succeeds once one host took the transaction and one of those admitted it to the topic (TS
    /// defaults: no acknowledgment asked of every host, the topic of any one).
    static func submit(
        _ atomic: AtomicBEEF, resolver: any OverlayLookupResolving, facilitator: any TopicFacilitator
    ) async throws -> MessageBoxAdvertisementBroadcast {
        let topic = try OverlayTopic(rawValue: Self.topic)
        let tagged = try TaggedBEEF(beef: atomic.serialized(limits: StorageLimits.beef), topics: [topic])
        let hosts = try await interestedHosts(topic, resolver: resolver)
        guard !hosts.isEmpty else { throw MessageBoxAdvertisementError.noInterestedHosts }
        try Task.checkCancellation()
        let answers = await withTaskGroup(of: (OverlayHost, Steak?).self,
                                          returning: [OverlayHost: Steak].self) { group in
            for host in hosts {
                group.addTask {
                    guard let steak = try? await facilitator.submit(tagged, to: host),
                          !steak.instructions.isEmpty else { return (host, nil) }
                    return (host, steak)
                }
            }
            var answers: [OverlayHost: Steak] = [:]
            for await (host, steak) in group { answers[host] = steak }
            return answers
        }
        let accepted = hosts.filter { answers[$0] != nil }
        guard !accepted.isEmpty else { throw MessageBoxAdvertisementError.allHostsRejected }
        guard accepted.contains(where: { answers[$0]?.acknowledges(topic) == true }) else {
            throw MessageBoxAdvertisementError.notAcknowledged
        }
        return MessageBoxAdvertisementBroadcast(transactionID: atomic.subjectTransactionID,
            acceptedHosts: accepted, failedHosts: hosts.filter { answers[$0] == nil })
    }

    /// The hosts whose SHIP advertisement names `topic`, as TS `findInterestedHosts` reads them.
    static func interestedHosts(_ topic: OverlayTopic, resolver: any OverlayLookupResolving) async throws -> [OverlayHost] {
        let answer = try await resolver.resolve(LookupQuestion(service: OverlayService(rawValue: "ls_ship"),
            query: Array(#"{"topics":["\#(topic.rawValue)"]}"#.utf8)))
        guard case .outputList(let outputs) = answer else { throw MessageBoxAdvertisementError.unexpectedLookupAnswer }
        var hosts: Set<OverlayHost> = []
        for output in outputs {
            guard let transaction = try? subject(output.beef),
                  Int(output.outputIndex) < transaction.outputs.count,
                  let token = try? OverlayAdminTokenCodec.decode(transaction.outputs[Int(output.outputIndex)].lockingScript),
                  case .ship(let advertised) = token.subject, advertised == topic else { continue }
            hosts.insert(token.host)
        }
        return hosts.sorted()
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
    /// wallet holds as spendable in the basket. Returns what the overlay submission did.
    ///
    /// TS goes on with no earlier advertisements to spend when the lookup fails. This throws
    /// instead, so a failed lookup never leaves an older advertisement live beside the new one.
    public func anoint(_ host: URL, wallet: RemoteWallet) async throws -> MessageBoxAdvertisementBroadcast {
        try await anoint(host, using: wallet)
    }

    /// Spends one advertisement without replacing it, as TS `revokeHostAdvertisement`.
    public func revoke(_ advertisement: MessageBoxAdvertisement, wallet: RemoteWallet) async throws -> MessageBoxAdvertisementBroadcast {
        try await revoke(advertisement, using: wallet)
    }

    func anoint(_ host: URL, using wallet: some MessageBoxAdvertisingWallet) async throws -> MessageBoxAdvertisementBroadcast {
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

    func revoke(_ advertisement: MessageBoxAdvertisement, using wallet: some MessageBoxAdvertisingWallet) async throws -> MessageBoxAdvertisementBroadcast {
        let created = try await wallet.createAction(WalletCreateActionRequest(
            description: "Revoke MessageBox host advertisement",
            inputBEEF: advertisement.beef,
            inputs: [try WalletCreateActionInput(outpoint: advertisement.outpoint,
                inputDescription: "Revoking host advertisement token",
                unlockingScriptLength: Self.unlockingScriptLength)]))
        return try await finish(created, spending: [advertisement], using: wallet)
    }

    /// Signs the advertisements the action spends, has the wallet finish and broadcast it, then
    /// submits it to `tm_messagebox`. Should signing fail, or the task be cancelled, before the
    /// wallet signed, the action is aborted so its inputs are released.
    private func finish(
        _ created: WalletCreateActionResult, spending: [MessageBoxAdvertisement],
        using wallet: some MessageBoxAdvertisingWallet
    ) async throws -> MessageBoxAdvertisementBroadcast {
        guard let signable = created.signableTransaction else {
            guard let transaction = created.transaction, spending.isEmpty else {
                throw MessageBoxAdvertisementError.noTransaction
            }
            return try await broadcast(transaction)
        }
        let signed: WalletSignActionResult
        do {
            try Task.checkCancellation()
            let spends = try await Self.spends(signable.transaction, spending: spending, keys: wallet.advertisementKeys)
            try Task.checkCancellation()
            signed = try await wallet.signAction(WalletSignActionRequest(reference: signable.reference,
                spends: spends, options: WalletSignActionOptions(acceptDelayedBroadcast: false)))
        } catch {
            let reference = signable.reference
            // Not in this task, which may be the cancelled one.
            await Task { _ = try? await wallet.abortAction(WalletAbortActionRequest(reference: reference)) }.value
            throw error
        }
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
