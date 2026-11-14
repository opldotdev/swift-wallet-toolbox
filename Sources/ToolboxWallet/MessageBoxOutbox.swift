import Foundation
import BSVCore
import BSVKeys
import BSVOverlay
import BSVTransaction
import BSVWallet
import ToolboxStorage

/// Durable PeerPay delivery, one saved payment per sender and recipient.
///
/// The payment is offered to the recipient's MessageBox before it is broadcast, as `@1sat/actions`
/// `sendToHandle` keeps a handle payment `noSend` until its envelope is delivered: a server that
/// refuses the delivery (the recipient holds no account there, blocks the sender, wants a fee)
/// leaves nothing on chain, and the funded action is aborted. A delivery that decided nothing
/// (a timeout, a 5xx) does not stop the broadcast; the payment is then saved and delivered again
/// with Retry, which submits the same signed BEEF and the same encrypted envelope and never calls
/// createAction again. A saved payment blocks only another payment to the same recipient, so a
/// failed send cannot become a second spend while payments to anyone else go ahead.
public actor MessageBoxOutbox {
    private let directory: URL
    private let resolveHost: @Sendable (PublicKey, URL) async throws -> URL
    private let makeClient: @Sendable (URL, ProtoWallet) throws -> MessageBoxClient
    private var active: Set<String> = []

    /// Looks up recipients' hosts on mainnet trackers. A testnet wallet uses
    /// `init(directory:network:)` with `.testnet`.
    public init(directory: URL) {
        self.init(directory: directory, network: .mainnet)
    }

    /// Looks up recipients' hosts on `network`'s SLAP trackers, which must match the wallet's
    /// chain. Discovery is built per lookup, so a tracker error surfaces from `send`.
    public init(directory: URL, network: BitcoinNetwork) {
        self.init(directory: directory, network: network, facilitator: nil,
            makeClient: { try MessageBoxClient(host: $0, wallet: $1) })
    }

    /// Test seam: `facilitator` replaces the HTTPS lookup transport.
    init(directory: URL, network: BitcoinNetwork, facilitator: (any LookupFacilitator)?,
        makeClient: @escaping @Sendable (URL, ProtoWallet) throws -> MessageBoxClient) {
        self.init(directory: directory,
            resolveHost: { recipient, fallback in
                let discovery = try facilitator.map {
                    try MessageBoxDiscovery(network: network, facilitator: $0)
                } ?? MessageBoxDiscovery(network: network)
                return try await discovery.host(for: recipient, fallback: fallback)
            },
            makeClient: makeClient)
    }

    /// Looks up recipients' hosts with `discovery`, whose network must match the wallet's chain.
    public init(directory: URL, discovery: MessageBoxDiscovery) {
        self.init(directory: directory, discovery: discovery,
            makeClient: { try MessageBoxClient(host: $0, wallet: $1) })
    }

    init(directory: URL, discovery: MessageBoxDiscovery,
        makeClient: @escaping @Sendable (URL, ProtoWallet) throws -> MessageBoxClient) {
        self.init(directory: directory,
            resolveHost: { try await discovery.host(for: $0, fallback: $1) },
            makeClient: makeClient)
    }

    init(directory: URL,
        resolveHost: @escaping @Sendable (PublicKey, URL) async throws -> URL,
        makeClient: @escaping @Sendable (URL, ProtoWallet) throws -> MessageBoxClient) {
        self.directory = directory
        self.resolveHost = resolveHost
        self.makeClient = makeClient
    }

    /// Every saved payment from `sender`, ordered by recipient.
    public func pending(for sender: PublicKey) throws -> [MessageBoxPendingPayment] {
        let hex = Hex.encode(sender.compressedBytes)
        try migrateSingleRecord(hex)
        let prefix = hex + "."
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        let single = hex + ".json"
        return try names.filter { $0 != single && $0.hasPrefix(prefix) && $0.hasSuffix(".json") }.sorted().compactMap { name in
            let recipient = String(name.dropFirst(prefix.count).dropLast(".json".count))
            return try load(hex, recipient)
        }
    }

    public func send(wallet: RemoteWallet, to recipient: PublicKey, satoshis: UInt64,
        description: String, fallbackHost: URL) async throws -> String {
        try await send(wallet: wallet as any MessageBoxPayingWallet, to: recipient,
            satoshis: satoshis, description: description, fallbackHost: fallbackHost)
    }

    func send(wallet: any MessageBoxPayingWallet, to recipient: PublicKey, satoshis: UInt64,
        description: String, fallbackHost: URL) async throws -> String {
        let sender = wallet.messageBoxIdentity
        let payee = Hex.encode(recipient.compressedBytes)
        guard active.insert(sender).inserted else { throw MessageBoxOutboxError.busy }
        defer { active.remove(sender) }
        try migrateSingleRecord(sender)
        if let pending = try load(sender, payee) { throw MessageBoxOutboxError.pending(pending.txid) }
        guard satoshis > 0 else { throw MessageBoxOutboxError.invalidAmount }
        let host = try await resolveHost(recipient, fallbackHost)
        let client = try makeClient(host, wallet.protoWallet)
        try await client.requireFreeDelivery(to: recipient)
        try Task.checkCancellation()
        let prefix = try await Self.nonce(wallet.protoWallet)
        let suffix = try await Self.nonce(wallet.protoWallet)
        let delivery = DeliveryState()
        do {
            let payment = try await wallet.createMessageBoxPayment(recipient: recipient, satoshis: satoshis,
                derivationPrefix: prefix, derivationSuffix: suffix, description: description,
                beforeBroadcast: { payment in
                    try Task.checkCancellation()
                    let token = MessageBoxPaymentToken(derivationPrefix: prefix, derivationSuffix: suffix,
                        transaction: payment.atomicBEEF, amount: satoshis, outputIndex: payment.outputIndex)
                    let envelope = try await client.preparePayment(to: recipient, token: token)
                    try await self.persist(MessageBoxPendingPayment(sender: sender,
                        recipient: payee, amount: satoshis,
                        txid: payment.transactionID.displayHex, host: host, reference: payment.reference,
                        atomicBEEF: payment.atomicBEEF, envelope: envelope, broadcastAccepted: false))
                    do {
                        try await client.deliver(envelope)
                        await delivery.delivered()
                    } catch let refusal as MessageBoxError where refusal.isRefusal {
                        // The server said no, so nothing is broadcast: throwing here makes the
                        // wallet abort the funded action, and the saved payment goes with it.
                        try await self.remove(sender, payee)
                        throw refusal
                    } catch {
                        // Undecided: the server may hold the message. Broadcast, and keep the
                        // payment for Retry, which resends this same envelope.
                    }
                })
            guard payment.results.contains(where: {
                $0.txid == payment.transactionID.displayHex && $0.status != .failed
            }) else { throw MessageBoxOutboxError.broadcastUncertain }
            guard var pending = try load(sender, payee) else { throw MessageBoxOutboxError.missingPayment }
            pending.broadcastAccepted = true
            try persist(pending)
            try Task.checkCancellation()
            if !(await delivery.isDelivered) { try await client.deliver(pending.envelope) }
            try remove(sender, payee)
            return pending.txid
        } catch {
            if let pending = try load(sender, payee) {
                throw MessageBoxOutboxError.notDelivered(txid: pending.txid, reason: Self.reason(error))
            }
            throw error
        }
    }

    /// Delivers the saved payment to `recipient` again, on the host it was first sent to, even if
    /// the default was changed later. A payment whose broadcast was not confirmed is delivered
    /// first and broadcast after, as `send` does. Returning success means server acceptance, not
    /// recipient internalization.
    public func retry(wallet: RemoteWallet, recipient: String) async throws -> String {
        try await retry(wallet: wallet as any MessageBoxPayingWallet, recipient: recipient)
    }

    func retry(wallet: any MessageBoxPayingWallet, recipient: String) async throws -> String {
        let sender = wallet.messageBoxIdentity
        guard active.insert(sender).inserted else { throw MessageBoxOutboxError.busy }
        defer { active.remove(sender) }
        try migrateSingleRecord(sender)
        guard var pending = try load(sender, recipient.lowercased()) else {
            throw MessageBoxOutboxError.missingPayment
        }
        do {
            try Task.checkCancellation()
            let client = try makeClient(pending.host, wallet.protoWallet)
            try await client.deliver(pending.envelope)
            if !pending.broadcastAccepted {
                try Task.checkCancellation()
                try await wallet.resumeMessageBoxPayment(pending)
                pending.broadcastAccepted = true
                try persist(pending)
            }
        } catch {
            throw MessageBoxOutboxError.notDelivered(txid: pending.txid, reason: Self.reason(error))
        }
        try remove(sender, pending.recipient)
        return pending.txid
    }

    /// Drops the saved payment to `recipient`.
    ///
    /// A payment storage never accepted for broadcast is aborted first, so its coins come back;
    /// if storage will not abort it (it may already be on the network), nothing is dropped and
    /// Retry is the way on. A broadcast payment is on chain to a key derived for the recipient:
    /// dropping it forgets the only delivery that tells the recipient how to claim it, and the
    /// coins do not come back to the sender.
    @discardableResult
    public func discard(wallet: RemoteWallet, recipient: String) async throws -> MessageBoxDiscarded {
        try await discard(wallet: wallet as any MessageBoxPayingWallet, recipient: recipient)
    }

    func discard(wallet: any MessageBoxPayingWallet, recipient: String) async throws -> MessageBoxDiscarded {
        let sender = wallet.messageBoxIdentity
        guard active.insert(sender).inserted else { throw MessageBoxOutboxError.busy }
        defer { active.remove(sender) }
        try migrateSingleRecord(sender)
        guard let pending = try load(sender, recipient.lowercased()) else {
            throw MessageBoxOutboxError.missingPayment
        }
        if pending.broadcastAccepted {
            try remove(sender, pending.recipient)
            return .forgotten(txid: pending.txid)
        }
        guard try await wallet.abandonMessageBoxPayment(pending) else {
            throw MessageBoxOutboxError.abortRefused(pending.txid)
        }
        try remove(sender, pending.recipient)
        return .released(txid: pending.txid)
    }

    private static func reason(_ error: any Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }

    private func file(_ sender: String, _ recipient: String) throws -> URL {
        // Do not allow an identifier from persisted data to become a path.
        _ = try PublicKey(Hex.decode(sender, maximumDecodedByteCount: 33))
        _ = try PublicKey(Hex.decode(recipient, maximumDecodedByteCount: 33))
        return directory.appendingPathComponent(sender.lowercased() + "." + recipient.lowercased() + ".json")
    }

    /// Records saved before payments were kept per recipient sit at `<sender>.json`. Moved to the
    /// recipient's own file the first time the sender's payments are read, so a payment saved by
    /// an earlier version is still retried, never lost.
    private func migrateSingleRecord(_ sender: String) throws {
        _ = try PublicKey(Hex.decode(sender, maximumDecodedByteCount: 33))
        let old = directory.appendingPathComponent(sender.lowercased() + ".json")
        guard FileManager.default.fileExists(atPath: old.path) else { return }
        let record = try decode(old, sender: sender)
        let new = try file(sender, record.recipient)
        if FileManager.default.fileExists(atPath: new.path) { throw MessageBoxOutboxError.invalidRecord }
        try FileManager.default.moveItem(at: old, to: new)
    }

    private func load(_ sender: String, _ recipient: String) throws -> MessageBoxPendingPayment? {
        let url = try file(sender, recipient)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let record = try decode(url, sender: sender)
        guard record.recipient == recipient.lowercased() else { throw MessageBoxOutboxError.invalidRecord }
        return record
    }

    private func decode(_ url: URL, sender: String) throws -> MessageBoxPendingPayment {
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= 64 << 20 else { throw MessageBoxOutboxError.invalidRecord }
        let record = try JSONDecoder().decode(MessageBoxPendingPayment.self, from: Data(contentsOf: url))
        guard record.sender == sender.lowercased(), record.envelope.recipient == record.recipient,
              record.amount > 0, record.amount <= 2_100_000_000_000_000,
              (try? PublicKey(Hex.decode(record.recipient, maximumDecodedByteCount: 33))) != nil,
              (try? TransactionID(displayHex: record.txid)) != nil,
              (try? MessageBoxHost.configured(record.host.absoluteString)) != nil else {
            throw MessageBoxOutboxError.invalidRecord
        }
        return record
    }

    private func persist(_ record: MessageBoxPendingPayment) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let url = try file(record.sender, record.recipient)
        try JSONEncoder().encode(record).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private func remove(_ sender: String, _ recipient: String) throws {
        try FileManager.default.removeItem(at: file(sender, recipient))
    }

    /// SDK createNonce: 16 random bytes followed by the wallet's server HMAC.
    private static func nonce(_ wallet: ProtoWallet) async throws -> String {
        let random = (0..<16).map { _ in UInt8.random(in: .min ... .max) }
        let hmac = try await wallet.createHMAC(WalletCreateHMACRequest(
            protocolID: WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: "server hmac"),
            keyID: WalletKeyID(String(decoding: random, as: UTF8.self)), data: random))
        return Data(random + hmac.hmac.bytes).base64EncodedString()
    }
}

/// Whether the delivery made before the broadcast was accepted.
private actor DeliveryState {
    private(set) var isDelivered = false
    func delivered() { isDelivered = true }
}

/// What ``MessageBoxOutbox/discard(wallet:recipient:)`` did.
public enum MessageBoxDiscarded: Sendable, Equatable {
    /// Never broadcast; storage aborted it and its coins are spendable again.
    case released(txid: String)
    /// Already on chain to the recipient's derived key; only the saved delivery was dropped.
    case forgotten(txid: String)
}

/// Internal seam for offline delivery-failure tests; the public API takes the
/// concrete RemoteWallet so callers cannot accidentally omit wallet validation.
protocol MessageBoxPayingWallet: Sendable {
    var messageBoxIdentity: String { get }
    var protoWallet: ProtoWallet { get }
    func createMessageBoxPayment(recipient: PublicKey, satoshis: UInt64,
        derivationPrefix: String, derivationSuffix: String, description: String,
        beforeBroadcast: @escaping @Sendable (CounterpartyPayment) async throws -> Void) async throws -> CounterpartyPayment
    func resumeMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws
    /// Aborts the saved payment's action. True when storage released it.
    func abandonMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws -> Bool
}

extension RemoteWallet: MessageBoxPayingWallet {
    var messageBoxIdentity: String { auth.identityKey }
    func createMessageBoxPayment(recipient: PublicKey, satoshis: UInt64,
        derivationPrefix: String, derivationSuffix: String, description: String,
        beforeBroadcast: @escaping @Sendable (CounterpartyPayment) async throws -> Void) async throws -> CounterpartyPayment {
        try await payToCounterparty(recipient: recipient, satoshis: satoshis,
            derivationPrefix: derivationPrefix, derivationSuffix: derivationSuffix,
            description: description, labels: ["peerpay"], beforeBroadcast: beforeBroadcast)
    }

    func abandonMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws -> Bool {
        // Storage refuses (`aborted: false`) for an action already sent to the network.
        try await abort(reference: pending.reference)
    }

    func resumeMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws {
        // Recover a lost processAction response without asking storage to accept
        // the new-transaction state transition twice. Both attempts use one txid.
        let known = try? await storage.processAction(auth, StorageProcessActionRequest(
            reference: pending.reference, isNewTx: false, isSendWith: true,
            rawTX: nil, sendWith: [pending.txid]))
        if known?.sendWithResults.contains(where: {
            $0.txid == pending.txid && $0.status != .failed
        }) == true { return }
        try Task.checkCancellation()
        let envelope = try AtomicBEEF(bytes: pending.atomicBEEF, limits: StorageLimits.beef)
        guard envelope.subjectTransactionID.displayHex == pending.txid,
              let transaction = try envelope.beef.transaction(for: envelope.subjectTransactionID, limits: StorageLimits.transaction) else {
            throw MessageBoxOutboxError.broadcastUncertain
        }
        let result = try await storage.processAction(auth, StorageProcessActionRequest(
            reference: pending.reference, isNewTx: true, isSendWith: false,
            rawTX: try transaction.serialized(limits: StorageLimits.transaction), sendWith: []))
        guard result.sendWithResults.contains(where: {
            $0.txid == pending.txid && $0.status != .failed
        }) else { throw MessageBoxOutboxError.broadcastUncertain }
    }
}

public struct MessageBoxPendingPayment: Codable, Sendable {
    public let sender: String
    public let recipient: String
    public let amount: UInt64
    public let txid: String
    public let host: URL
    let reference: String
    let atomicBEEF: [UInt8]
    let envelope: MessageBoxEnvelope
    /// True once storage accepted the transaction for broadcast: the coins have left the sender.
    public internal(set) var broadcastAccepted: Bool
}

public enum MessageBoxOutboxError: Error, LocalizedError, Sendable, Equatable {
    case busy, invalidAmount, missingPayment, invalidRecord, broadcastUncertain
    /// A payment to this recipient is saved and not delivered; a new one would pay them twice.
    case pending(String)
    /// The payment is saved but its delivery failed, for `reason`.
    case notDelivered(txid: String, reason: String)
    /// Storage would not abort the saved payment, so it may already be on the network.
    case abortRefused(String)
    public var errorDescription: String? {
        switch self {
        case .busy: "A MessageBox payment is already in progress for this account."
        case .invalidAmount: "Enter a positive payment amount."
        case .missingPayment: "There is no saved MessageBox payment to this recipient."
        case .invalidRecord: "The saved payment needs recovery. A new payment was not created."
        case .broadcastUncertain: "The transaction's broadcast is not confirmed. Retry the saved payment."
        case .pending: "A payment to this recipient is saved but not delivered. Retry or discard it before sending them another."
        case .notDelivered(_, let reason): "The payment is saved but was not delivered. \(reason)"
        case .abortRefused: "This payment may already be on the network, so it was not discarded. Retry delivery instead."
        }
    }
}
