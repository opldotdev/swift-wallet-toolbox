import Foundation
import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxStorage

/// Durable PeerPay delivery. One unresolved payment per sender prevents a failed
/// send from becoming a second spend. Recovery submits the same signed BEEF and
/// the same encrypted envelope; it never calls createAction again.
public actor MessageBoxOutbox {
    private let directory: URL
    private let resolveHost: @Sendable (PublicKey, URL) async throws -> URL
    private let makeClient: @Sendable (URL, ProtoWallet) throws -> MessageBoxClient
    private var active: Set<String> = []

    public init(directory: URL) {
        self.directory = directory
        self.resolveHost = { try await MessageBoxDiscovery().host(for: $0, fallback: $1) }
        self.makeClient = { try MessageBoxClient(host: $0, wallet: $1) }
    }

    init(directory: URL,
        resolveHost: @escaping @Sendable (PublicKey, URL) async throws -> URL,
        makeClient: @escaping @Sendable (URL, ProtoWallet) throws -> MessageBoxClient) {
        self.directory = directory
        self.resolveHost = resolveHost
        self.makeClient = makeClient
    }

    public func pending(for sender: PublicKey) throws -> MessageBoxPendingPayment? {
        try load(Hex.encode(sender.compressedBytes))
    }

    public func send(wallet: RemoteWallet, to recipient: PublicKey, satoshis: UInt64,
        description: String, fallbackHost: URL) async throws -> String {
        try await send(wallet: wallet as any MessageBoxPayingWallet, to: recipient,
            satoshis: satoshis, description: description, fallbackHost: fallbackHost)
    }

    func send(wallet: any MessageBoxPayingWallet, to recipient: PublicKey, satoshis: UInt64,
        description: String, fallbackHost: URL) async throws -> String {
        let sender = wallet.messageBoxIdentity
        guard active.insert(sender).inserted else { throw MessageBoxOutboxError.busy }
        defer { active.remove(sender) }
        if let pending = try load(sender) { throw MessageBoxOutboxError.pending(pending.txid) }
        guard satoshis > 0 else { throw MessageBoxOutboxError.invalidAmount }
        let host = try await resolveHost(recipient, fallbackHost)
        let client = try makeClient(host, wallet.protoWallet)
        try await client.requireFreeDelivery(to: recipient)
        try Task.checkCancellation()
        let prefix = try await Self.nonce(wallet.protoWallet)
        let suffix = try await Self.nonce(wallet.protoWallet)
        do {
            let payment = try await wallet.createMessageBoxPayment(recipient: recipient, satoshis: satoshis,
                derivationPrefix: prefix, derivationSuffix: suffix, description: description,
                beforeBroadcast: { payment in
                    try Task.checkCancellation()
                    let token = MessageBoxPaymentToken(derivationPrefix: prefix, derivationSuffix: suffix,
                        transaction: payment.atomicBEEF, amount: satoshis, outputIndex: payment.outputIndex)
                    let envelope = try await client.preparePayment(to: recipient, token: token)
                    try await self.persist(MessageBoxPendingPayment(sender: sender,
                        recipient: Hex.encode(recipient.compressedBytes), amount: satoshis,
                        txid: payment.transactionID.displayHex, host: host, reference: payment.reference,
                        atomicBEEF: payment.atomicBEEF, envelope: envelope, broadcastAccepted: false))
                })
            guard payment.results.contains(where: {
                $0.txid == payment.transactionID.displayHex && $0.status != .failed
            }) else { throw MessageBoxOutboxError.broadcastUncertain }
            guard var pending = try load(sender) else { throw MessageBoxOutboxError.missingPayment }
            pending.broadcastAccepted = true
            try persist(pending)
            try Task.checkCancellation()
            try await client.deliver(pending.envelope)
            try remove(sender)
            return pending.txid
        } catch {
            if let pending = try load(sender) { throw MessageBoxOutboxError.pending(pending.txid) }
            throw error
        }
    }

    /// Uses the originally selected host, even if the default was changed later.
    /// Returning success means server acceptance, not recipient internalization.
    public func retry(wallet: RemoteWallet) async throws -> String {
        try await retry(wallet: wallet as any MessageBoxPayingWallet)
    }

    func retry(wallet: any MessageBoxPayingWallet) async throws -> String {
        let sender = wallet.messageBoxIdentity
        guard active.insert(sender).inserted else { throw MessageBoxOutboxError.busy }
        defer { active.remove(sender) }
        guard var pending = try load(sender) else { throw MessageBoxOutboxError.missingPayment }
        if !pending.broadcastAccepted {
            try Task.checkCancellation()
            try await wallet.resumeMessageBoxPayment(pending)
            pending.broadcastAccepted = true
            try persist(pending)
        }
        try Task.checkCancellation()
        let client = try makeClient(pending.host, wallet.protoWallet)
        try await client.deliver(pending.envelope)
        try remove(sender)
        return pending.txid
    }

    private func file(_ sender: String) throws -> URL {
        // Do not allow an identifier from persisted data to become a path.
        _ = try PublicKey(Hex.decode(sender, maximumDecodedByteCount: 33))
        return directory.appendingPathComponent(sender.lowercased() + ".json")
    }

    private func load(_ sender: String) throws -> MessageBoxPendingPayment? {
        let url = try file(sender)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= 64 << 20 else { throw MessageBoxOutboxError.invalidRecord }
        let record = try JSONDecoder().decode(MessageBoxPendingPayment.self, from: Data(contentsOf: url))
        guard record.sender == sender, record.envelope.recipient == record.recipient,
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
        let url = try file(record.sender)
        try JSONEncoder().encode(record).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private func remove(_ sender: String) throws { try FileManager.default.removeItem(at: file(sender)) }

    /// SDK createNonce: 16 random bytes followed by the wallet's server HMAC.
    private static func nonce(_ wallet: ProtoWallet) async throws -> String {
        let random = (0..<16).map { _ in UInt8.random(in: .min ... .max) }
        let hmac = try await wallet.createHMAC(WalletCreateHMACRequest(
            protocolID: WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: "server hmac"),
            keyID: WalletKeyID(String(decoding: random, as: UTF8.self)), data: random))
        return Data(random + hmac.hmac.bytes).base64EncodedString()
    }
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
    var broadcastAccepted: Bool
}

public enum MessageBoxOutboxError: Error, LocalizedError, Sendable {
    case busy, invalidAmount, missingPayment, invalidRecord, broadcastUncertain
    case pending(String)
    public var errorDescription: String? {
        switch self {
        case .busy: "A MessageBox payment is already in progress for this account."
        case .invalidAmount: "Enter a positive payment amount."
        case .missingPayment: "There is no pending MessageBox payment to retry."
        case .invalidRecord: "The saved payment needs recovery. A new payment was not created."
        case .broadcastUncertain: "The transaction's broadcast is not confirmed. Retry the saved payment."
        case .pending: "A payment is saved but delivery is not confirmed. Retry delivery; do not send another payment."
        }
    }
}
