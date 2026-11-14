import Foundation
import BSVCore
import BSVKeys
import BSVOverlay
import BSVTransaction
import BSVWallet
import ToolboxCore
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
///
/// The record says how far delivery got (``MessageBoxDelivery``), and it is saved as offered
/// before each request leaves. Once a server may hold the signed transaction, the recipient can
/// broadcast it by accepting the payment, so the funded action is never aborted after that: only
/// a payment no server holds can be discarded for its coins, and anything offered goes forward
/// with Retry, which broadcasts it. A payment no server holds is never offered again: storage may
/// already have released its action, so Discard is its only way out. A payment storage failed for
/// good (it expired the unsigned action) can no longer be broadcast by this wallet and is only
/// forgotten.
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
    /// A file in the directory whose name is not `<sender>.<recipient key>.json` is not a saved
    /// payment and is passed over.
    public func pending(for sender: PublicKey) throws -> [MessageBoxPendingPayment] {
        let hex = Hex.encode(sender.compressedBytes)
        try migrateSingleRecord(hex)
        let prefix = hex + "."
        guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: directory.path).filter { $0.hasPrefix(prefix) && $0.hasSuffix(".json") }.sorted().compactMap { name in
            let recipient = String(name.dropFirst(prefix.count).dropLast(".json".count))
            guard Self.isKey(recipient) else { return nil }
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
        let attempt = SendAttempt()
        do {
            let payment = try await wallet.createMessageBoxPayment(recipient: recipient, satoshis: satoshis,
                derivationPrefix: prefix, derivationSuffix: suffix, description: description,
                beforeBroadcast: { payment in
                    try Task.checkCancellation()
                    let token = MessageBoxPaymentToken(derivationPrefix: prefix, derivationSuffix: suffix,
                        transaction: payment.atomicBEEF, amount: satoshis, outputIndex: payment.outputIndex)
                    let envelope = try await client.preparePayment(to: recipient, token: token)
                    var record = MessageBoxPendingPayment(sender: sender,
                        recipient: payee, amount: satoshis,
                        txid: payment.transactionID.displayHex, host: host, reference: payment.reference,
                        atomicBEEF: payment.atomicBEEF, envelope: envelope, broadcastAccepted: false,
                        delivery: .offered)
                    // Saved as offered before the request leaves: from then on the server may hold
                    // the signed transaction, and a recipient who accepts it broadcasts it.
                    try await self.persist(record)
                    do {
                        try await Self.deliver(envelope, with: client)
                    } catch let refusal as MessageBoxError where refusal.isRefusal {
                        // This envelope's one offer was turned down, so no server holds it. Nothing
                        // is broadcast: throwing here makes the wallet abort the funded action, and
                        // the record goes once storage confirms the abort.
                        await attempt.refused(refusal)
                        record.delivery = .notOffered
                        try await self.persist(record)
                        throw refusal
                    } catch {
                        // Undecided: the server may hold the message. Broadcast, and keep the
                        // payment for Retry, which resends this same envelope.
                        return
                    }
                    // Nothing may throw from here: the wallet would abort an action the server
                    // now holds. The record says accepted once the broadcast is.
                    await attempt.delivered()
                })
            guard payment.results.contains(where: {
                $0.txid == payment.transactionID.displayHex && $0.status != .failed
            }) else { throw MessageBoxOutboxError.broadcastUncertain }
            guard var pending = try load(sender, payee) else { throw MessageBoxOutboxError.missingPayment }
            pending.broadcastAccepted = true
            if await attempt.isDelivered { pending.delivery = .accepted }
            try persist(pending)
            try Task.checkCancellation()
            if pending.delivery != .accepted { try await Self.deliver(pending.envelope, with: client) }
            try remove(sender, payee)
            return pending.txid
        } catch {
            if let refusal = await attempt.refusal {
                // Refused before the broadcast. The wallet rethrows the refusal only once storage
                // confirmed the abort; otherwise the payment stays saved, never offered, for Discard.
                guard case BRC29PaymentError.notReleased = error else {
                    if try load(sender, payee) != nil { try remove(sender, payee) }
                    throw refusal
                }
                guard var pending = try load(sender, payee) else { throw refusal }
                if pending.delivery != .notOffered {
                    pending.delivery = .notOffered
                    try persist(pending)
                }
                throw MessageBoxOutboxError.notReleased(txid: pending.txid, reason: Self.reason(refusal))
            }
            if var pending = try load(sender, payee) {
                if !pending.broadcastAccepted && Self.isFailedAction(error) {
                    pending.broadcastRefused = true
                    try persist(pending)
                    throw MessageBoxOutboxError.broadcastRefused(pending.txid)
                }
                throw MessageBoxOutboxError.notDelivered(txid: pending.txid, reason: Self.reason(error))
            }
            throw error
        }
    }

    /// Delivers the saved payment to `recipient` again, on the host it was first sent to, even if
    /// the default was changed later. Returning success means server acceptance, not recipient
    /// internalization.
    ///
    /// Only a payment that was offered is retried. One storage has not accepted yet is broadcast
    /// first: its signed transaction is out of this wallet's hands, so putting it on chain only
    /// settles this wallet's own coins. A server that answers with `ERR_DUPLICATE_MESSAGE` already
    /// holds this envelope, which counts as delivered.
    ///
    /// A payment no server holds throws ``MessageBoxOutboxError/neverSent(_:)``: storage may already
    /// have released its action (an abort whose answer was lost, or storage failing an abandoned
    /// unsigned action), so offering it now could hand the recipient a transaction whose coins this
    /// wallet spends elsewhere. When storage refuses the broadcast for good, because it failed the
    /// action, the payment is marked so and ``MessageBoxOutboxError/broadcastRefused(_:)`` is thrown;
    /// Discard then forgets it.
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
        if pending.broadcastRefused { throw MessageBoxOutboxError.broadcastRefused(pending.txid) }
        if pending.delivery == .notOffered { throw MessageBoxOutboxError.neverSent(pending.txid) }
        do {
            try Task.checkCancellation()
            if !pending.broadcastAccepted {
                do {
                    try await wallet.resumeMessageBoxPayment(pending)
                } catch let failed where Self.isFailedAction(failed) {
                    pending.broadcastRefused = true
                    try persist(pending)
                    throw MessageBoxOutboxError.broadcastRefused(pending.txid)
                }
                pending.broadcastAccepted = true
                try persist(pending)
            }
            if pending.delivery != .accepted {
                try Task.checkCancellation()
                let client = try makeClient(pending.host, wallet.protoWallet)
                try await Self.deliver(pending.envelope, with: client)
                pending.delivery = .accepted
                try persist(pending)
            }
        } catch let error as MessageBoxOutboxError where error == .broadcastRefused(pending.txid) {
            throw error
        } catch {
            throw MessageBoxOutboxError.notDelivered(txid: pending.txid, reason: Self.reason(error))
        }
        try remove(sender, pending.recipient)
        return pending.txid
    }

    /// Drops the saved payment to `recipient`.
    ///
    /// A payment no server holds and storage never accepted for broadcast is aborted first, and
    /// dropped only once storage confirms the abort, so its coins come back. A payment that was
    /// offered to a server is not aborted, because the recipient can broadcast it by accepting
    /// it: ``MessageBoxOutboxError/offered(_:)`` is thrown and Retry is the way on. A broadcast
    /// payment is on chain to a key derived for the recipient: dropping it forgets the only
    /// delivery that tells the recipient how to claim it, and the coins do not come back.
    ///
    /// When storage will not abort, it is asked whether it already sent the transaction. If it
    /// did, the payment is marked broadcast and ``MessageBoxOutboxError/alreadySent(_:)`` is thrown;
    /// discarding it again forgets it. When storage refuses the abort with WERR_INVALID_PARAMETER
    /// on `reference`, which TS `findAbortableTransaction` throws for a sent, failed or unknown
    /// action, and does not hold it as sent, it already released it. Any other failure keeps the
    /// payment, so Discard can be tried again.
    ///
    /// A payment storage failed for good is dropped without an abort, as ``MessageBoxDiscarded/abandoned(txid:)``.
    @discardableResult
    public func discard(wallet: RemoteWallet, recipient: String) async throws -> MessageBoxDiscarded {
        try await discard(wallet: wallet as any MessageBoxPayingWallet, recipient: recipient)
    }

    func discard(wallet: any MessageBoxPayingWallet, recipient: String) async throws -> MessageBoxDiscarded {
        let sender = wallet.messageBoxIdentity
        guard active.insert(sender).inserted else { throw MessageBoxOutboxError.busy }
        defer { active.remove(sender) }
        try migrateSingleRecord(sender)
        guard var pending = try load(sender, recipient.lowercased()) else {
            throw MessageBoxOutboxError.missingPayment
        }
        if pending.broadcastAccepted {
            try remove(sender, pending.recipient)
            return .forgotten(txid: pending.txid)
        }
        if pending.broadcastRefused {
            try remove(sender, pending.recipient)
            return .abandoned(txid: pending.txid)
        }
        guard pending.delivery == .notOffered else { throw MessageBoxOutboxError.offered(pending.txid) }
        let failure: any Error
        var storageRefused = false
        do {
            if try await wallet.abandonMessageBoxPayment(pending) {
                try remove(sender, pending.recipient)
                return .released(txid: pending.txid)
            }
            failure = MessageBoxOutboxError.abortRefused(pending.txid)
        } catch WireError.invalidParameter(name: "reference", _) {
            // TS `abortAction` refuses an action that is sent, already failed or unknown with this
            // one error. Anything else (WERR_INTERNAL, WERR_NOT_ACTIVE, a dropped connection)
            // decided nothing about the reservation.
            storageRefused = true
            failure = MessageBoxOutboxError.abortRefused(pending.txid)
        } catch {
            failure = error
        }
        let sent: Bool
        do {
            sent = try await wallet.messageBoxPaymentWasSent(pending)
        } catch {
            throw failure
        }
        guard sent else {
            // Never offered, so this wallet never asked storage to broadcast it. Storage holds it
            // neither as abortable nor as sent: an earlier abort went through and its answer was
            // lost, and nothing is reserved for it any more.
            guard storageRefused else { throw failure }
            try remove(sender, pending.recipient)
            return .released(txid: pending.txid)
        }
        pending.broadcastAccepted = true
        try persist(pending)
        throw MessageBoxOutboxError.alreadySent(pending.txid)
    }

    /// Delivers `envelope`. message-box-server refuses a message ID it already stores with 400
    /// `ERR_DUPLICATE_MESSAGE`; the ID is this envelope's own HMAC, so the server holds this very
    /// envelope and the delivery is done, as webrtpay's `MessageBoxSignaler` reads it.
    private static func deliver(_ envelope: MessageBoxEnvelope, with client: MessageBoxClient) async throws {
        do {
            try await client.deliver(envelope)
        } catch let error as MessageBoxError where error.isDuplicate {
            return
        }
    }

    /// Storage will never broadcast this action: TS `validatePlannedTransaction` throws
    /// WERR_INVALID_OPERATION "invalid transaction status failed" once storage failed it (an abort,
    /// or the monitor failing an abandoned unsigned action). Every other failure may pass.
    static func isFailedAction(_ error: any Error) -> Bool {
        guard case WireError.invalidOperation(let message) = error else { return false }
        return message.contains("invalid transaction status failed")
    }

    private static func isKey(_ hex: String) -> Bool {
        (try? PublicKey(Hex.decode(hex, maximumDecodedByteCount: 33))) != nil
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
    /// an earlier version is still retried, never lost. One that cannot be read, or whose
    /// recipient already has a saved payment, is renamed out of the way (`<sender>.json.unreadable-…`)
    /// and kept on disk, so it no longer blocks every payment from this sender.
    private func migrateSingleRecord(_ sender: String) throws {
        _ = try PublicKey(Hex.decode(sender, maximumDecodedByteCount: 33))
        let old = directory.appendingPathComponent(sender.lowercased() + ".json")
        guard FileManager.default.fileExists(atPath: old.path) else { return }
        let new: URL
        do {
            let record = try decode(old, sender: sender)
            new = try file(sender, record.recipient)
        } catch {
            return try quarantine(old)
        }
        if FileManager.default.fileExists(atPath: new.path) { return try quarantine(old) }
        try FileManager.default.moveItem(at: old, to: new)
    }

    private func quarantine(_ url: URL) throws {
        let aside = url.deletingLastPathComponent().appendingPathComponent(
            url.lastPathComponent + ".unreadable-" + UUID().uuidString.lowercased())
        try FileManager.default.moveItem(at: url, to: aside)
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

/// What the delivery made before the broadcast came to, within one `send`.
private actor SendAttempt {
    private(set) var isDelivered = false
    private(set) var refusal: MessageBoxError?
    func delivered() { isDelivered = true }
    func refused(_ error: MessageBoxError) { refusal = error }
}

/// What ``MessageBoxOutbox/discard(wallet:recipient:)`` did.
public enum MessageBoxDiscarded: Sendable, Equatable {
    /// Never broadcast; storage aborted it and its coins are spendable again.
    case released(txid: String)
    /// Already on chain to the recipient's derived key; only the saved delivery was dropped.
    case forgotten(txid: String)
    /// Storage failed the action, so this wallet can't broadcast it and its coins are spendable
    /// again; only the saved delivery was dropped. The recipient's server may still hold the
    /// signed transaction, and the recipient can put it on chain while those coins are unspent.
    case abandoned(txid: String)
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
    /// True when storage holds the saved payment's transaction as sent to the network.
    func messageBoxPaymentWasSent(_ pending: MessageBoxPendingPayment) async throws -> Bool
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
        // Storage refuses an action already sent to the network: TS `abortAction` throws
        // WERR_INVALID_PARAMETER for it, and others answer `aborted: false`.
        try await abort(reference: pending.reference)
    }

    func messageBoxPaymentWasSent(_ pending: MessageBoxPendingPayment) async throws -> Bool {
        // A sendWith-only processAction never commits a new transaction: storage shares the txid
        // it already holds and reports its state, or reports it failed when it holds none.
        let known = try await storage.processAction(auth, StorageProcessActionRequest(
            reference: pending.reference, isNewTx: false, isSendWith: true,
            rawTX: nil, sendWith: [pending.txid]))
        return known.sendWithResults.contains(where: { $0.txid == pending.txid && $0.status != .failed })
    }

    func resumeMessageBoxPayment(_ pending: MessageBoxPendingPayment) async throws {
        // Recover a lost processAction response without asking storage to accept
        // the new-transaction state transition twice. Both attempts use one txid. A probe that
        // fails decides nothing: the new-transaction call below answers for itself.
        do {
            if try await messageBoxPaymentWasSent(pending) { return }
        } catch is CancellationError {
            throw CancellationError()
        } catch {}
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
    /// How far delivery got. Only a payment no server holds can be discarded for its coins.
    public internal(set) var delivery: MessageBoxDelivery
    /// True once storage refused the broadcast for good: it failed the action, so this wallet can
    /// never send it. Discard forgets it; the recipient may still hold it.
    public internal(set) var broadcastRefused: Bool = false
}

extension MessageBoxPendingPayment {
    private enum CodingKeys: String, CodingKey {
        case sender, recipient, amount, txid, host, reference, atomicBEEF, envelope, broadcastAccepted, delivery
        case broadcastRefused
    }

    /// A record saved before delivery was tracked reads as offered, the state that never
    /// releases coins a server might hold.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(sender: try container.decode(String.self, forKey: .sender),
            recipient: try container.decode(String.self, forKey: .recipient),
            amount: try container.decode(UInt64.self, forKey: .amount),
            txid: try container.decode(String.self, forKey: .txid),
            host: try container.decode(URL.self, forKey: .host),
            reference: try container.decode(String.self, forKey: .reference),
            atomicBEEF: try container.decode([UInt8].self, forKey: .atomicBEEF),
            envelope: try container.decode(MessageBoxEnvelope.self, forKey: .envelope),
            broadcastAccepted: try container.decode(Bool.self, forKey: .broadcastAccepted),
            delivery: try container.decodeIfPresent(MessageBoxDelivery.self, forKey: .delivery) ?? .offered,
            broadcastRefused: try container.decodeIfPresent(Bool.self, forKey: .broadcastRefused) ?? false)
    }
}

/// How far a saved payment's delivery got.
public enum MessageBoxDelivery: String, Codable, Sendable {
    /// No MessageBox server holds it: its one offer was refused, or it was never sent. Its funded
    /// action may be aborted, and it is never offered again.
    case notOffered = "not-offered"
    /// Sent with no answer that settles it, so the server may hold the signed transaction and the
    /// recipient may broadcast it. It is never aborted; Retry broadcasts it and delivers again.
    case offered
    /// A server took it.
    case accepted
}

public enum MessageBoxOutboxError: Error, LocalizedError, Sendable, Equatable {
    case busy, invalidAmount, missingPayment, invalidRecord, broadcastUncertain
    /// A payment to this recipient is saved and not delivered; a new one would pay them twice.
    case pending(String)
    /// The payment is saved but its delivery failed, for `reason`.
    case notDelivered(txid: String, reason: String)
    /// The server refused the payment, for `reason`, and nothing was broadcast, but storage did
    /// not confirm the abort: the payment is saved, never offered, and Discard releases its coins.
    case notReleased(txid: String, reason: String)
    /// Storage would not abort the saved payment, so it may already be on the network.
    case abortRefused(String)
    /// The payment was offered to the recipient's server, which may hold it, so it is not aborted.
    case offered(String)
    /// Storage already sent the payment, so its coins do not come back. It is now saved as
    /// broadcast: Retry delivers it, and Discard forgets it.
    case alreadySent(String)
    /// The payment was refused and never sent, so it is not offered again: Discard returns its coins.
    case neverSent(String)
    /// Storage failed the payment's action, so this wallet can never broadcast it. Discard forgets
    /// it; the recipient's server may still hold it.
    case broadcastRefused(String)
    public var errorDescription: String? {
        switch self {
        case .busy: "A MessageBox payment is already in progress for this account."
        case .invalidAmount: "Enter a positive payment amount."
        case .missingPayment: "There is no saved MessageBox payment to this recipient."
        case .invalidRecord: "The saved payment needs recovery. A new payment was not created."
        case .broadcastUncertain: "The transaction's broadcast is not confirmed. Retry the saved payment."
        case .pending: "A payment to this recipient is saved but not delivered. Retry or discard it before sending them another."
        case .notDelivered(_, let reason): "The payment is saved but was not delivered. \(reason)"
        case .notReleased(_, let reason): "Nothing was sent, but the payment's coins are still held. Discard it to release them. \(reason)"
        case .abortRefused: "This payment may already be on the network, so it was not discarded. Retry delivery instead."
        case .offered: "The recipient's MessageBox server may already hold this payment, and the recipient can broadcast it, so it can't be cancelled. Retry to send it."
        case .alreadySent: "This payment was already sent, so its coins won't come back. Retry delivers it to the recipient; discarding it now only forgets the delivery."
        case .neverSent: "This payment was turned down and never sent, so it isn't offered again. Discard it to return its coins, then send a new payment."
        case .broadcastRefused: "Storage gave up on this payment and won't send it, so its coins are spendable again. The recipient's MessageBox server may still hold it, and the recipient could still put it on chain while those coins are unspent. Discard it to stop retrying."
        }
    }
}
