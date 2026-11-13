import Foundation
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxCore
import ToolboxStorage

/// A PeerPay payment waiting in `payment_inbox`, as `@bsv/message-box-client` `PeerPayClient`
/// reads one: the message it came in, the sender's identity key (compressed, lowercase hex) and
/// the payment token.
public struct MessageBoxIncomingPayment: Sendable, Equatable {
    public let messageId: String
    public let sender: String
    public let token: MessageBoxPaymentToken

    public init(messageId: String, sender: String, token: MessageBoxPaymentToken) {
        self.messageId = messageId; self.sender = sender; self.token = token
    }
}

/// The payments one ``MessageBoxClient/incomingPayments(offset:beforeOpening:)`` call read.
/// `truncated` is true when the inbox holds more messages than one listing reads (TS: 1,000
/// over 10 pages); accept or acknowledge these and list again for the rest, or list from
/// `nextOffset` to read past messages that stay in the inbox.
public struct MessageBoxPaymentListing: Sendable, Equatable {
    public let payments: [MessageBoxIncomingPayment]
    public let truncated: Bool
    /// The inbox offset just past the last message this listing read, counting messages that
    /// were not payments or could not be read, since those stay in the inbox. Each message
    /// acknowledged since moves the rest one place earlier, so subtract those, or list from 0.
    public let nextOffset: Int
    /// Rows the server returned that could not be read as messages at all, as
    /// ``MessageBoxListing/skipped`` counts them. Messages that were read but are not payments
    /// are not counted.
    public let skipped: Int

    public init(payments: [MessageBoxIncomingPayment], truncated: Bool, nextOffset: Int, skipped: Int = 0) {
        self.payments = payments; self.truncated = truncated; self.nextOffset = nextOffset; self.skipped = skipped
    }
}

/// What ``MessageBoxClient/accept(_:wallet:beforeAcknowledge:)`` did.
public struct MessageBoxAcceptedPayment: Sendable, Equatable {
    /// The payment as the server listed it at the time of acceptance.
    public let payment: MessageBoxIncomingPayment
    /// True when the message also carried a MessageBox recipient payment with wallet-payment
    /// outputs, and the wallet internalized it.
    public let recipientPaymentInternalized: Bool
    /// False when the payment was internalized but the message was not removed: the server did
    /// not confirm it, or the caller's `beforeAcknowledge` check threw. The funds are in the
    /// wallet either way; a later acknowledge removes it.
    public let acknowledged: Bool
}

/// The TS `PeerPayClient` errors for accepting a payment, with its messages.
public enum MessageBoxPaymentError: Error, LocalizedError, Equatable, Sendable {
    case invalidMessageID, alreadyProcessing, notInInbox, settlementFailed
    /// The message's envelope carried a payment that was not internalized; the reason says
    /// whether it ever can be. TS reports both as the `failed` payment outcome. Do not
    /// acknowledge a message whose payment was `refused`. `catch .recipientPaymentFailed` without
    /// a reason still catches both.
    case recipientPaymentFailed(RecipientPaymentFailure)
    /// ``MessageBoxClient/accept(_:wallet:beforeAcknowledge:)`` internalized the PeerPay token,
    /// but not the payment the message's envelope carried, so the message was not acknowledged.
    /// TS takes the envelope payment while listing and has no such state.
    case envelopePaymentNotTaken(MessageBoxEnvelopePaymentNotTaken)

    /// Why an envelope payment was not internalized.
    public enum RecipientPaymentFailure: Sendable, Equatable {
        /// The payment cannot be read, or a wallet-payment output in it is not this wallet's to
        /// claim. It can never be internalized, so nothing is lost by acknowledging the message.
        case unreadable
        /// The wallet or its storage refused the payment or failed. Internalizing it again may
        /// succeed; keep the message until it does.
        case refused
    }

    public var errorDescription: String? {
        switch self {
        case .invalidMessageID: "Incoming payment message ID is invalid"
        case .alreadyProcessing: "Payment message is already being processed by this client"
        case .notInInbox: "Incoming payment is not present exactly once in the authenticated inbox"
        case .settlementFailed: "BRC-29 settlement failed recipient, amount, transaction, or wallet validation."
        case .recipientPaymentFailed(.unreadable):
            "The payment this message carried cannot be read or does not pay this wallet, so it can never be internalized."
        case .recipientPaymentFailed(.refused):
            "The wallet did not internalize the payment this message carried, so the message was not acknowledged."
        case .envelopePaymentNotTaken:
            "The payment was internalized, but not the payment its message carried, so the message was not acknowledged."
        }
    }
}

/// What ``MessageBoxPaymentError/envelopePaymentNotTaken(_:)`` carries: the PeerPay token is in
/// the wallet; the message, still in the inbox, carries an envelope payment that is not.
///
/// When `reason` is `refused`, run ``MessageBoxClient/internalizeEnvelopePayment(of:wallet:)`` on
/// `message` again later and acknowledge once it returns, or accept the payment again: wallet
/// storage merges the token it already holds. When `reason` is `unreadable`, the envelope payment
/// can never be taken; acknowledge `message` to clear it from the inbox.
public struct MessageBoxEnvelopePaymentNotTaken: Sendable, Equatable {
    /// The payment whose token the wallet internalized.
    public let payment: MessageBoxIncomingPayment
    /// The message as the server listed it at acceptance, with its envelope payment.
    public let message: MessageBoxMessage
    public let reason: MessageBoxPaymentError.RecipientPaymentFailure

    public init(payment: MessageBoxIncomingPayment, message: MessageBoxMessage,
                reason: MessageBoxPaymentError.RecipientPaymentFailure) {
        self.payment = payment; self.message = message; self.reason = reason
    }
}

/// The two wallet calls accepting a payment needs. The public API takes the concrete
/// `RemoteWallet`, whose `internalizeAction` re-checks BRC-29 ownership; tests use this seam.
protocol MessageBoxReceivingWallet: Sendable {
    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult
    func internalizeAction(_ request: WalletInternalizeActionRequest) async throws -> WalletInternalizeActionResult
}

extension RemoteWallet: MessageBoxReceivingWallet {}

/// The message IDs one client is accepting, so a second accept of the same message is refused
/// while the first runs, as TS `withPaymentMutation` does.
actor MessageBoxActivePayments {
    private var messageIds: Set<String> = []
    func begin(_ messageId: String) -> Bool { messageIds.insert(messageId).inserted }
    func end(_ messageId: String) { messageIds.remove(messageId) }
}

extension MessageBoxClient {
    /// TS `PeerPayClient` bounds.
    static let maximumIncomingPayments = 1_000
    static let incomingPaymentPageSize = 100
    static let incomingPaymentPages = 10

    /// Payments waiting in this server's `payment_inbox`, as TS `listIncomingPayments` returns
    /// them: at most 1,000 messages over at most 10 pages of 100, in the server's order (oldest
    /// first), the first of any repeated message ID kept. A message that cannot be read, opened or
    /// decoded as a payment token is left out, not thrown. When the server still has more after
    /// those bounds, TS throws; here the payments read so far are returned with `truncated` set,
    /// so messages that cannot be read, which are never acknowledged, cannot hide every payment
    /// behind them.
    ///
    /// The listing starts at `offset` in the inbox. TS `listIncomingPayments` always starts at 0;
    /// its `listMessages` takes the same `offset`. When a full window holds messages that stay in
    /// the inbox, pass the listing's `nextOffset` to read the payments after them.
    ///
    /// `beforeOpening`, when given, runs before each message is decrypted with the wallet; if it
    /// throws, the listing stops with that error. Use it to stop when the wallet locks.
    public func incomingPayments(
        offset: Int = 0, beforeOpening: (@Sendable () async throws -> Void)? = nil
    ) async throws -> MessageBoxPaymentListing {
        let listed = try await listRows(messageBox: Self.paymentInbox, pageSize: Self.incomingPaymentPageSize,
            maxPages: Self.incomingPaymentPages, limit: Self.maximumIncomingPayments, offset: offset,
            skipMalformed: true)
        var seen = Set<String>()
        var payments: [MessageBoxIncomingPayment] = []
        for row in listed.rows {
            guard seen.insert(row.message.messageId).inserted else { continue }
            try Task.checkCancellation()
            try await beforeOpening?()
            if let payment = await incomingPayment(row) { payments.append(payment) }
        }
        return MessageBoxPaymentListing(payments: payments, truncated: listed.truncated, nextOffset: listed.nextOffset,
            skipped: listed.skipped)
    }

    /// Accepts a listed payment, as TS `acceptPayment` does: the message is looked up again on the
    /// server and must be there exactly once; the payment is internalized into `wallet` as a
    /// BRC-29 wallet payment with the message sender as `senderIdentityKey`, labelled `peerpay`;
    /// only then is the message acknowledged. A failed acknowledgement is reported in the result,
    /// not thrown, because the funds are already in the wallet.
    ///
    /// A message stored with a `{"message", "payment"}` envelope also carries the recipient's
    /// MessageBox payment. TS `listMessages` internalizes that payment's wallet-payment outputs
    /// while listing; here it is internalized after the token, the same way, so an envelope
    /// payment that cannot be taken never keeps the token out of the wallet. If the envelope
    /// payment is not taken, the message is not acknowledged, because it holds the only copy of
    /// that payment, and ``MessageBoxPaymentError/envelopePaymentNotTaken(_:)`` is thrown: the
    /// token is in the wallet, and the error says whether the envelope payment can be retried
    /// and carries the message to retry it on. Accepting again is also safe: wallet storage
    /// merges a repeat internalize of a transaction it already holds.
    ///
    /// `beforeAcknowledge`, when given, runs after everything is internalized and right before
    /// the acknowledgement. If it throws, the message is not acknowledged and the result reports
    /// `acknowledged` false, because the funds are already in the wallet. Use it to keep the
    /// message when the wallet locked while the payment was being accepted. TS has no such hook.
    /// It does not run when the envelope payment was not taken.
    public func accept(
        _ payment: MessageBoxIncomingPayment, wallet: RemoteWallet,
        beforeAcknowledge: (@Sendable () async throws -> Void)? = nil
    ) async throws -> MessageBoxAcceptedPayment {
        try await accept(payment, receiver: wallet, beforeAcknowledge: beforeAcknowledge)
    }

    func accept(
        _ payment: MessageBoxIncomingPayment, receiver: some MessageBoxReceivingWallet,
        beforeAcknowledge: (@Sendable () async throws -> Void)? = nil
    ) async throws -> MessageBoxAcceptedPayment {
        let messageId = try MessageBoxIncomingPayment.boundedMessageID(payment.messageId)
        guard await activePayments.begin(messageId) else { throw MessageBoxPaymentError.alreadyProcessing }
        do {
            let (incoming, message) = try await freshIncomingPayment(messageId)
            try await Self.internalize(incoming, into: receiver)
            let recipientPaymentInternalized: Bool
            do {
                recipientPaymentInternalized = try await Self.internalizeEnvelopePayment(message.payment, into: receiver)
            } catch MessageBoxPaymentError.recipientPaymentFailed(let reason) {
                throw MessageBoxPaymentError.envelopePaymentNotTaken(
                    MessageBoxEnvelopePaymentNotTaken(payment: incoming, message: message, reason: reason))
            }
            var acknowledged = true
            do {
                try await beforeAcknowledge?()
                try await acknowledge(messageIds: [incoming.messageId])
            } catch {
                acknowledged = false
            }
            await activePayments.end(messageId)
            return MessageBoxAcceptedPayment(payment: incoming, recipientPaymentInternalized: recipientPaymentInternalized,
                acknowledged: acknowledged)
        } catch {
            await activePayments.end(messageId)
            throw error
        }
    }

    /// TS `findIncomingPaymentsByMessageId`: one page of at most two, asked for by message ID.
    /// Returns the payment and the message it came in, with any envelope payment. A lookup the
    /// server reports as having more cannot show the message is there exactly once, so it is
    /// refused, as TS refuses it when its one page still has more.
    private func freshIncomingPayment(_ messageId: String) async throws -> (MessageBoxIncomingPayment, MessageBoxMessage) {
        let listed = try await listRows(messageBox: Self.paymentInbox, pageSize: 2, maxPages: 1, limit: 2,
            messageId: messageId, skipMalformed: true)
        guard !listed.truncated else { throw MessageBoxPaymentError.notInInbox }
        var matches: [(MessageBoxIncomingPayment, MessageBoxMessage)] = []
        for row in listed.rows where row.message.messageId == messageId {
            if let payment = await incomingPayment(row) { matches.append((payment, row.message)) }
        }
        guard matches.count == 1 else { throw MessageBoxPaymentError.notInInbox }
        return matches[0]
    }

    /// Internalizes the payment a listed message's `{"message", "payment"}` envelope carried, as
    /// TS `listMessages` does through `internalizeRecipientPayment`: its wallet-payment outputs
    /// go into `wallet`. Returns true when it did; false when the message carried no payment, or
    /// one with no wallet-payment outputs (TS `no-wallet-outputs`), and nothing was asked of the
    /// wallet.
    ///
    /// Before the wallet is asked, each wallet-payment output is checked to be in the transaction
    /// and locked to the BRC-29 key this wallet derives for it, as `RemoteWallet` checks it, so a
    /// payment to someone else is told apart from a wallet that refused.
    ///
    /// It does not acknowledge the message; the caller does, last, once whatever else the message
    /// carries is in the wallet. When this throws ``MessageBoxPaymentError/recipientPaymentFailed(_:)``
    /// with `unreadable`, the payment cannot be read or pays an output this wallet cannot claim:
    /// it can never be taken, and acknowledging loses nothing. With `refused`, the wallet or its
    /// storage refused it or failed: do not acknowledge, because the message holds the only copy
    /// of that payment; run the step again later. When it rethrows `CancellationError` the task
    /// was cancelled while the wallet was working, and the wallet may or may not have taken it;
    /// treat that as `refused`. ``accept(_:wallet:beforeAcknowledge:)`` does this step itself for
    /// PeerPay payments.
    ///
    /// Unlike `accept`, this step has no in-flight guard: two calls for the same message both
    /// ask the wallet to internalize. It relies on wallet storage merging a repeat internalize of
    /// a transaction it already holds: TS storage takes the merge path, where a wallet payment to
    /// an output it already manages is idempotent, so the payment is not counted twice.
    @discardableResult
    public func internalizeEnvelopePayment(of message: MessageBoxMessage, wallet: RemoteWallet) async throws -> Bool {
        try await internalizeEnvelopePayment(of: message, receiver: wallet)
    }

    @discardableResult
    func internalizeEnvelopePayment(of message: MessageBoxMessage, receiver: some MessageBoxReceivingWallet) async throws -> Bool {
        try await Self.internalizeEnvelopePayment(message.payment, into: receiver)
    }

    /// The envelope step behind ``internalizeEnvelopePayment(of:wallet:)`` and `accept`.
    static func internalizeEnvelopePayment(
        _ payment: JSONValue?, into wallet: some MessageBoxReceivingWallet
    ) async throws -> Bool {
        guard let request = try recipientPaymentRequest(payment) else { return false }
        try await requireRecipientPaymentOwned(request, by: wallet)
        try await internalizeRecipientPayment(request, into: wallet)
        return true
    }

    /// `RemoteWallet.internalizeAction`'s ownership check, run first so that a payment this
    /// wallet can never claim is reported `unreadable`, not `refused`: every wallet-payment output
    /// must be in the subject transaction and locked to the BRC-29 key the wallet derives for its
    /// sender, prefix and suffix. A wallet that cannot derive the key (it locked, say) refused.
    static func requireRecipientPaymentOwned(
        _ request: WalletInternalizeActionRequest, by wallet: some MessageBoxReceivingWallet
    ) async throws {
        let unreadable = MessageBoxPaymentError.recipientPaymentFailed(.unreadable)
        guard let subject = try? request.transaction.beef.transaction(
            for: request.transaction.subjectTransactionID, limits: StorageLimits.transaction) else { throw unreadable }
        for output in request.outputs {
            guard case .walletPayment(let remittance) = output.remittance else { continue }
            let index = Int(output.outputIndex)
            let keyRequest: WalletGetPublicKeyRequest
            do {
                guard index < subject.outputs.count else { throw unreadable }
                // The canonical base64 the sender derived with, rebuilt from the remittance bytes.
                let prefix = Base64Encoding.encode(remittance.derivationPrefix.bytes)
                let suffix = Base64Encoding.encode(remittance.derivationSuffix.bytes)
                keyRequest = WalletGetPublicKeyRequest(selection: .derived(
                    protocolID: try WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: BRC29.protocolID),
                    keyID: try WalletKeyID(BRC29.keyID(prefix: prefix, suffix: suffix)),
                    counterparty: .publicKey(remittance.senderIdentityKey), forSelf: true))
            } catch {
                throw unreadable
            }
            let derived: PublicKey
            do {
                derived = try await wallet.getPublicKey(keyRequest).publicKey
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                throw MessageBoxPaymentError.recipientPaymentFailed(.refused)
            }
            let owned: Bool
            do {
                owned = try subject.outputs[index].lockingScript == BRC29.lockingScript(for: derived)
            } catch {
                throw unreadable
            }
            guard owned else { throw unreadable }
        }
    }

    /// TS `snapshotIncomingPayment`: the envelope payment as an internalize request for its
    /// wallet-payment outputs, or nil when there is no payment or it has no such outputs (TS
    /// `no-wallet-outputs`, which internalizes nothing). A payment that cannot be read throws
    /// ``MessageBoxPaymentError/recipientPaymentFailed(_:)`` with `unreadable`.
    static func recipientPaymentRequest(_ value: JSONValue?) throws -> WalletInternalizeActionRequest? {
        guard let value else { return nil }
        do {
            guard case .object(let payment) = value,
                  let tx = MessageBoxIncomingPayment.byteArray(payment["tx"]), !tx.isEmpty,
                  tx.count <= MessageBoxIncomingPayment.maximumRecipientPaymentBytes,
                  case .array(let items)? = payment["outputs"],
                  items.count <= MessageBoxIncomingPayment.maximumRecipientPaymentOutputs else {
                throw MessageBoxPaymentError.recipientPaymentFailed(.unreadable)
            }
            var outputs: [WalletInternalizeOutput] = []
            for item in items {
                guard case .object(let output) = item else { throw MessageBoxPaymentError.recipientPaymentFailed(.unreadable) }
                guard output["protocol"] == .string("wallet payment") else { continue }
                guard case .number(let number)? = output["outputIndex"], number.rounded() == number,
                      let index = UInt32(exactly: number),
                      case .object(let remittance)? = output["paymentRemittance"],
                      case .string(let prefix)? = remittance["derivationPrefix"],
                      case .string(let suffix)? = remittance["derivationSuffix"],
                      case .string(let sender)? = remittance["senderIdentityKey"] else {
                    throw MessageBoxPaymentError.recipientPaymentFailed(.unreadable)
                }
                outputs.append(WalletInternalizeOutput(outputIndex: index, remittance: .walletPayment(
                    try WalletPaymentRemittance(
                        derivationPrefix: WalletBase64Data(base64: prefix),
                        derivationSuffix: WalletBase64Data(base64: suffix),
                        senderIdentityKey: PublicKey(Hex.decode(sender, maximumDecodedByteCount: 33))))))
            }
            let description: String
            switch payment["description"] {
            case .none, .some(.null):
                description = "MessageBox recipient payment"
            case .string(let text)? where MessageBoxIncomingPayment.isExactDescription(text):
                description = text
            default:
                throw MessageBoxPaymentError.recipientPaymentFailed(.unreadable)
            }
            guard !outputs.isEmpty else { return nil }
            return try WalletInternalizeActionRequest(
                transaction: AtomicBEEF(bytes: tx, limits: StorageLimits.beef),
                description: description, outputs: outputs)
        } catch {
            throw MessageBoxPaymentError.recipientPaymentFailed(.unreadable)
        }
    }

    /// TS `internalizeRecipientPayment`: the wallet must report the payment accepted. Anything
    /// else from the wallet is `refused`, since asking again may succeed.
    static func internalizeRecipientPayment(
        _ request: WalletInternalizeActionRequest, into wallet: some MessageBoxReceivingWallet
    ) async throws {
        do {
            guard try await wallet.internalizeAction(request).accepted else {
                throw MessageBoxPaymentError.recipientPaymentFailed(.refused)
            }
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw MessageBoxPaymentError.recipientPaymentFailed(.refused)
        }
    }

    private func incomingPayment(_ row: ListedRow) async -> MessageBoxIncomingPayment? {
        guard let plaintext = try? await open(row.message) else { return nil }
        return MessageBoxIncomingPayment.decode(messageId: row.message.messageId, sender: row.rawSender, plaintext: plaintext)
    }

    /// TS `Brc29RemittanceModule.acceptSettlement` as PeerPay configures it. Any failure is the
    /// one settlement error, as in TS.
    static func internalize(_ payment: MessageBoxIncomingPayment, into wallet: some MessageBoxReceivingWallet) async throws {
        do {
            let token = payment.token
            let prefix = token.customInstructions.derivationPrefix
            let suffix = token.customInstructions.derivationSuffix
            guard MessageBoxIncomingPayment.isBoundedDerivation(prefix),
                  MessageBoxIncomingPayment.isBoundedDerivation(suffix),
                  !token.transaction.isEmpty,
                  token.transaction.count <= MessageBoxIncomingPayment.maximumSettlementTransactionBytes,
                  token.amount >= 1, token.amount <= MessageBoxIncomingPayment.maximumSatoshis,
                  let outputIndex = UInt32(exactly: token.outputIndex) else {
                throw MessageBoxPaymentError.settlementFailed
            }
            let sender = try PublicKey(Hex.decode(payment.sender, maximumDecodedByteCount: 33))
            // BRC-42: the recipient derives its own child key for this sender.
            let derived = try await wallet.getPublicKey(WalletGetPublicKeyRequest(selection: .derived(
                protocolID: WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: BRC29.protocolID),
                keyID: WalletKeyID(BRC29.keyID(prefix: prefix, suffix: suffix)),
                counterparty: .publicKey(sender), forSelf: true)))
            let expected = try BRC29.lockingScript(for: derived.publicKey)
            let atomic = try AtomicBEEF(bytes: token.transaction, limits: StorageLimits.beef)
            guard let subject = try atomic.beef.transaction(for: atomic.subjectTransactionID, limits: StorageLimits.transaction),
                  token.outputIndex < subject.outputs.count,
                  subject.outputs[token.outputIndex].satoshis == token.amount,
                  subject.outputs[token.outputIndex].lockingScript == expected else {
                throw MessageBoxPaymentError.settlementFailed
            }
            let remittance = try WalletPaymentRemittance(
                derivationPrefix: WalletBase64Data(base64: prefix),
                derivationSuffix: WalletBase64Data(base64: suffix),
                senderIdentityKey: sender)
            let request = try WalletInternalizeActionRequest(
                transaction: atomic, description: "BRC-29 payment received", labels: ["peerpay"],
                outputs: [WalletInternalizeOutput(outputIndex: outputIndex, remittance: .walletPayment(remittance))])
            guard try await wallet.internalizeAction(request).accepted else {
                throw MessageBoxPaymentError.settlementFailed
            }
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw MessageBoxPaymentError.settlementFailed
        }
    }
}

extension MessageBoxIncomingPayment {
    static let maximumMessageIDBytes = 1_024
    static let maximumTransactionBytes = 64 * 1024 * 1024
    static let maximumSettlementTransactionBytes = 4 * 1024 * 1024
    static let maximumSatoshis: UInt64 = 2_100_000_000_000_000
    static let maximumDerivationLength = 399
    /// TS `MAX_PAYMENT_BEEF_BYTES` and `MAX_PAYMENT_OUTPUTS` for an envelope payment.
    static let maximumRecipientPaymentBytes = 32 * 1024 * 1024
    static let maximumRecipientPaymentOutputs = 101
    /// `Number.MAX_SAFE_INTEGER`.
    static let maximumSafeInteger: Double = 9_007_199_254_740_991

    /// TS `paymentFromMessage` over an opened message: the plaintext is parsed as JSON when it
    /// is JSON (a JSON string is parsed once more), must be an object, may name only the message
    /// sender as its own, and must carry a valid token. Anything else is nil.
    public static func decode(messageId: String, sender: String, plaintext: String) -> MessageBoxIncomingPayment? {
        var body = parseJSON(plaintext) ?? .string(plaintext)
        if case .string(let text) = body {
            guard let parsed = parseJSON(text) else { return nil }
            body = parsed
        }
        guard case .object(let payment) = body else { return nil }
        if let claimed = payment["sender"], claimed != .null, claimed != .string(sender) { return nil }
        guard let boundedID = try? boundedMessageID(messageId), isCanonicalIdentityKey(sender),
              let token = paymentToken(payment) else { return nil }
        return MessageBoxIncomingPayment(messageId: boundedID, sender: sender, token: token)
    }

    /// TS `boundedMessageId`.
    static func boundedMessageID(_ value: String) throws -> String {
        guard !value.isEmpty, value.utf8.count <= maximumMessageIDBytes,
              !value.unicodeScalars.contains(where: { $0.value <= 0x1f || (0x7f...0x9f).contains($0.value) }) else {
            throw MessageBoxPaymentError.invalidMessageID
        }
        return value
    }

    /// TS `canonicalIdentityKey`: `02` or `03` and 64 lowercase hex digits, a point on the curve
    /// that encodes back to the same text.
    static func isCanonicalIdentityKey(_ value: String) -> Bool {
        let utf8 = Array(value.utf8)
        guard utf8.count == 66, utf8[0] == 0x30, utf8[1] == 0x32 || utf8[1] == 0x33,
              utf8.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }),
              let bytes = try? Hex.decode(value, maximumDecodedByteCount: 33),
              let key = try? PublicKey(bytes) else { return false }
        return Hex.encode(key.compressedBytes) == value
    }

    /// TS `normalizePaymentToken(payment, true)`.
    static func paymentToken(_ payment: [String: JSONValue]) -> MessageBoxPaymentToken? {
        guard case .object(let instructions)? = payment["customInstructions"] else { return nil }
        let transaction: [UInt8]?
        if case .string(let text)? = payment["transaction"] {
            transaction = canonicalBase64(text, maximumBytes: maximumTransactionBytes)
        } else {
            transaction = byteArray(payment["transaction"])
        }
        guard let transaction, !transaction.isEmpty, transaction.count <= maximumTransactionBytes,
              let amount = safeInteger(payment["amount"]), amount > 0 else { return nil }
        // An index the platform's Int cannot hold (arm64_32 above Int32.max) is refused, not trapped.
        var outputIndex = 0
        if let value = payment["outputIndex"], value != .null {
            guard let index = safeInteger(value), index >= 0, index <= 0xffff_ffff,
                  let exact = Int(exactly: index) else { return nil }
            outputIndex = exact
        }
        guard let prefix = derivation(instructions["derivationPrefix"]),
              let suffix = derivation(instructions["derivationSuffix"]) else { return nil }
        return MessageBoxPaymentToken(derivationPrefix: prefix, derivationSuffix: suffix,
            transaction: transaction, amount: UInt64(amount), outputIndex: outputIndex)
    }

    /// TS `boundedDerivation`, applied when a settlement is accepted.
    static func isBoundedDerivation(_ value: String) -> Bool {
        !value.isEmpty && value.utf16.count <= maximumDerivationLength
            && !value.unicodeScalars.contains(where: {
                $0.value <= 0x1f || $0.value == 0x7f || $0.properties.isWhitespace
            })
    }

    /// TS `exactBoundedText(description, 50, forbidControls)`.
    static func isExactDescription(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 50
            && value.trimmingCharacters(in: .whitespacesAndNewlines) == value
            && !value.unicodeScalars.contains(where: { $0.value <= 0x1f || (0x7f...0x9f).contains($0.value) })
    }

    private static func parseJSON(_ text: String) -> JSONValue? {
        try? JSONDecoder().decode(JSONValue.self, from: Data(text.utf8))
    }

    /// A JS safe integer, the way `Number.isSafeInteger` reads a JSON number.
    private static func safeInteger(_ value: JSONValue?) -> Double? {
        guard case .number(let number)? = value, number.isFinite, number.rounded() == number,
              abs(number) <= maximumSafeInteger else { return nil }
        return number
    }

    /// TS `normalizeBRC100ByteArray`: an array of bytes, or the historical `{"0": …, "1": …}`
    /// object with contiguous keys from zero and at least one byte.
    static func byteArray(_ value: JSONValue?) -> [UInt8]? {
        switch value {
        case .array(let items)?:
            var bytes: [UInt8] = []
            bytes.reserveCapacity(items.count)
            for item in items {
                guard let byte = byteValue(item) else { return nil }
                bytes.append(byte)
            }
            return bytes
        case .object(let object)?:
            guard !object.isEmpty else { return nil }
            var bytes: [UInt8] = []
            bytes.reserveCapacity(object.count)
            for index in 0..<object.count {
                guard let item = object[String(index)], let byte = byteValue(item) else { return nil }
                bytes.append(byte)
            }
            return bytes
        default:
            return nil
        }
    }

    private static func byteValue(_ value: JSONValue) -> UInt8? {
        guard case .number(let number) = value, number.rounded() == number, number >= 0, number <= 255 else { return nil }
        return UInt8(number)
    }

    /// TS `decodePeerPayTransaction`: padded canonical base64 of one to `maximumBytes` bytes.
    private static func canonicalBase64(_ text: String, maximumBytes: Int) -> [UInt8]? {
        guard !text.isEmpty, text.utf8.count % 4 == 0, text.utf8.count <= (maximumBytes + 2) / 3 * 4,
              let bytes = try? Base64Encoding.decode(text, maximumDecodedByteCount: maximumBytes),
              !bytes.isEmpty, Base64Encoding.encode(bytes) == text else { return nil }
        return bytes
    }

    /// TS `validateBase64String`, which trims; here the trimmed text must also be canonical
    /// base64, because the wallet stores the derivation as those bytes.
    private static func derivation(_ value: JSONValue?) -> String? {
        guard case .string(let text)? = value else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, (try? WalletBase64Data(base64: trimmed)) != nil else { return nil }
        return trimmed
    }
}
