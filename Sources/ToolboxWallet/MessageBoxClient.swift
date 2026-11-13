import Foundation
import BSVCore
import BSVKeys
import BSVWallet
import ToolboxAuth
import ToolboxCore

/// HTTP subset of @bsv/message-box-client for any box. The application chooses its server;
/// messages are encrypted end-to-end and every request is mutually authenticated (BRC-103/104).
public struct MessageBoxClient: Sendable {
    private let wallet: ProtoWallet
    private let transport: any AuthenticatedTransport
    private let basePath: String
    /// Payment messages this client is accepting now. Copies of a client share it, as one TS
    /// `PeerPayClient` instance does.
    let activePayments = MessageBoxActivePayments()

    public init(host: URL, wallet: ProtoWallet, transport: (any AuthenticatedTransport)? = nil) throws {
        let host = try MessageBoxHost.configured(host.absoluteString)
        self.wallet = wallet
        self.transport = transport ?? AuthenticatedSession(baseURL: host, wallet: wallet)
        self.basePath = host.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    /// Check permission before creating a transaction. Paid message delivery needs a
    /// separately approved fee; it must never silently increase the payment amount.
    public func requireFreeDelivery(
        to recipient: PublicKey, messageBox: String = MessageBoxClient.paymentInbox
    ) async throws {
        try Self.requireBoxName(messageBox)
        var query = URLComponents()
        query.queryItems = [
            URLQueryItem(name: "recipient", value: Hex.encode(recipient.compressedBytes)),
            URLQueryItem(name: "messageBox", value: messageBox)
        ]
        let response = try await transport.send(method: "GET", path: path("permissions/quote"),
            query: query.percentEncodedQuery.map { "?" + $0 }, headers: [:], body: nil)
        let object = try parse(response)
        struct QuoteResponse: Decodable {
            struct Quote: Decodable { let recipientFee: Int; let deliveryFee: Int }
            let quote: Quote
        }
        guard let quote = try? JSONDecoder().decode(QuoteResponse.self, from: Data(response.body)).quote,
              quote.recipientFee >= -1, quote.deliveryFee >= 0,
              object["status"] as? String != "error" else { throw MessageBoxError.invalidResponse }
        let recipientFee = quote.recipientFee, deliveryFee = quote.deliveryFee
        guard recipientFee != -1 else { throw MessageBoxError.blocked }
        guard recipientFee == 0, deliveryFee == 0 else { throw MessageBoxError.deliveryFeeRequired }
    }

    /// Prepare once and persist before broadcasting. Reusing this envelope keeps the
    /// HMAC message ID stable across delivery retries, as in the TypeScript client.
    public func preparePayment(to recipient: PublicKey, token: MessageBoxPaymentToken) async throws -> MessageBoxEnvelope {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let tokenString = String(decoding: try encoder.encode(token), as: UTF8.self)
        return try await prepareMessage(to: recipient, messageBox: Self.paymentInbox, body: tokenString)
    }

    /// Encrypts a text body for any box, as `@bsv/message-box-client` `sendMessage` does by
    /// default: BRC-2 under `[1, "messagebox"]`, key ID `1`, the recipient as counterparty; the
    /// wire body is `{"encryptedMessage": <base64>}`. The message ID is the HMAC of the body as
    /// TS `stringifyBRC100` sees it, a JSON string, so it is stable across retries.
    public func prepareMessage(to recipient: PublicKey, messageBox: String, body: String) async throws -> MessageBoxEnvelope {
        try Self.requireBoxName(messageBox)
        guard !body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw MessageBoxError.invalidMessage
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let protocolID = try Self.messageBoxProtocol()
        let keyID = try WalletKeyID("1")
        let hmac = try await wallet.createHMAC(WalletCreateHMACRequest(
            protocolID: protocolID, keyID: keyID, counterparty: .publicKey(recipient),
            data: Array(try encoder.encode(body))))
        let encrypted = try await wallet.encrypt(WalletEncryptRequest(
            protocolID: protocolID, keyID: keyID, counterparty: .publicKey(recipient),
            plaintext: Array(body.utf8)))
        let wire = try encoder.encode(["encryptedMessage": Data(encrypted.ciphertext).base64EncodedString()])
        return MessageBoxEnvelope(recipient: Hex.encode(recipient.compressedBytes),
            messageId: Hex.encode(hmac.hmac.bytes), body: String(decoding: wire, as: UTF8.self),
            messageBox: messageBox)
    }

    public func deliver(_ envelope: MessageBoxEnvelope) async throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let request = try encoder.encode(["message": envelope])
        let response = try await transport.send(method: "POST", path: path("sendMessage"),
            query: nil, headers: ["Content-Type": "application/json"], body: Array(request))
        let object = try parse(response)
        guard object["status"] as? String == "success" else { throw MessageBoxError.rejected }
    }

    /// Lists one box on this server, following `hasMore` pages as the TS client does. A stored
    /// `{"message": …, "payment": …}` envelope is unwrapped, as TS `listMessages` does: `body` is
    /// the wrapped message and `payment` the payment record. ``open(_:)`` decrypts an
    /// `encryptedMessage` body.
    ///
    /// The listing starts at `offset` (TS `offset`/`skip`; the server lists oldest first) and
    /// stops after `maxPages` pages. When the server still reports more, the messages read so far
    /// are returned with `truncated` set. Acknowledging them lets the next listing reach the rest;
    /// messages left on the server are passed over by listing again from the listing's
    /// `nextOffset`.
    ///
    /// A row that cannot be read as a message (no message ID, a sender that is not a key, a body
    /// that is neither text nor JSON) fails the listing with ``MessageBoxError/invalidResponse``.
    /// With `skipMalformed`, it is left out and counted in the listing's `skipped` instead, so one
    /// such row does not hide every message on the server; the listing is then not
    /// ``MessageBoxListing/isComplete``. A skipped row stays on the server and counts in
    /// `nextOffset`. TS `listMessagesLite` has no such rows: it keeps whatever the server sent.
    public func listMessages(
        messageBox: String, pageSize: Int = 100, maxPages: Int = 100, offset: Int = 0, skipMalformed: Bool = false
    ) async throws -> MessageBoxListing {
        let listed = try await listRows(messageBox: messageBox, pageSize: pageSize, maxPages: maxPages, offset: offset,
            skipMalformed: skipMalformed)
        return MessageBoxListing(messages: listed.rows.map(\.message), truncated: listed.truncated,
            nextOffset: listed.nextOffset, skipped: listed.skipped)
    }

    /// One listed row: the message, and its sender exactly as the server sent it.
    struct ListedRow: Sendable {
        let message: MessageBoxMessage
        let rawSender: String
    }

    /// The paging loop behind every listing. `limit` caps the rows taken in total, as TS
    /// `fetchMessagePages` does, and `messageId` asks the server for that one message. A row that
    /// cannot be read fails the listing, or is left out and counted in `skipped` with
    /// `skipMalformed`.
    ///
    /// It stops at the first of: a page without `hasMore`, `limit` rows taken, or `maxPages`
    /// pages read. TS throws when the last allowed page still has more; here the rows read so far
    /// are returned with `truncated` set, because rows that cannot be read are never acknowledged
    /// and would otherwise block the listing for good. `truncated` is also set when `limit` cut
    /// rows out of a page or the server has more after the limit.
    ///
    /// The first page is asked for at `offset`, as TS `fetchMessagePages` starts at its
    /// `offset`/`skip`. `nextOffset` is the server offset just past the last row taken (a row that
    /// could not be read counts, since it is still on the server), so a caller that leaves the
    /// rows on the server can list on from there.
    func listRows(
        messageBox: String, pageSize: Int, maxPages: Int, limit: Int? = nil, offset start: Int = 0,
        messageId: String? = nil, skipMalformed: Bool = false
    ) async throws -> (rows: [ListedRow], truncated: Bool, nextOffset: Int, skipped: Int) {
        try Self.requireBoxName(messageBox)
        guard pageSize > 0, maxPages > 0, limit.map({ $0 > 0 }) ?? true,
              start >= 0, Int64(start) <= Self.maximumListOffset else { throw MessageBoxError.invalidMessage }
        var rows: [ListedRow] = []
        var skipped = 0
        var received = 0
        var offset = start
        for _ in 0..<maxPages {
            let remaining = limit.map { $0 - received }
            var fields: [String: Any] = [
                "messageBox": messageBox, "offset": offset, "limit": min(pageSize, remaining ?? pageSize),
            ]
            if let messageId { fields["messageId"] = messageId }
            let request = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
            let response = try await transport.send(method: "POST", path: path("listMessages"),
                query: nil, headers: ["Content-Type": "application/json"], body: Array(request))
            let object = try parse(response)
            guard let page = object["messages"] as? [Any] else { throw MessageBoxError.invalidResponse }
            let taken = remaining.map { Array(page.prefix($0)) } ?? page
            received += taken.count
            for item in taken {
                if let row = item as? [String: Any], let sender = row["sender"] as? String,
                   let message = try? MessageBoxMessage(row: row) {
                    rows.append(ListedRow(message: message, rawSender: sender))
                } else if skipMalformed {
                    skipped += 1
                } else {
                    throw MessageBoxError.invalidResponse
                }
            }
            let hasMore = object["hasMore"] as? Bool == true
            let cut = taken.count < page.count
            let full = limit.map { received >= $0 } ?? false
            if !hasMore || cut || full { return (rows, hasMore || cut, offset + taken.count, skipped) }
            // Prefer the server's cursor when it moves forward; otherwise step by what we saw,
            // or by a full page when the page came back empty, so an empty page never stalls.
            if let next = Self.integer(object["nextOffset"]), next > offset {
                offset = next
            } else {
                offset += page.isEmpty ? pageSize : page.count
            }
        }
        return (rows, true, offset, skipped)
    }

    /// `Number.MAX_SAFE_INTEGER`, the largest offset TS sends.
    static let maximumListOffset: Int64 = 9_007_199_254_740_991

    /// This client's identity key, the one messages to it are encrypted for.
    func identityKey() async throws -> PublicKey {
        try await wallet.getPublicKey(WalletGetPublicKeyRequest(selection: .identity)).publicKey
    }

    /// Removes delivered messages from this server. Only acknowledge a message once whatever it
    /// carried has been made durable: the server deletes it.
    public func acknowledge(messageIds: [String]) async throws {
        var seen = Set<String>()
        let unique = messageIds.filter { seen.insert($0).inserted }
        guard !unique.isEmpty, unique.allSatisfy({ !$0.isEmpty }) else { throw MessageBoxError.invalidMessage }
        let request = try JSONSerialization.data(withJSONObject: ["messageIds": unique], options: [.sortedKeys])
        let response = try await transport.send(method: "POST", path: path("acknowledgeMessage"),
            query: nil, headers: ["Content-Type": "application/json"], body: Array(request))
        _ = try parse(response)
    }

    /// The plaintext of a listed message: decrypted when the body is `{"encryptedMessage": …}`,
    /// otherwise the stored body unchanged.
    public func open(_ message: MessageBoxMessage) async throws -> String {
        guard let object = try? JSONSerialization.jsonObject(with: Data(message.body.utf8)) as? [String: Any],
              let encoded = object["encryptedMessage"] else { return message.body }
        guard let text = encoded as? String, let ciphertext = Data(base64Encoded: text) else {
            throw MessageBoxError.invalidMessage
        }
        let sender = try PublicKey(Hex.decode(message.sender, maximumDecodedByteCount: 33))
        let plaintext = try await wallet.decrypt(WalletDecryptRequest(
            protocolID: try Self.messageBoxProtocol(), keyID: try WalletKeyID("1"),
            counterparty: .publicKey(sender), ciphertext: Array(ciphertext)))
        guard let string = String(bytes: plaintext.plaintext, encoding: .utf8) else { throw MessageBoxError.invalidMessage }
        return string
    }

    /// One authenticated binary request to this server, for protocols that frame their own bodies
    /// (BRC-231 posts DAG-CBOR to the same `sendMessage`/`listMessages`/`acknowledgeMessage`
    /// paths). A non-2xx status throws; the response body is returned undecoded.
    public func post(_ endpoint: String, contentType: String, body: [UInt8]) async throws -> [UInt8] {
        let trimmed = endpoint.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard !trimmed.isEmpty, !trimmed.contains("?"), !trimmed.contains("#"), !trimmed.contains("..") else {
            throw MessageBoxError.invalidMessage
        }
        let response = try await transport.send(method: "POST", path: path(trimmed),
            query: nil, headers: ["Content-Type": contentType], body: body)
        guard (200..<300).contains(response.statusCode) else {
            throw MessageBoxError.httpStatus(response.statusCode)
        }
        return response.body
    }

    public static let paymentInbox = "payment_inbox"
    /// The TS client caps box names at 64 UTF-8 bytes and forbids control characters.
    static let maxBoxNameBytes = 64

    static func requireBoxName(_ name: String) throws {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              name.utf8.count <= maxBoxNameBytes,
              !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else {
            throw MessageBoxError.invalidMessage
        }
    }

    private static func messageBoxProtocol() throws -> WalletProtocolID {
        try WalletProtocolID(securityLevel: .everyApp, name: "messagebox")
    }

    private func path(_ suffix: String) -> String {
        basePath.isEmpty ? "/\(suffix)" : "/\(basePath)/\(suffix)"
    }

    /// A non-negative whole number from a JSON value, refusing booleans and fractions.
    static func integer(_ value: Any?) -> Int? {
        // JSON booleans arrive as NSNumber with the char type; `is Bool` also matches 0 and 1 on Darwin.
        guard let number = value as? NSNumber, String(cString: number.objCType) != "c" else { return nil }
        let double = number.doubleValue
        guard double >= 0, double.rounded() == double, double <= Double(Int.max / 2) else { return nil }
        return Int(double)
    }

    private func parse(_ response: AuthenticatedResponse) throws -> [String: Any] {
        guard (200..<300).contains(response.statusCode) else {
            throw MessageBoxError.httpStatus(response.statusCode)
        }
        guard let object = try JSONSerialization.jsonObject(with: Data(response.body)) as? [String: Any] else {
            throw MessageBoxError.invalidResponse
        }
        guard object["status"] as? String != "error" else { throw MessageBoxError.rejected }
        return object
    }
}

public struct MessageBoxPaymentToken: Codable, Sendable, Equatable {
    public struct Instructions: Codable, Sendable, Equatable {
        public let derivationPrefix: String
        public let derivationSuffix: String
    }
    public let customInstructions: Instructions
    public let transaction: [UInt8]
    public let amount: UInt64
    public let outputIndex: Int

    public init(derivationPrefix: String, derivationSuffix: String, transaction: [UInt8], amount: UInt64, outputIndex: Int) {
        self.customInstructions = Instructions(derivationPrefix: derivationPrefix, derivationSuffix: derivationSuffix)
        self.transaction = transaction
        self.amount = amount
        self.outputIndex = outputIndex
    }
}

public struct MessageBoxEnvelope: Codable, Sendable, Equatable {
    public let recipient: String
    public let messageId: String
    public let body: String
    public let messageBox: String
    private enum CodingKeys: String, CodingKey { case recipient, messageId, body, messageBox }
    public init(recipient: String, messageId: String, body: String, messageBox: String = MessageBoxClient.paymentInbox) {
        self.recipient = recipient; self.messageId = messageId; self.body = body; self.messageBox = messageBox
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let box = try c.decode(String.self, forKey: .messageBox)
        do { try MessageBoxClient.requireBoxName(box) } catch { throw MessageBoxError.invalidResponse }
        self.init(recipient: try c.decode(String.self, forKey: .recipient),
            messageId: try c.decode(String.self, forKey: .messageId), body: try c.decode(String.self, forKey: .body),
            messageBox: box)
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(recipient, forKey: .recipient); try c.encode(messageId, forKey: .messageId)
        try c.encode(body, forKey: .body); try c.encode(messageBox, forKey: .messageBox)
    }
}

/// A message as `/listMessages` returns it. `sender` is the compressed identity key, hex.
///
/// When the server stored the message in a `{"message": …, "payment": …}` envelope, `body` is
/// the wrapped message and `payment` the envelope's payment record, as TS `listMessages` returns
/// them. Listing does not internalize that payment; ``MessageBoxClient/accept(_:wallet:beforeAcknowledge:)``
/// does, before it acknowledges the message, and ``MessageBoxClient/internalizeEnvelopePayment(of:wallet:)``
/// does it for any other message. An envelope payment that is not an object is kept as it was
/// stored; it can never be internalized, and the envelope step reports it unreadable.
public struct MessageBoxMessage: Sendable, Equatable {
    public let messageId: String
    public let body: String
    public let sender: String
    public let createdAt: String?
    public let payment: JSONValue?

    public init(messageId: String, body: String, sender: String, createdAt: String? = nil, payment: JSONValue? = nil) {
        self.messageId = messageId; self.body = body; self.sender = sender; self.createdAt = createdAt
        self.payment = payment
    }

    init(row: [String: Any]) throws {
        guard let id = row["messageId"] as? String, !id.isEmpty,
              let sender = row["sender"] as? String,
              let key = try? Hex.decode(sender, maximumDecodedByteCount: 33), key.count == 33 else { throw MessageBoxError.invalidResponse }
        let stored: String
        if let text = row["body"] as? String {
            stored = text
        } else if let object = row["body"], JSONSerialization.isValidJSONObject(object),
                  let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) {
            // Some servers return the stored JSON body parsed; keep it as text.
            stored = String(decoding: data, as: UTF8.self)
        } else {
            throw MessageBoxError.invalidResponse
        }
        let (body, payment) = try Self.unwrap(stored)
        self.init(messageId: id, body: body, sender: sender.lowercased(),
            createdAt: row["created_at"] as? String ?? row["createdAt"] as? String, payment: payment)
    }

    /// TS `listMessages`: a body that parses to an object with its own `message` key is an
    /// envelope. A string message is the body as it stands; a null message leaves the envelope as
    /// the body; any other message is kept as JSON text. A payment that is present and not null
    /// is kept even when it is not an object. TS `listMessagesLite` drops such a payment and keeps
    /// the message; here it stays, so the envelope step reports it unreadable instead of the
    /// message being acknowledged as if it carried nothing. Only a payment that cannot be
    /// represented as JSON makes the row unreadable.
    static func unwrap(_ stored: String) throws -> (body: String, payment: JSONValue?) {
        guard let parsed = try? JSONSerialization.jsonObject(with: Data(stored.utf8), options: [.fragmentsAllowed]),
              let envelope = parsed as? [String: Any], let wrapped = envelope["message"] else {
            return (stored, nil)
        }
        var body = stored
        if let text = wrapped as? String {
            body = text
        } else if !(wrapped is NSNull), let data = try? JSONSerialization.data(
            withJSONObject: wrapped, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]) {
            body = String(decoding: data, as: UTF8.self)
        }
        guard let value = envelope["payment"], !(value is NSNull) else { return (body, nil) }
        // Wrapped in an array so a payment that is a bare string or number decodes too.
        guard let data = try? JSONSerialization.data(withJSONObject: [value], options: [.sortedKeys]),
              let decoded = try? JSONDecoder().decode([JSONValue].self, from: data),
              decoded.count == 1 else {
            throw MessageBoxError.invalidResponse
        }
        return (body, decoded[0])
    }
}

/// One listing of a box. `truncated` is true when the server has more than was read: the page
/// cap or the row limit was reached while it still reported more. Acknowledge what was handled
/// and list again to read the rest, or list from `nextOffset` to read past messages left there.
/// `skipped` counts rows a `skipMalformed` listing left out; check ``isComplete`` before treating
/// the listing as the whole box. Skipped rows stay in the box, so a caller paging through it
/// lists on until `truncated` is false, not until `isComplete` is true.
public struct MessageBoxListing: Sendable, Equatable {
    public let messages: [MessageBoxMessage]
    public let truncated: Bool
    /// The server offset just past the last message this listing read. Listing again from it
    /// reads on from there while the messages before it stay on the server; each message
    /// acknowledged since moves the rest one place earlier, so subtract those, or list from 0.
    public let nextOffset: Int
    /// Rows the server returned that could not be read as messages and were left out, with
    /// `skipMalformed`. They stay on the server and are counted in `nextOffset`. Always 0 without
    /// `skipMalformed`, which throws on such a row instead.
    public let skipped: Int

    /// True when this listing holds every message the server listed: it was not truncated and no
    /// row was skipped.
    public var isComplete: Bool { !truncated && skipped == 0 }

    public init(messages: [MessageBoxMessage], truncated: Bool, nextOffset: Int, skipped: Int = 0) {
        self.messages = messages; self.truncated = truncated; self.nextOffset = nextOffset; self.skipped = skipped
    }
}

public enum MessageBoxError: Error, LocalizedError, Sendable {
    case invalidHost, invalidResponse, blocked, deliveryFeeRequired, rejected, invalidMessage
    case httpStatus(Int)
    public var errorDescription: String? {
        switch self {
        case .invalidHost: "The MessageBox server must have a valid HTTPS URL."
        case .invalidResponse: "The MessageBox server returned an unreadable response."
        case .blocked: "This recipient does not accept payments from this identity."
        case .deliveryFeeRequired: "This MessageBox requires a delivery fee. No payment was created."
        case .rejected: "The MessageBox server did not accept the delivery."
        case .invalidMessage: "The message, box name or message ID is not valid for MessageBox."
        case .httpStatus(let status): "The MessageBox server returned HTTP \(status)."
        }
    }
}
