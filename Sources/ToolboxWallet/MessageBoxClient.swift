import Foundation
import BSVCore
import BSVKeys
import BSVWallet
import ToolboxAuth

/// HTTP subset of @bsv/message-box-client for any box. The application chooses its server;
/// messages are encrypted end-to-end and every request is mutually authenticated (BRC-103/104).
public struct MessageBoxClient: Sendable {
    private let wallet: ProtoWallet
    private let transport: any AuthenticatedTransport
    private let basePath: String

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

    /// Lists one box on this server, following `hasMore` pages as the TS client does. Bodies are
    /// returned as stored; ``open(_:)`` decrypts an `encryptedMessage` body.
    public func listMessages(messageBox: String, pageSize: Int = 100, maxPages: Int = 100) async throws -> [MessageBoxMessage] {
        try Self.requireBoxName(messageBox)
        guard pageSize > 0, maxPages > 0 else { throw MessageBoxError.invalidMessage }
        var messages: [MessageBoxMessage] = []
        var offset = 0
        for _ in 0..<maxPages {
            let request = try JSONSerialization.data(withJSONObject: [
                "messageBox": messageBox, "offset": offset, "limit": pageSize,
            ] as [String: Any], options: [.sortedKeys])
            let response = try await transport.send(method: "POST", path: path("listMessages"),
                query: nil, headers: ["Content-Type": "application/json"], body: Array(request))
            let object = try parse(response)
            guard let rows = object["messages"] as? [[String: Any]] else { throw MessageBoxError.invalidResponse }
            let page = try rows.map(MessageBoxMessage.init(row:))
            messages.append(contentsOf: page)
            guard object["hasMore"] as? Bool == true, !page.isEmpty else { return messages }
            offset += page.count
        }
        throw MessageBoxError.tooManyPages
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

public struct MessageBoxPaymentToken: Codable, Sendable {
    public struct Instructions: Codable, Sendable {
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
public struct MessageBoxMessage: Sendable, Equatable {
    public let messageId: String
    public let body: String
    public let sender: String
    public let createdAt: String?

    public init(messageId: String, body: String, sender: String, createdAt: String? = nil) {
        self.messageId = messageId; self.body = body; self.sender = sender; self.createdAt = createdAt
    }

    init(row: [String: Any]) throws {
        guard let id = row["messageId"] as? String, !id.isEmpty,
              let sender = row["sender"] as? String,
              let key = try? Hex.decode(sender, maximumDecodedByteCount: 33), key.count == 33 else { throw MessageBoxError.invalidResponse }
        let body: String
        if let text = row["body"] as? String {
            body = text
        } else if let object = row["body"], JSONSerialization.isValidJSONObject(object),
                  let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) {
            // Some servers return the stored JSON body parsed; keep it as text.
            body = String(decoding: data, as: UTF8.self)
        } else {
            throw MessageBoxError.invalidResponse
        }
        self.init(messageId: id, body: body, sender: sender.lowercased(),
            createdAt: row["created_at"] as? String ?? row["createdAt"] as? String)
    }
}

public enum MessageBoxError: Error, LocalizedError, Sendable {
    case invalidHost, invalidResponse, blocked, deliveryFeeRequired, rejected, invalidMessage, tooManyPages
    case httpStatus(Int)
    public var errorDescription: String? {
        switch self {
        case .invalidHost: "The MessageBox server must have a valid HTTPS URL."
        case .invalidResponse: "The MessageBox server returned an unreadable response."
        case .blocked: "This recipient does not accept payments from this identity."
        case .deliveryFeeRequired: "This MessageBox requires a delivery fee. No payment was created."
        case .rejected: "The MessageBox server did not accept the delivery."
        case .invalidMessage: "The message, box name or message ID is not valid for MessageBox."
        case .tooManyPages: "The MessageBox listing has more pages than allowed; acknowledge messages first."
        case .httpStatus(let status): "The MessageBox server returned HTTP \(status)."
        }
    }
}
