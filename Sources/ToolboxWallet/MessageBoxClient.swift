import Foundation
import BSVCore
import BSVKeys
import BSVWallet
import ToolboxAuth

/// HTTP subset of @bsv/message-box-client. The application chooses its server;
/// payment messages are always encrypted end-to-end and mutually authenticated.
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
    public func requireFreeDelivery(to recipient: PublicKey) async throws {
        var query = URLComponents()
        query.queryItems = [
            URLQueryItem(name: "recipient", value: Hex.encode(recipient.compressedBytes)),
            URLQueryItem(name: "messageBox", value: "payment_inbox")
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
        let tokenData = try encoder.encode(token)
        let tokenString = String(decoding: tokenData, as: UTF8.self)
        let protocolID = try WalletProtocolID(securityLevel: .everyApp, name: "messagebox")
        let keyID = try WalletKeyID("1")
        // TS hashes stringifyBRC100(message.body); PeerPay supplies a JSON string,
        // so the HMAC covers the JSON-quoted string, not the unquoted token bytes.
        let hmac = try await wallet.createHMAC(WalletCreateHMACRequest(
            protocolID: protocolID, keyID: keyID, counterparty: .publicKey(recipient),
            data: Array(try encoder.encode(tokenString))))
        let encrypted = try await wallet.encrypt(WalletEncryptRequest(
            protocolID: protocolID, keyID: keyID, counterparty: .publicKey(recipient),
            plaintext: Array(tokenData)))
        let body = try encoder.encode(["encryptedMessage": Data(encrypted.ciphertext).base64EncodedString()])
        return MessageBoxEnvelope(recipient: Hex.encode(recipient.compressedBytes),
            messageId: Hex.encode(hmac.hmac.bytes), body: String(decoding: body, as: UTF8.self))
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
    public var messageBox: String { "payment_inbox" }
    private enum CodingKeys: String, CodingKey { case recipient, messageId, body, messageBox }
    public init(recipient: String, messageId: String, body: String) {
        self.recipient = recipient; self.messageId = messageId; self.body = body
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard try c.decode(String.self, forKey: .messageBox) == "payment_inbox" else {
            throw MessageBoxError.invalidResponse
        }
        self.init(recipient: try c.decode(String.self, forKey: .recipient),
            messageId: try c.decode(String.self, forKey: .messageId), body: try c.decode(String.self, forKey: .body))
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(recipient, forKey: .recipient); try c.encode(messageId, forKey: .messageId)
        try c.encode(body, forKey: .body); try c.encode(messageBox, forKey: .messageBox)
    }
}

public enum MessageBoxError: Error, LocalizedError, Sendable {
    case invalidHost, invalidResponse, blocked, deliveryFeeRequired, rejected
    case httpStatus(Int)
    public var errorDescription: String? {
        switch self {
        case .invalidHost: "The MessageBox server must have a valid HTTPS URL."
        case .invalidResponse: "The MessageBox server returned an unreadable response."
        case .blocked: "This recipient does not accept payments from this identity."
        case .deliveryFeeRequired: "This MessageBox requires a delivery fee. No payment was created."
        case .rejected: "The MessageBox server did not accept the delivery."
        case .httpStatus(let status): "The MessageBox server returned HTTP \(status)."
        }
    }
}
