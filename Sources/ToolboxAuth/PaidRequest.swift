import Foundation
import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxCore
import ToolboxStorage

/// What a wallet must do to pay for a request: derive the payee's BRC-29 key, make the
/// derivation suffix nonce, and fund and sign the payment.
public typealias PayingWallet = WalletPublicKeyProviding & WalletHMACOperations & WalletActionOperations

/// A BRC-105 payment for one request: the transaction and the derivation the server needs to
/// receive it, as `AuthFetch.createPaymentContext` builds it.
///
/// The transaction is funded, signed and sent to the network when it is built, before the server
/// sees it, so a reply lost after the paid request leaves the coins with a server that can only
/// claim them from this value. Keep it until the request has an answer, and resend the same
/// payment with ``AuthenticatedSession/sendPaid(method:path:query:headers:body:payer:payment:paymentRetryAttempts:onPayment:)``
/// rather than paying again.
public struct BRC105Payment: Equatable, Sendable {
    /// The `x-bsv-payment-version` this client speaks (`AuthFetch.ts` `PAYMENT_VERSION`).
    public static let version = "1.0"
    /// The paid sends `sendPaid` makes when the caller names no positive number
    /// (`getMaxPaymentAttempts`).
    public static let defaultAttempts = 3

    /// The server's nonce from `x-bsv-payment-derivation-prefix`.
    public let derivationPrefix: String
    /// This wallet's nonce (``AuthNonce``).
    public let derivationSuffix: String
    /// The payee, as the reply that asked for the payment named it.
    public let serverIdentityKey: String
    public let satoshisRequired: UInt64
    /// The payment as Atomic BEEF (BRC-95).
    public let transaction: [UInt8]

    /// Refuses bytes that are not an Atomic BEEF envelope, since the transaction ID is read from it.
    public init(
        derivationPrefix: String, derivationSuffix: String, serverIdentityKey: String,
        satoshisRequired: UInt64, transaction: [UInt8]
    ) throws {
        guard transaction.count >= 36, transaction.prefix(4).elementsEqual([1, 1, 1, 1]) else {
            throw BRC105Error.invalidTransaction
        }
        self.derivationPrefix = derivationPrefix
        self.derivationSuffix = derivationSuffix
        self.serverIdentityKey = serverIdentityKey
        self.satoshisRequired = satoshisRequired
        self.transaction = transaction
    }

    /// The payment's transaction ID in display (reversed) hex: the Atomic BEEF's subject.
    public var transactionID: String {
        Hex.encode(transaction[4..<36].reversed())
    }

    /// The `x-bsv-payment` request header: `JSON.stringify({derivationPrefix, derivationSuffix,
    /// transaction})` with the transaction in base64, byte for byte as AuthFetch writes it.
    public var headerValue: String {
        OrderedJSON.record([
            "derivationPrefix": .string(derivationPrefix),
            "derivationSuffix": .string(derivationSuffix),
            "transaction": .string(Data(transaction).base64EncodedString()),
        ]).serialized()
    }

    /// True when a 402 asks for exactly this payment (`isPaymentContextCompatible`).
    func satisfies(_ requirement: BRC105Requirement) -> Bool {
        satoshisRequired == requirement.satoshis
            && serverIdentityKey == requirement.serverIdentityKey
            && derivationPrefix == requirement.derivationPrefix
    }
}

extension BRC105Payment: Codable {
    private enum CodingKeys: String, CodingKey {
        case derivationPrefix, derivationSuffix, serverIdentityKey, satoshisRequired, transaction
    }

    /// The transaction is kept as base64, as the header carries it.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let text = try container.decode(String.self, forKey: .transaction)
        guard let bytes = Data(base64Encoded: text) else {
            throw DecodingError.dataCorruptedError(
                forKey: .transaction, in: container, debugDescription: "transaction is not base64"
            )
        }
        try self.init(
            derivationPrefix: try container.decode(String.self, forKey: .derivationPrefix),
            derivationSuffix: try container.decode(String.self, forKey: .derivationSuffix),
            serverIdentityKey: try container.decode(String.self, forKey: .serverIdentityKey),
            satoshisRequired: try container.decode(UInt64.self, forKey: .satoshisRequired),
            transaction: Array(bytes)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(derivationPrefix, forKey: .derivationPrefix)
        try container.encode(derivationSuffix, forKey: .derivationSuffix)
        try container.encode(serverIdentityKey, forKey: .serverIdentityKey)
        try container.encode(satoshisRequired, forKey: .satoshisRequired)
        try container.encode(Data(transaction).base64EncodedString(), forKey: .transaction)
    }
}

/// Why a paid request failed. ``message`` is AuthFetch's own text for the same failure.
public enum BRC105Error: Error, Equatable, Sendable {
    /// The 402 named a payment version other than ``BRC105Payment/version``, or none (nil).
    case unsupportedVersion(server: String?)
    case missingSatoshisRequired
    /// The amount the 402 asked for is not a positive whole number of satoshis.
    case invalidSatoshisRequired(String)
    case missingServerIdentityKey
    case missingDerivationPrefix
    /// The wallet's payment was not an Atomic BEEF, or it returned none.
    case invalidTransaction
    /// Every paid send failed. The payment was sent to the network when it was built, so the
    /// coins are with the server's key: keep the payment and resend it.
    case paymentFailed(
        url: String, attempts: Int, maxAttempts: Int, satoshis: UInt64,
        serverIdentityKey: String, transactionID: String, lastError: String
    )

    /// The message `AuthFetch.handlePaymentAndRetry` throws for the same case.
    public var message: String {
        switch self {
        case .unsupportedVersion(let server):
            "Unsupported x-bsv-payment-version response header. Client version: "
                + "\(BRC105Payment.version), Server version: \(server ?? "null")"
        case .missingSatoshisRequired:
            "Missing x-bsv-payment-satoshis-required response header."
        case .invalidSatoshisRequired:
            "Invalid x-bsv-payment-satoshis-required response header value."
        case .missingServerIdentityKey:
            "Missing x-bsv-auth-identity-key response header."
        case .missingDerivationPrefix:
            "Missing x-bsv-payment-derivation-prefix response header."
        case .invalidTransaction:
            "The wallet did not return the payment transaction as Atomic BEEF."
        case .paymentFailed(let url, let attempts, let maxAttempts, let satoshis, let payee, _, _):
            "Paid request to \(url) failed after \(attempts)/\(maxAttempts) attempts. "
                + "Sent \(satoshis) satoshis to \(payee)."
        }
    }
}

extension BRC105Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unsupportedVersion, .missingSatoshisRequired, .invalidSatoshisRequired,
             .missingServerIdentityKey, .missingDerivationPrefix:
            "The server asked for a payment this wallet can't make."
        case .invalidTransaction:
            "The wallet couldn't build the payment."
        case .paymentFailed(_, _, _, let satoshis, _, _, _):
            "The payment of \(satoshis) satoshis was sent, but the server didn't accept the "
                + "request. Try again to resend the same payment."
        }
    }
}

extension BRC105Error: CustomDebugStringConvertible {
    public var debugDescription: String {
        switch self {
        case .invalidSatoshisRequired(let value):
            "BRC105Error.invalidSatoshisRequired: \(message) (\(value.debugDescription))"
        case .paymentFailed(_, _, _, _, _, let txid, let lastError):
            "BRC105Error.paymentFailed: \(ErrorDetail.withoutQueries(message)) payment \(txid); "
                + "last error: \(lastError)"
        default:
            "BRC105Error: \(message)"
        }
    }
}

/// What a 402 asks for, read in `handlePaymentAndRetry`'s order so the first fault found is the
/// one TypeScript reports.
struct BRC105Requirement: Equatable, Sendable {
    let satoshis: UInt64
    let serverIdentityKey: String
    let derivationPrefix: String

    init(_ response: AuthenticatedResponse) throws {
        let version = response.header("x-bsv-payment-version")
        guard let version, version == BRC105Payment.version else {
            throw BRC105Error.unsupportedVersion(server: version)
        }
        guard let satoshisText = response.header("x-bsv-payment-satoshis-required"),
              !satoshisText.isEmpty else {
            throw BRC105Error.missingSatoshisRequired
        }
        guard let satoshis = Self.javaScriptParseInt(satoshisText), satoshis > 0 else {
            throw BRC105Error.invalidSatoshisRequired(satoshisText)
        }
        guard let serverIdentityKey = response.header("x-bsv-auth-identity-key") else {
            throw BRC105Error.missingServerIdentityKey
        }
        guard let prefix = response.header("x-bsv-payment-derivation-prefix"), !prefix.isEmpty else {
            throw BRC105Error.missingDerivationPrefix
        }
        self.satoshis = satoshis
        self.serverIdentityKey = serverIdentityKey
        self.derivationPrefix = prefix
    }

    /// `parseInt(text)` with no radix: leading ECMAScript white space, an optional sign, `0x` for
    /// hexadecimal, then as many digits as there are; anything after them is ignored (`"12abc"`
    /// is 12, `"1e3"` is 1). Nil where JavaScript gives `NaN`, and for a negative value or one
    /// past `UInt64`, which TypeScript would refuse as not positive or fail later in
    /// `createAction` as no valid amount.
    static func javaScriptParseInt(_ text: String) -> UInt64? {
        var scalars = Substring(text).unicodeScalars.drop(while: isECMAScriptWhiteSpace)
        var negative = false
        if let sign = scalars.first, sign == "+" || sign == "-" {
            negative = sign == "-"
            scalars = scalars.dropFirst()
        }
        var radix: UInt64 = 10
        if scalars.count >= 2, scalars.first == "0",
           let x = scalars.dropFirst().first, x == "x" || x == "X" {
            radix = 16
            scalars = scalars.dropFirst(2)
        }
        var value: UInt64 = 0
        var digits = 0
        for scalar in scalars {
            guard let digit = UInt64(String(scalar), radix: Int(radix)), scalar.isASCII else { break }
            let (shifted, overflow) = value.multipliedReportingOverflow(by: radix)
            let (sum, carry) = shifted.addingReportingOverflow(digit)
            guard !overflow, !carry else { return nil }
            value = sum
            digits += 1
        }
        guard digits > 0 else { return nil }
        return negative && value != 0 ? nil : value
    }

    /// `StrWhiteSpaceChar`: the white space and line terminators `parseInt` skips.
    private static func isECMAScriptWhiteSpace(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0xFEFF, 0x2028, 0x2029: true
        default: scalar.properties.generalCategory == .spaceSeparator
        }
    }
}

extension AuthenticatedSession {
    /// Sends a request that may cost money: AuthFetch's 402 handling (`handlePaymentAndRetry`).
    ///
    /// A reply other than 402 is returned as it is. A signed 402 is read as BRC-105: `payer` pays
    /// the satoshis it asks for to the peer that signed it, under the server's derivation prefix
    /// and a fresh suffix, in one P2PKH output; `onPayment` gets the payment; then the request is
    /// sent again with an `x-bsv-payment` header. An unsigned 402 is refused like any unsigned
    /// error status and is never paid.
    ///
    /// A paid send that throws is retried with the same payment after 250 ms, 500 ms and so on.
    /// A paid send answered with another 402 is sent again at once: with the same payment while
    /// the 402 asks for the same amount, payee and prefix, and with a new payment (passed to
    /// `onPayment`) when it changes any of them. At most `paymentRetryAttempts` paid sends are
    /// made in all (3 when it is not positive); after that ``BRC105Error/paymentFailed`` is thrown.
    ///
    /// `onPayment` runs after the payment is built and before it is first sent. The payment is
    /// already on the network then, so persist it there: if the reply is lost, pass it back as
    /// `payment` and the request is sent with it straight away, with no unpaid request first and
    /// no second payment. An error from `onPayment` stops the call before the paid send.
    public func sendPaid(
        method: String, path: String, query: String? = nil,
        headers: [String: String] = [:], body: [UInt8]? = nil,
        payer: any PayingWallet,
        payment: BRC105Payment? = nil,
        paymentRetryAttempts: Int = BRC105Payment.defaultAttempts,
        onPayment: (@Sendable (BRC105Payment) async throws -> Void)? = nil
    ) async throws -> AuthenticatedResponse {
        try await sendPaid(
            method: method, path: path, query: query, headers: headers, body: body,
            payer: payer, payment: payment, paymentRetryAttempts: paymentRetryAttempts,
            onPayment: onPayment, makeSuffix: { try await AuthNonce.create($0) }
        )
    }

    /// `makeSuffix` makes each payment's derivation suffix; tests fix it.
    func sendPaid(
        method: String, path: String, query: String?,
        headers: [String: String], body: [UInt8]?,
        payer: any PayingWallet, payment resumed: BRC105Payment?,
        paymentRetryAttempts: Int,
        onPayment: (@Sendable (BRC105Payment) async throws -> Void)?,
        makeSuffix: @Sendable (any PayingWallet) async throws -> String
    ) async throws -> AuthenticatedResponse {
        let maxAttempts = paymentRetryAttempts > 0 ? paymentRetryAttempts : BRC105Payment.defaultAttempts
        let url = url(forPath: path, query: try Self.wireQuery(query)).absoluteString
        let call = "\(method) \(ErrorDetail.hostPath(host: baseURL.host, port: baseURL.port, path: path))"

        var payment: BRC105Payment
        if let resumed {
            payment = resumed
        } else {
            let response = try await send(
                method: method, path: path, query: query, headers: headers, body: body
            )
            guard response.statusCode == 402 else { return response }
            let requirement: BRC105Requirement
            do {
                requirement = try BRC105Requirement(response)
            } catch {
                ToolboxLog.error("ToolboxAuth", "\(call) answered 402 with a payment request this "
                    + "client can't meet: \(ErrorDetail.describe(error))")
                throw error
            }
            payment = try await pay(requirement, payer: payer, makeSuffix: makeSuffix)
            try await onPayment?(payment)
        }

        var attempts = 0
        while true {
            guard attempts < maxAttempts else {
                throw Self.failed(call: call, url: url, payment: payment, attempts: attempts,
                    maxAttempts: maxAttempts, lastError: "Maximum payment attempts exceeded before retrying")
            }
            attempts += 1
            var regenerated: BRC105Payment?
            do {
                let response = try await send(
                    method: method, path: path, query: query,
                    headers: Self.headers(headers, paying: payment), body: body
                )
                guard response.statusCode == 402 else { return response }
                // AuthFetch reads a 402 to a paid send in a nested call, so a fault in it (or in
                // building a new payment) is this attempt's failure, retried with this payment.
                let requirement = try BRC105Requirement(response)
                // With no paid send left, a new payment could never be sent, so none is made: the
                // loop ends at its attempt check.
                if !payment.satisfies(requirement), attempts < maxAttempts {
                    ToolboxLog.error("ToolboxAuth", "\(call): the server changed the payment it "
                        + "asks for after payment \(payment.transactionID); paying again "
                        + "(\(requirement.satoshis) satoshis)")
                    regenerated = try await pay(requirement, payer: payer, makeSuffix: makeSuffix)
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                ToolboxLog.error("ToolboxAuth", "\(call): paid attempt \(attempts)/\(maxAttempts) "
                    + "with payment \(payment.transactionID) failed: \(ErrorDetail.describe(error))")
                guard attempts < maxAttempts else {
                    throw Self.failed(call: call, url: url, payment: payment, attempts: attempts,
                        maxAttempts: maxAttempts, lastError: ErrorDetail.describe(error))
                }
                try await Task.sleep(nanoseconds: Self.paymentRetryDelay(afterAttempt: attempts))
                continue
            }
            if let regenerated {
                payment = regenerated
                try await onPayment?(regenerated)
            }
        }
    }

    /// `getPaymentRetryDelay`: 250 ms per failed attempt so far, at most 1.25 s.
    static func paymentRetryDelay(afterAttempt attempt: Int) -> UInt64 {
        UInt64(250 * min(attempt, 5)) * 1_000_000
    }

    /// The caller's headers with the payment added, replacing any `x-bsv-payment` they set.
    static func headers(_ headers: [String: String], paying payment: BRC105Payment) -> [String: String] {
        var result = headers.filter { $0.key.lowercased() != "x-bsv-payment" }
        result["x-bsv-payment"] = payment.headerValue
        return result
    }

    /// `createPaymentContext`: the payee's BRC-29 key from this prefix and a new suffix, one
    /// P2PKH output for the amount, and the action that funds, signs and sends it.
    private func pay(
        _ requirement: BRC105Requirement, payer: any PayingWallet,
        makeSuffix: @Sendable (any PayingWallet) async throws -> String
    ) async throws -> BRC105Payment {
        let suffix = try await makeSuffix(payer)
        let payee = try PublicKey(Hex.decode(requirement.serverIdentityKey, maximumDecodedByteCount: 65))
        let derived = try await payer.getPublicKey(WalletGetPublicKeyRequest(selection: .derived(
            protocolID: WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: BRC29.protocolID),
            keyID: WalletKeyID(BRC29.keyID(prefix: requirement.derivationPrefix, suffix: suffix)),
            counterparty: .publicKey(payee), forSelf: false
        )))
        let instructions = OrderedJSON.record([
            "derivationPrefix": .string(requirement.derivationPrefix),
            "derivationSuffix": .string(suffix),
            "payee": .string(requirement.serverIdentityKey),
        ]).serialized()
        let output = try WalletCreateActionOutput(
            lockingScript: try BRC29.lockingScript(for: derived.publicKey).bytes,
            satoshis: requirement.satoshis,
            outputDescription: "HTTP request payment",
            customInstructions: instructions
        )
        let result = try await payer.createAction(WalletCreateActionRequest(
            description: "Payment for request to \(origin)",
            outputs: [output],
            options: WalletCreateActionOptions(randomizeOutputs: false)
        ))
        guard let transaction = result.transaction else {
            ToolboxLog.error("ToolboxAuth", "the wallet funded the payment for \(origin) but "
                + "returned no transaction")
            throw BRC105Error.invalidTransaction
        }
        return try BRC105Payment(
            derivationPrefix: requirement.derivationPrefix, derivationSuffix: suffix,
            serverIdentityKey: requirement.serverIdentityKey, satoshisRequired: requirement.satoshis,
            transaction: try transaction.serialized(limits: StorageLimits.beef)
        )
    }

    /// `new URL(url).origin`: scheme, host and a port other than the scheme's default.
    var origin: String {
        let scheme = (baseURL.scheme ?? "https").lowercased()
        var host = (baseURL.host ?? "").lowercased()
        if host.contains(":"), !host.hasPrefix("[") { host = "[\(host)]" }
        let defaultPort = ["http": 80, "https": 443, "ws": 80, "wss": 443][scheme]
        guard let port = baseURL.port, port != defaultPort else { return "\(scheme)://\(host)" }
        return "\(scheme)://\(host):\(port)"
    }

    private static func failed(
        call: String, url: String, payment: BRC105Payment, attempts: Int, maxAttempts: Int,
        lastError: String
    ) -> BRC105Error {
        let error = BRC105Error.paymentFailed(
            url: url, attempts: attempts, maxAttempts: maxAttempts,
            satoshis: payment.satoshisRequired, serverIdentityKey: payment.serverIdentityKey,
            transactionID: payment.transactionID, lastError: lastError
        )
        ToolboxLog.error("ToolboxAuth", "\(call): \(ErrorDetail.describe(error)); derivation prefix "
            + "\(payment.derivationPrefix), suffix \(payment.derivationSuffix)")
        return error
    }
}
