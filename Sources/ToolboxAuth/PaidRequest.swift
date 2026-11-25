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
    /// The payment's bytes are not an Atomic BEEF envelope.
    case invalidTransaction
    /// Every paid send failed. The payment was sent to the network when it was built, so the
    /// coins are with the server's key: keep the payment and resend it.
    case paymentFailed(
        url: String, attempts: Int, maxAttempts: Int, satoshis: UInt64,
        serverIdentityKey: String, transactionID: String, lastError: String
    )
    /// `payer` pays from the identity `payer`, but the session authenticates as `session`. The
    /// server derives the payment's output from the session's identity, so it could never accept
    /// the payment: nothing was paid.
    case payerMismatch(payer: String, session: String)
    /// A payment passed back to resume pays `payee`, but the session's peer is `peer`. Nothing was
    /// sent.
    case paymentPeerMismatch(payee: String, peer: String)
    /// The wallet funded the payment, but returned nothing that can be sent: no transaction, an
    /// unsigned one, or one that is not Atomic BEEF. The paid request was not sent. `aborted` is
    /// true when the wallet released the action; otherwise `transactionID` (nil when the wallet
    /// named none) is the action to look for in the wallet.
    case paymentUnusable(transactionID: String?, aborted: Bool, reason: String)
    /// `onPayment` failed for this payment, so the paid request was not sent. The payment was
    /// built: save it and resume with it rather than paying again.
    case paymentNotSaved(payment: BRC105Payment, reason: String)
    /// A paid send failed after the request may have reached the server's application: the reply
    /// was lost or could not be read, or the server signed it for a session this side no longer
    /// holds. It is not sent again, since a paid request need not be idempotent. Check whether it
    /// took effect before resuming with `payment`.
    case outcomeUnknown(url: String, attempts: Int, payment: BRC105Payment, lastError: String)

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
        case .payerMismatch(let payer, let session):
            "The payer's identity key \(payer) is not the session's identity key \(session)."
        case .paymentPeerMismatch(let payee, let peer):
            "The payment pays \(payee), but the session's peer is \(peer)."
        case .paymentUnusable(let txid, let aborted, let reason):
            "The wallet's payment \(txid ?? "(no transaction ID)") can't be sent: \(reason). "
                + (aborted ? "The wallet released it." : "The wallet did not release it.")
        case .paymentNotSaved(let payment, let reason):
            "Payment \(payment.transactionID) of \(payment.satoshisRequired) satoshis to "
                + "\(payment.serverIdentityKey) was not saved: \(reason)"
        case .outcomeUnknown(let url, let attempts, let payment, _):
            "Paid request to \(url) may have run on attempt \(attempts); not resent. "
                + "Sent \(payment.satoshisRequired) satoshis to \(payment.serverIdentityKey)."
        }
    }

    /// True for a failure that must end the call even within a paid attempt: the request may
    /// have run, the payer can never pay, or the wallet funded a payment that can't be sent.
    var endsPaidRequest: Bool {
        switch self {
        case .outcomeUnknown, .payerMismatch, .paymentUnusable: true
        default: false
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
        case .payerMismatch:
            "The paying wallet isn't the one signed in to this server."
        case .paymentPeerMismatch:
            "That payment is for a different server."
        case .paymentUnusable(_, let aborted, _):
            aborted ? "The wallet couldn't build the payment. Nothing was spent."
                : "The wallet couldn't build the payment. Check the wallet's pending actions."
        case .paymentNotSaved(let payment, _):
            "The payment of \(payment.satoshisRequired) satoshis was made but couldn't be saved, "
                + "so the request wasn't sent."
        case .outcomeUnknown(_, _, let payment, _):
            "The paid request may have gone through (\(payment.satoshisRequired) satoshis sent). "
                + "Check before trying again."
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
        case .outcomeUnknown(_, _, let payment, let lastError):
            "BRC105Error.outcomeUnknown: \(ErrorDetail.withoutQueries(message)) payment "
                + "\(payment.transactionID); last error: \(lastError)"
        case .paymentUnusable:
            "BRC105Error.paymentUnusable: \(message)"
        case .paymentNotSaved:
            "BRC105Error.paymentNotSaved: \(message)"
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
    /// error status and is never paid. `payer` must hold the identity this session signs with,
    /// since the server derives the payment's output from it; otherwise
    /// ``BRC105Error/payerMismatch(payer:session:)`` is thrown before anything is paid.
    ///
    /// A paid send that fails before the request could reach the server's application (no
    /// connection, a refused handshake, an expired session the server refused before running the
    /// request, a gate's unsigned 4xx) is retried with the same payment after 250 ms, 500 ms and
    /// so on. Unlike AuthFetch, which retries every failure, a paid send that may have reached the
    /// application (a lost or unreadable reply, a signed reply for a session this side no longer
    /// holds) is not sent again, since a paid request such as a claim need not be idempotent:
    /// ``BRC105Error/outcomeUnknown(url:attempts:payment:lastError:)`` carries the payment, to
    /// resume with once the caller knows the first send did not take effect.
    ///
    /// A paid send answered with another 402 is sent again at once: with the same payment while
    /// the 402 asks for the same amount, payee and prefix, and with a new payment (passed to
    /// `onPayment`) when it changes any of them. At most `paymentRetryAttempts` paid sends are
    /// made in all (3 when it is not positive); after that ``BRC105Error/paymentFailed`` is thrown.
    ///
    /// `onPayment` runs after each payment is built and before it is first sent. The payment is
    /// already on the network then, so persist it there: if the reply is lost, pass it back as
    /// `payment` and the request is sent with it straight away, with no unpaid request first and
    /// no second payment. A resumed payment must pay this session's peer, or
    /// ``BRC105Error/paymentPeerMismatch(payee:peer:)`` is thrown before it is sent. An error from
    /// `onPayment` stops the call before the paid send, as
    /// ``BRC105Error/paymentNotSaved(payment:reason:)`` carrying the payment. A payment the wallet
    /// funds but that can't be sent is aborted where the wallet allows and thrown as
    /// ``BRC105Error/paymentUnusable(transactionID:aborted:reason:)``, never dropped.
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
            let peer = try await peerIdentityKey()
            let payee = try? PublicKey(Hex.decode(resumed.serverIdentityKey, maximumDecodedByteCount: 65))
            guard payee == peer else {
                let error = BRC105Error.paymentPeerMismatch(
                    payee: resumed.serverIdentityKey, peer: Hex.encode(peer.compressedBytes)
                )
                ToolboxLog.error("ToolboxAuth", "\(call): resumed payment \(resumed.transactionID) "
                    + "not sent: \(ErrorDetail.describe(error))")
                throw error
            }
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
            try await save(payment, call: call, onPayment: onPayment)
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
                let response: AuthenticatedResponse
                do {
                    response = try await sendTrackingDelivery(
                        method: method, path: path, query: query,
                        headers: Self.headers(headers, paying: payment), body: body
                    )
                } catch let sent as RequestMayHaveRun {
                    let error = BRC105Error.outcomeUnknown(url: url, attempts: attempts,
                        payment: payment, lastError: ErrorDetail.describe(sent.underlying))
                    ToolboxLog.error("ToolboxAuth", "\(call): \(ErrorDetail.describe(error)); "
                        + "derivation prefix \(payment.derivationPrefix), suffix \(payment.derivationSuffix)")
                    throw error
                }
                // A signed 402 is the server's payment check refusing the request before running
                // it, so sending it again is safe.
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
            } catch let error as BRC105Error where error.endsPaidRequest {
                throw error
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
                try await save(regenerated, call: call, onPayment: onPayment)
            }
        }
    }

    /// Hands a new payment to `onPayment`. Its failure is thrown with the payment, which is on the
    /// network by now and would otherwise be lost to the caller.
    private func save(
        _ payment: BRC105Payment, call: String,
        onPayment: (@Sendable (BRC105Payment) async throws -> Void)?
    ) async throws {
        do {
            try await onPayment?(payment)
        } catch {
            let error = BRC105Error.paymentNotSaved(payment: payment, reason: ErrorDetail.describe(error))
            ToolboxLog.error("ToolboxAuth", "\(call): \(ErrorDetail.describe(error)); derivation "
                + "prefix \(payment.derivationPrefix), suffix \(payment.derivationSuffix)")
            throw error
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
        try await requirePayer(payer)
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
        // From here the wallet holds a funded action, so no failure may drop it: each is thrown
        // naming it, and an unsigned one is released.
        if let signable = result.signableTransaction {
            // Asked for a signed, processed action, the wallet left it unsigned, so nothing of it
            // was sent and its inputs can be released.
            let txid = signable.transaction.subjectTransactionID.displayHex
            let aborted = await abort(signable.reference, payer: payer, transactionID: txid)
            throw unusable(txid, aborted: aborted, "the wallet returned it unsigned")
        }
        guard let transaction = result.transaction else {
            throw unusable(result.transactionID?.displayHex, aborted: false, "the wallet returned no transaction")
        }
        let txid = transaction.subjectTransactionID.displayHex
        do {
            return try BRC105Payment(
                derivationPrefix: requirement.derivationPrefix, derivationSuffix: suffix,
                serverIdentityKey: requirement.serverIdentityKey, satoshisRequired: requirement.satoshis,
                transaction: try transaction.serialized(limits: StorageLimits.beef)
            )
        } catch {
            throw unusable(txid, aborted: false,
                "it could not be written as Atomic BEEF (\(ErrorDetail.describe(error)))")
        }
    }

    /// Refuses a payer whose identity is not the one this session authenticates with: the server
    /// derives the payment's output from the session's identity and would refuse the payment.
    private func requirePayer(_ payer: any PayingWallet) async throws {
        let request = WalletGetPublicKeyRequest(selection: .identity)
        let payerKey = try await payer.getPublicKey(request).publicKey
        let sessionKey = try await wallet.getPublicKey(request).publicKey
        guard payerKey == sessionKey else {
            let error = BRC105Error.payerMismatch(
                payer: Hex.encode(payerKey.compressedBytes), session: Hex.encode(sessionKey.compressedBytes)
            )
            ToolboxLog.error("ToolboxAuth", "paying \(origin): \(ErrorDetail.describe(error))")
            throw error
        }
    }

    /// Releases an unsigned payment action. Best effort: false, logged, when the wallet keeps it.
    private func abort(
        _ reference: WalletBase64Data, payer: any PayingWallet, transactionID: String
    ) async -> Bool {
        do {
            let aborted = try await payer.abortAction(WalletAbortActionRequest(reference: reference)).aborted
            if !aborted {
                ToolboxLog.error("ToolboxAuth", "the wallet did not release payment action "
                    + "\(transactionID) for \(origin)")
            }
            return aborted
        } catch {
            ToolboxLog.error("ToolboxAuth", "abortAction did not release payment action "
                + "\(transactionID) for \(origin): \(ErrorDetail.describe(error))")
            return false
        }
    }

    private func unusable(_ transactionID: String?, aborted: Bool, _ reason: String) -> BRC105Error {
        let error = BRC105Error.paymentUnusable(transactionID: transactionID, aborted: aborted, reason: reason)
        ToolboxLog.error("ToolboxAuth", "the wallet funded the payment for \(origin): "
            + ErrorDetail.describe(error))
        return error
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
