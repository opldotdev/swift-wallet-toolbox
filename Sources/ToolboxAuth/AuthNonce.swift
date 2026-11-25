import Foundation
import BSVWallet

/// The SDK's `createNonce` (`auth/utils/createNonce.ts`): sixteen random bytes followed by the
/// wallet's HMAC of them, base64.
///
/// The HMAC is under protocol `[2, "server hmac"]` with the random bytes, read as UTF-8, as its key
/// ID, so the wallet that made a nonce (and only it) can later tell it made it (`verifyNonce`).
/// BRC-105 uses one as a payment's derivation suffix; PeerPay uses two as a payment's prefix and
/// suffix.
public enum AuthNonce {
    static let randomByteCount = 16

    /// A fresh nonce from `wallet`, with `counterparty` `.self` as the SDK defaults it.
    public static func create(
        _ wallet: any WalletHMACOperations, counterparty: WalletCounterparty = .self
    ) async throws -> String {
        // `SystemRandomNumberGenerator` is cryptographically secure on every supported platform.
        let random = (0..<randomByteCount).map { _ in UInt8.random(in: .min ... .max) }
        return try await create(wallet, counterparty: counterparty, random: random)
    }

    /// The nonce for a given random half. Tests fix it to compare against TypeScript vectors.
    static func create(
        _ wallet: any WalletHMACOperations, counterparty: WalletCounterparty, random: [UInt8]
    ) async throws -> String {
        let hmac = try await wallet.createHMAC(WalletCreateHMACRequest(
            protocolID: WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: "server hmac"),
            keyID: WalletKeyID(keyID(for: random)), counterparty: counterparty, data: random))
        return Data(random + hmac.hmac.bytes).base64EncodedString()
    }

    /// `Utils.toUTF8(bytes)`, which is `new TextDecoder().decode(bytes)`: each ill-formed sequence
    /// becomes U+FFFD by the same maximal-subpart rule Swift's decoder follows, and a leading byte
    /// order mark is dropped, which Swift's decoder does not do on its own. Random bytes start with
    /// one once in 2^24 nonces; keeping it would derive a different HMAC key than TypeScript does.
    static func keyID(for bytes: [UInt8]) -> String {
        let text = bytes.starts(with: [0xEF, 0xBB, 0xBF]) ? Array(bytes.dropFirst(3)) : bytes
        return String(decoding: text, as: UTF8.self)
    }
}
