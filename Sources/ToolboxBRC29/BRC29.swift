import Foundation
import BSVKeys

/// BRC-29 — the derivation scheme behind every address a wallet gives out.
///
/// A payer and a payee agree on a key identifier; each derives the same address from it, the payer
/// from the payee's public key and the payee from its own private key. No address is reused and
/// neither side has to ask the other for one.
///
/// It has its own module because it is its own thing: the Go toolbox gives it a top-level
/// `pkg/brc29`, and both a receiving screen and the change generator need it without needing each
/// other. Burying it in the action layer would make an address depend on the transaction builder.
///
/// It lives in the toolbox rather than the SDK for the same reason it does in TypeScript and Go:
/// BRC-42 and BRC-43 are general derivation and belong to the SDK, while BRC-29 is a wallet
/// payment convention built on top of them.
public enum BRC29 {
    /// The protocol identifier, security level 2. The same twelve characters appear in the
    /// TypeScript and Go implementations, and an address derived under any other string is a
    /// different address — which is to say, lost money.
    public static let protocolID = "3241645161d8"
    public static let securityLevel = 2

    /// The key identifier is the prefix and suffix joined by one space.
    ///
    /// Both halves are stored per output, because without them the key that unlocks that output
    /// cannot be found again.
    public static func keyID(prefix: String, suffix: String) -> String {
        "\(prefix) \(suffix)"
    }

    /// The invoice number BRC-43 derives against.
    public static func invoiceNumber(prefix: String, suffix: String) -> String {
        "\(securityLevel)-\(protocolID)-\(keyID(prefix: prefix, suffix: suffix))"
    }
}

public enum BRC29Error: Error, Equatable, Sendable {
    case notImplemented(String)
    /// A stored output carried one half of its derivation and not the other, so its key cannot be
    /// rebuilt. Reported rather than guessed: guessing here spends the wrong output or none.
    case incompleteDerivation
}
