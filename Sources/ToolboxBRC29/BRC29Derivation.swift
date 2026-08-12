import BSVKeys
import BSVScript

/// Deriving the keys and addresses a BRC-29 payment uses.
///
/// A payer and a payee agree on a prefix and a suffix. Each side then derives the same P2PKH
/// address from them: the payer from the payee's public key, the payee from its own private key.
/// No address is reused and neither side has to ask the other for one.
///
/// Both derivations go through BRC-42 in `swift-sdk`, against the invoice number pinned in
/// `BRC29`. Deriving by hand here would be inventing key mathematics, which is how money becomes
/// unspendable — the address looks right and no key opens it.
public extension BRC29 {

    /// The private key that unlocks an output paid to us.
    ///
    /// `recipientKey` is our own identity key and `senderPublicKey` is the payer's. Both halves
    /// of the derivation are required: the same prefix and suffix under a different counterparty
    /// give a different key, which is why an output stores who paid it as well as how.
    static func receivingPrivateKey(
        recipient recipientKey: PrivateKey,
        sender senderPublicKey: PublicKey,
        prefix: String,
        suffix: String
    ) throws -> PrivateKey {
        try recipientKey.derivedChild(
            with: senderPublicKey,
            invoiceNumber: invoiceNumber(prefix: prefix, suffix: suffix)
        )
    }

    /// The public key to pay, derived by the payer.
    ///
    /// `recipientPublicKey` is who is being paid and `senderKey` is our own identity key. The
    /// result is the public half of what the recipient will derive privately, which is what makes
    /// the payment spendable by them and nobody else.
    static func payingPublicKey(
        recipient recipientPublicKey: PublicKey,
        sender senderKey: PrivateKey,
        prefix: String,
        suffix: String
    ) throws -> PublicKey {
        try recipientPublicKey.derivedChild(
            with: senderKey,
            invoiceNumber: invoiceNumber(prefix: prefix, suffix: suffix)
        )
    }

    /// The address a BRC-29 payment is sent to.
    static func address(
        for publicKey: PublicKey,
        network: BitcoinNetwork = .mainnet
    ) -> Address {
        Address(publicKey: publicKey, network: network)
    }

    /// The locking script for a BRC-29 payment.
    ///
    /// Plain P2PKH over the derived key. BRC-29 changes which key is used, never how the output
    /// is locked, so anything that can spend a P2PKH output can spend this one given the key.
    static func lockingScript(
        for publicKey: PublicKey,
        network: BitcoinNetwork = .mainnet,
        maximumByteCount: Int = 1 << 20
    ) throws -> Script {
        try Script.payToPublicKeyHash(
            address(for: publicKey, network: network).publicKeyHash,
            maximumByteCount: maximumByteCount
        )
    }

    // MARK: - Receive addresses

    /// The fixed derivation prefix Yours Wallet uses for a receiving address.
    ///
    /// It is `"yours receive"` exactly, and it is not ours to change: a wallet restored from a
    /// Yours backup must derive the same addresses, or the money that was received there becomes
    /// invisible. The suffix is the address index written as a decimal string.
    static let receivePrefix = "yours receive"

    /// The key that receives at a given index.
    ///
    /// A receiving address is derived self-referentially: the wallet is both the recipient and the
    /// sender, so it can rebuild the same address set on any device from the identity key alone.
    /// That is what makes these addresses recoverable — no counterparty has to be remembered.
    static func receivingKey(
        identity: PrivateKey,
        index: Int
    ) throws -> PrivateKey {
        try receivingPrivateKey(
            recipient: identity,
            sender: identity.publicKey,
            prefix: receivePrefix,
            suffix: String(index)
        )
    }

    /// The receiving address at a given index.
    static func receivingAddress(
        identity: PrivateKey,
        index: Int,
        network: BitcoinNetwork = .mainnet
    ) throws -> Address {
        address(for: try receivingKey(identity: identity, index: index).publicKey, network: network)
    }
}
