import BSVKeys

/// The address a 1Sat wallet receives at.
///
/// This is a 1Sat-ecosystem convention, not a generic BRC-100 one, and it is **not** BRC-29. The
/// current `@1sat/actions` `deriveDepositAddresses` derives self-referentially under protocol
/// `[0, "p 1sat"]` with the key identifier `"1sat <index>"` — a BRC-42 child of the identity key
/// with the identity key as its own counterparty. Any wallet that binds the same identity key
/// derives the same default addresses without coordinating.
///
/// The protocol owner is `OneSatAddresses.DepositAddresses` in `swift-1sat-sdk`, which mirrors
/// `@1sat/actions` `deriveDepositAddresses` (including a caller-chosen prefix). This type is a
/// byte-identical copy of that derivation for the fixed default prefix `"1sat"`. The copy stays
/// here because the toolbox cannot depend on `swift-1sat-sdk`: that package already depends on
/// this one (`swift-1sat-sdk/Package.swift`), and the reverse edge would cycle. Change
/// `DepositAddresses` first. A change here that is not made there fails the cross-repo equality
/// test in `OneSatAddressesTests`.
///
/// An earlier version of this file used the prefix `"yours receive"` under BRC-29's protocol. That
/// convention was deleted upstream (`1sat-sdk` commit "Default deposit prefix '1sat'; remove
/// YOURS_PREFIX"), so it produced addresses the live ecosystem no longer scans — money received
/// against a real Yours identity would have been invisible. The values here are checked against
/// `@bsv/sdk`'s own `getPublicKey`, not against a vector this library generated for itself.
public enum OneSatDeposit {
    /// The keyID prefix. The suffix is the index as a decimal string, joined by a space.
    public static let prefix = "1sat"

    /// The BRC-43 invoice number the derivation runs against.
    ///
    /// Security level 0, protocol name `"p 1sat"`, key identifier `"1sat <index>"`. The exact
    /// string `@bsv/sdk` computes for `getPublicKey([0, "p 1sat"], "1sat <index>")`.
    static func invoiceNumber(index: Int) -> String {
        "0-p 1sat-\(prefix) \(index)"
    }

    /// The private key that receives at a given index.
    ///
    /// Self-referential: the identity key is both the derivation's owner and its counterparty, so
    /// the whole address set rebuilds from the identity key alone on any device.
    public static func key(identity: PrivateKey, index: Int) throws -> PrivateKey {
        try identity.derivedChild(
            with: identity.publicKey, invoiceNumber: invoiceNumber(index: index)
        )
    }

    /// The receiving address at a given index.
    public static func address(
        identity: PrivateKey,
        index: Int,
        network: BitcoinNetwork = .mainnet
    ) throws -> Address {
        Address(publicKey: try key(identity: identity, index: index).publicKey, network: network)
    }
}
