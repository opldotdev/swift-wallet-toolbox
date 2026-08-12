import BSVCompat
import BSVKeys

/// Recovering a wallet's identity key from its recovery phrase.
///
/// This is the BSV Association's reference scheme, matching `bsv-desktop` exactly: the identity key
/// **is** the mnemonic's key material, with no BIP-32 path, no hashing, and no per-account
/// derivation function. It is the most authoritative choice because `bsv-desktop` is the official
/// BRC-100 wallet built on the same `wallet-toolbox` + storage stack this library targets.
///
/// Two cases, branching on the entropy size, both from `bsv-desktop/src/lib/utils/keyMaterial.ts`:
///
/// - **24-word phrase** (256-bit / 32-byte entropy): the entropy itself is the private key. This is
///   reversible — the phrase can be regenerated from the key — which is why the reference prefers
///   it when available.
/// - **12-word phrase** (128-bit entropy): the first 32 bytes of the BIP-39 seed.
///
/// There is deliberately no BIP-39 passphrase here. The reference keeps the wallet password as a
/// separate encryption layer (UMP), never mixed into the identity key.
public enum MnemonicRestore {

    /// The identity key a phrase recovers. This key both authenticates to storage and signs.
    public static func identityKey(fromPhrase phrase: String) throws -> PrivateKey {
        try identityKey(from: try Mnemonic(phrase))
    }

    /// The identity key a parsed mnemonic recovers.
    ///
    /// The branch on entropy size is the whole scheme, so it lives here once and both the phrase
    /// overload and a caller that already holds the mnemonic go through it. A caller that instead
    /// takes the first 32 bytes of the seed for a 24-word phrase derives a different, wrong key.
    public static func identityKey(from mnemonic: Mnemonic) throws -> PrivateKey {
        let keyBytes: [UInt8]
        if mnemonic.entropy.count == 32 {
            // 24-word: the entropy is the key, reversibly.
            keyBytes = mnemonic.entropy
        } else {
            // 12-word: the first 32 bytes of the seed.
            keyBytes = Array(try mnemonic.seed().bytes.prefix(32))
        }
        return try PrivateKey(keyBytes)
    }
}
