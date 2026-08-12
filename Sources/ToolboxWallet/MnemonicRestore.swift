import BSVCompat
import BSVKeys

/// Recovering a wallet's keys from its recovery phrase.
///
/// The phrase is the whole backup. Turning it into keys is the same sequence Yours Wallet uses, to
/// the exact derivation path, so a phrase written down in one wallet restores the same addresses in
/// this one. Getting the path wrong would produce a valid-looking wallet holding none of the
/// original money — so the paths are constants, checked against a cross-implementation vector.
public enum MnemonicRestore {

    /// BIP-44 style paths, matching `yours-wallet/src/utils/constants.ts`. Coin type 236 is BSV.
    public enum Path {
        /// The identity key, from which the BRC-100 wallet and its receiving addresses derive.
        public static let identity = "m/0'/236'/0'/0/0"
        /// The legacy funding key. Kept for a full restore of an older wallet's coins.
        public static let wallet = "m/44'/236'/0'/1/0"
        /// The legacy ordinals key.
        public static let ord = "m/44'/236'/1'/0/0"
    }

    /// Every key a restore recovers.
    public struct Keys: Sendable {
        public let identity: PrivateKey
        public let wallet: PrivateKey
        public let ord: PrivateKey

        public init(identity: PrivateKey, wallet: PrivateKey, ord: PrivateKey) {
            self.identity = identity
            self.wallet = wallet
            self.ord = ord
        }
    }

    /// The identity key alone — what a BRC-100 wallet is built from.
    ///
    /// `passphrase` is the optional BIP-39 twenty-fifth word, empty by default as Yours leaves it.
    public static func identityKey(
        fromPhrase phrase: String,
        passphrase: String = ""
    ) throws -> PrivateKey {
        try key(fromPhrase: phrase, passphrase: passphrase, path: Path.identity)
    }

    /// All three keys, for restoring an older wallet's funding and ordinals coins as well as its
    /// identity.
    public static func keys(
        fromPhrase phrase: String,
        passphrase: String = ""
    ) throws -> Keys {
        let root = try rootKey(fromPhrase: phrase, passphrase: passphrase)
        return Keys(
            identity: try root.derived(path: Path.identity).key,
            wallet: try root.derived(path: Path.wallet).key,
            ord: try root.derived(path: Path.ord).key
        )
    }

    private static func key(
        fromPhrase phrase: String, passphrase: String, path: String
    ) throws -> PrivateKey {
        try rootKey(fromPhrase: phrase, passphrase: passphrase).derived(path: path).key
    }

    private static func rootKey(
        fromPhrase phrase: String, passphrase: String
    ) throws -> ExtendedPrivateKey {
        let seed = try Mnemonic(phrase).seed(passphrase: passphrase)
        return try ExtendedPrivateKey(seed: seed.bytes, network: .mainnet)
    }
}
