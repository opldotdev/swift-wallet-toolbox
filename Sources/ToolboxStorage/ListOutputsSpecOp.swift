import Foundation

/// `listOutputs` special operations: reserved basket names that make storage run an operation
/// instead of listing that basket.
///
/// Storage runs these on its side, so a client only needs the name. The values and their meaning
/// are `@bsv/wallet-toolbox`'s (`src/sdk/types.ts`); the operations themselves are in its
/// `src/storage/methods/ListOutputsSpecOp.ts`.
public enum ListOutputsSpecOp {

    /// Returns the wallet's current change balance in `totalOutputs`. `outputs` is always empty.
    public static let walletBalance =
        "893b7646de0e1c9f741bd6e9169b76a8847ae34adef7bef1e6a285371206d2e8"

    /// Returns the wallet-managed change outputs: spendable BRC-29 change in the `default` basket.
    public static let walletManagedUtxos =
        "284570a6213a74ba861c38b1cf790e1e400d9cf9324454b76ea98860b6031c1a"

    /// Returns currently spendable change outputs conclusively confirmed spent, rejecting if any
    /// candidate cannot be classified. Tag `release` also marks them not spendable; tag `all`
    /// covers every spendable output regardless of basket.
    public static let invalidChange =
        "5a76fd430a311f8bc0553859061710a4475c19fed46e2ff95969aa918e612e57"

    /// Updates automatic change management. Tag 0 is the desired number of spendable change
    /// outputs, tag 1 the minimum satoshis for a new change output.
    public static let setWalletChangeParams =
        "a4979d28ced8581e9c1c92f1001cc7cb3aabf8ea32e10888ad898f0a509a3929"

    /// Lists outputs from every basket in the namespace given by tag 0 (a basket matches when its
    /// name is that tag followed by a space and more), for permission modules that keep one
    /// basket per asset, such as `p color`.
    ///
    /// Includes unspent outputs of signed transactions, including those awaiting broadcast, and
    /// outputs reserved as an input of a pending (`unsigned`, `unprocessed`, `nosend` or
    /// `sending`) action with `spendable` false. Spent outputs are excluded. Results are ordered
    /// by txid and vout and are not paged: `limit` and `offset` are ignored, and storage refuses
    /// the call when more than 10,000 outputs match.
    public static let basketPrefixOutputs =
        "b9184a72141e6a4d3d148c67a6d0ad92864a4d85290579ea5bef8bd62eb01b6f"

    /// Every `listOutputs` special-operation basket name.
    public static let all: [String] = [
        walletBalance, walletManagedUtxos, invalidChange, setWalletChangeParams, basketPrefixOutputs,
    ]

    /// Whether `basket` is a reserved `listOutputs` special-operation name
    /// (`isListOutputsSpecOp`).
    public static func contains(_ basket: String) -> Bool {
        all.contains(basket)
    }
}
