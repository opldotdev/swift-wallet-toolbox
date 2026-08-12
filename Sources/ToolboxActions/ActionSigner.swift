import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage

/// Signs the inputs a funded action spends.
///
/// Every input storage returns is one of the wallet's own outputs, locked to a BRC-29 key. The
/// prefix and suffix stored alongside it name that key; this derives it and signs.
///
/// It goes through `assemble`, so the output check has already run by the time any key is used.
/// Signing from a `StorageCreateActionResult` directly is not offered — a second entry point is a
/// second way to skip the check.
public enum ActionSigner {

    /// Verifies, assembles, and signs every input.
    ///
    /// - Parameters:
    ///   - funded: what storage returned.
    ///   - requested: the outputs the caller asked for, from their own request.
    ///   - identityKey: the wallet's key, from which each input's spending key is derived.
    ///   - senderPublicKey: who paid these outputs. For change the wallet paid itself, so this is
    ///     the wallet's own public key.
    ///   - maximumFee: the most the caller will pay to miners, in satoshis.
    public static func sign(
        _ funded: StorageCreateActionResult,
        requested: [WalletCreateActionOutput],
        identityKey: PrivateKey,
        senderPublicKey: PublicKey,
        maximumFee: Int64,
        limits: TransactionLimits = WalletTransactionLimits.standard
    ) throws -> Transaction {
        // Before the outputs are even checked. Storage picks the inputs, so it can leave every
        // output exactly as asked and still take the whole wallet as a fee by selecting a large
        // input and returning no change. No output is wrong, so no output check finds it.
        try ActionAssembler.requireFeeWithin(maximumFee, for: funded)

        var transaction = try ActionAssembler.assemble(
            funded, requested: requested, changeKey: identityKey, limits: limits
        )

        for (index, input) in funded.inputs.enumerated() {
            guard let prefix = input.derivationPrefix,
                  let suffix = input.derivationSuffix else {
                // Without both halves the key cannot be rebuilt. Signing the rest and returning a
                // partly signed transaction would look like success and spend nothing.
                throw ActionError.unusableInput(
                    "input \(index) is missing its derivation, so its key cannot be found"
                )
            }

            // Each input is derived against whoever paid it. Two inputs from different senders
            // produce different spending keys, so a single sender for all of them would sign at
            // most one. An input with no recorded sender is change the wallet paid itself, and its
            // counterparty is the fallback — normally the wallet's own key.
            let sender: PublicKey
            if let senderHex = input.senderIdentityKey {
                guard let bytes = hexBytes(senderHex), let key = try? PublicKey(bytes) else {
                    throw ActionError.unusableInput(
                        "input \(index) names a sender key that cannot be read"
                    )
                }
                sender = key
            } else {
                sender = senderPublicKey
            }

            let spendingKey = try BRC29.receivingPrivateKey(
                recipient: identityKey,
                sender: sender,
                prefix: prefix,
                suffix: suffix
            )

            do {
                try transaction.signPayToPublicKeyHashInput(
                    at: index, with: spendingKey, limits: limits
                )
            } catch {
                // The SDK refuses when the derived key does not hash to the script it is unlocking.
                // That means the derivation and the output disagree, which is worth saying plainly
                // rather than reporting as a signature failure.
                throw ActionError.unusableInput(
                    "input \(index) is not locked to the key its derivation produces"
                )
            }
        }

        return transaction
    }

    private static func hexBytes(_ text: String) -> [UInt8]? {
        guard text.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}