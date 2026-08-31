import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage

/// Signs the inputs a funded action spends.
///
/// The ordinary path accepts only the wallet's own BRC-29 outputs. The package-only BRC-116 path
/// additionally accepts permission-token inputs whose exact sources the permission repository
/// declares independently of storage's funded response.
///
/// It goes through `assemble`, so the output check has already run by the time any key is used.
/// Signing from a `StorageCreateActionResult` directly is not offered — a second entry point is a
/// second way to skip the check.
public enum ActionSigner {

    /// One BRC-116 permission token that a funded action is expected to consume.
    ///
    /// The expected source data is caller-owned state, not a copy of storage's funded response.
    /// Matching all three values before asking the wallet to sign prevents storage from swapping
    /// the declared token for another output at the same input position.
    package struct BRC116PermissionTokenSpend: Sendable {
        package let outpoint: Outpoint
        package let satoshis: Int64
        package let lockingScript: [UInt8]
        package let signer: any WalletSignatureOperations

        package init(
            outpoint: Outpoint,
            satoshis: Int64,
            lockingScript: [UInt8],
            signer: any WalletSignatureOperations
        ) {
            self.outpoint = outpoint
            self.satoshis = satoshis
            self.lockingScript = lockingScript
            self.signer = signer
        }
    }

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

    /// Signs a funded BRC-116 token renewal or revocation action.
    ///
    /// Storage may add and reorder ordinary wallet inputs while funding. Token declarations are
    /// therefore matched to the transaction's actual outpoints, never to an assumed input index.
    /// This entry point is package-only because its fixed admin protocol is an implementation
    /// detail of the permission repository, not a general external-input signing API.
    package static func signBRC116PermissionTokenAction(
        _ funded: StorageCreateActionResult,
        requested: [WalletCreateActionOutput],
        identityKey: PrivateKey,
        senderPublicKey: PublicKey,
        permissionTokenSpends: [BRC116PermissionTokenSpend],
        maximumFee: Int64,
        limits: TransactionLimits = WalletTransactionLimits.standard
    ) async throws -> Transaction {
        // These checks deliberately precede declaration parsing and key derivation. Storage can
        // preserve every declared input while redirecting an output or taking an excessive fee.
        try ActionAssembler.requireFeeWithin(maximumFee, for: funded)
        var transaction = try ActionAssembler.assemble(
            funded, requested: requested, changeKey: identityKey, limits: limits
        )

        var declarations: [Outpoint: BRC116PermissionTokenSpend] = [:]
        for declaration in permissionTokenSpends {
            guard declarations.updateValue(declaration, forKey: declaration.outpoint) == nil else {
                throw ActionError.unusableInput(
                    "permission token spend is declared more than once: \(declaration.outpoint)"
                )
            }
        }

        enum SigningPlan {
            case brc29(index: Int, key: PrivateKey)
            case permissionToken(index: Int, signer: any WalletSignatureOperations)
        }

        var seenFundedOutpoints: Set<Outpoint> = []
        var matchedDeclarations: Set<Outpoint> = []
        var plans: [SigningPlan] = []
        plans.reserveCapacity(funded.inputs.count)

        // Validate every funded input before making any signature request. Besides preventing a
        // partly signed result, this makes an undeclared PushDrop input fail as a non-BRC-29 input
        // instead of being opportunistically signed with an unrelated wallet key.
        for (index, input) in funded.inputs.enumerated() {
            let outpoint = try fundedOutpoint(input, at: index)
            guard seenFundedOutpoints.insert(outpoint).inserted else {
                throw ActionError.unusableInput(
                    "funded action contains duplicate input outpoint: \(outpoint)"
                )
            }

            if let declaration = declarations[outpoint] {
                guard matchedDeclarations.insert(outpoint).inserted else {
                    throw ActionError.unusableInput(
                        "permission token input is matched more than once: \(outpoint)"
                    )
                }
                guard input.sourceSatoshis == declaration.satoshis else {
                    throw ActionError.unusableInput(
                        "permission token \(outpoint) has a different source amount"
                    )
                }
                guard declaration.satoshis > 0 else {
                    throw ActionError.unusableInput(
                        "permission token \(outpoint) must carry at least one satoshi"
                    )
                }
                guard input.sourceLockingScript == declaration.lockingScript else {
                    throw ActionError.unusableInput(
                        "permission token \(outpoint) has a different locking script"
                    )
                }
                guard let sourceOutput = transaction.inputs[index].sourceOutput else {
                    throw ActionError.unusableInput(
                        "permission token \(outpoint) has no source output"
                    )
                }
                do {
                    _ = try PushDrop.decode(
                        sourceOutput.lockingScript,
                        lockPosition: .beforeCompatibility
                    )
                } catch {
                    throw ActionError.unusableInput(
                        "permission token \(outpoint) is not a BRC-48 PushDrop output"
                    )
                }
                plans.append(.permissionToken(index: index, signer: declaration.signer))
                continue
            }

            guard let prefix = input.derivationPrefix,
                  let suffix = input.derivationSuffix else {
                throw ActionError.unusableInput(
                    "input \(index) is neither a declared permission token nor a derived BRC-29 input"
                )
            }
            let sender = try inputSender(
                input, at: index, fallback: senderPublicKey
            )
            let spendingKey = try BRC29.receivingPrivateKey(
                recipient: identityKey,
                sender: sender,
                prefix: prefix,
                suffix: suffix
            )
            let expectedScript = try BRC29.lockingScript(for: spendingKey.publicKey).bytes
            guard input.sourceLockingScript == expectedScript else {
                throw ActionError.unusableInput(
                    "input \(index) is not a BRC-29 output locked to its recorded derivation"
                )
            }
            plans.append(.brc29(index: index, key: spendingKey))
        }

        if let missing = declarations.keys.first(where: { !matchedDeclarations.contains($0) }) {
            throw ActionError.unusableInput(
                "declared permission token is absent from the funded action: \(missing)"
            )
        }

        let protocolID = try WalletProtocolID.walletInternalAdmin(
            securityLevel: .everyAppAndCounterparty,
            name: "admin permission token encryption"
        )
        let keyID = try WalletKeyID("1")

        // Mutate only this local candidate. If any signer fails, no partly signed transaction is
        // returned to the caller.
        for plan in plans {
            switch plan {
            case .brc29(let index, let key):
                try transaction.signPayToPublicKeyHashInput(
                    at: index, with: key, limits: limits
                )
            case .permissionToken(let index, let signer):
                try await transaction.signPushDropInput(
                    at: index,
                    using: signer,
                    protocolID: protocolID,
                    keyID: keyID,
                    counterparty: .self,
                    lockPosition: .beforeCompatibility,
                    hashType: .all,
                    limits: limits
                )
            }
        }

        guard transaction.inputs.allSatisfy({ !$0.unlockingScript.bytes.isEmpty }) else {
            throw ActionError.unusableInput("not every funded input was signed")
        }
        return transaction
    }

    private static func fundedOutpoint(
        _ input: StorageActionInput, at index: Int
    ) throws -> Outpoint {
        do {
            return Outpoint(
                transactionID: try TransactionID(displayHex: input.sourceTXID),
                outputIndex: input.sourceVout
            )
        } catch {
            throw ActionError.unusableInput(
                "input \(index) names a transaction that cannot be read: \(input.sourceTXID)"
            )
        }
    }

    private static func inputSender(
        _ input: StorageActionInput,
        at index: Int,
        fallback: PublicKey
    ) throws -> PublicKey {
        guard let senderHex = input.senderIdentityKey else { return fallback }
        guard let bytes = hexBytes(senderHex), let key = try? PublicKey(bytes) else {
            throw ActionError.unusableInput(
                "input \(index) names a sender key that cannot be read"
            )
        }
        return key
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
