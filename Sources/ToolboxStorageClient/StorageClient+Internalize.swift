import Foundation
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// Accepting a payment somebody else made to this wallet.
///
/// `internalizeAction` takes a transaction that already exists on chain — as Atomic BEEF — and
/// tells storage which of its outputs belong to this wallet and how. A wallet-payment output is
/// spendable money, tagged with the BRC-29 derivation needed to unlock it later; a basket
/// insertion is a token or ordinal to hold rather than spend.
extension StorageClient {

    public func internalizeAction(
        _ auth: AuthID, _ request: WalletInternalizeActionRequest
    ) async throws -> WalletInternalizeActionResult {
        let outputs = try request.outputs.map { output -> JSONValue in
            switch output.remittance {
            case .walletPayment(let payment):
                return .object([
                    "outputIndex": .number(Double(output.outputIndex)),
                    "protocol": .string("wallet payment"),
                    "paymentRemittance": .object([
                        "derivationPrefix": .string(payment.derivationPrefix.base64),
                        "derivationSuffix": .string(payment.derivationSuffix.base64),
                        "senderIdentityKey": .string(
                            payment.senderIdentityKey.compressedBytes
                                .map { String(format: "%02x", $0) }.joined()
                        ),
                    ]),
                ])
            case .basketInsertion(let insertion):
                // `validateBasketInsertion`: basket and tags trimmed and lowercased, as storage
                // stores and matches them.
                var remittance: [String: JSONValue] = [
                    "basket": .string(try ActionBatchWire.identifier(insertion.basket, name: "basket")),
                    "tags": .array(try ActionBatchWire.identifiers(insertion.tags, name: "tag").map { .string($0) }),
                ]
                if let instructions = insertion.customInstructions {
                    remittance["customInstructions"] = .string(instructions)
                }
                return .object([
                    "outputIndex": .number(Double(output.outputIndex)),
                    "protocol": .string("basket insertion"),
                    "insertionRemittance": .object(remittance),
                ])
            }
        }

        let arguments: [String: JSONValue] = [
            "description": .string(request.description),
            // `validateInternalizeActionArgs` validates each label as `validateLabel` does.
            "labels": .array(try ActionBatchWire.identifiers(request.labels, name: "label").map { .string($0) }),
            "outputs": .array(outputs),
        ]
        // The Atomic BEEF travels as bytes, as the reference signer sends it
        // (`ab.toUint8ArrayAtomic(txid)`): base64 once storage reads binary requests, so a large
        // received transaction stays within the auth layer's 100,000-value cap.
        let transaction = try request.transaction.serialized(limits: StorageLimits.beef)

        let result = try await call("internalizeAction", rawParams: [
            OrderedJSON(.object(auth.jsonObject)),
            OrderedJSON(.object(arguments)).setting("tx", .bytes(transaction)),
        ])
        return WalletInternalizeActionResult(accepted: result["accepted"]?.boolValue ?? true)
    }
}
