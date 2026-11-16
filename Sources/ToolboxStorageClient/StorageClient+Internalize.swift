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
                // Deliberately not what TS sends. The TS client passes the caller's raw basket and
                // tags, and TS storage files basket insertions from those raw args (its own
                // `validateInternalizeActionArgs` result is used only for labels), so a mixed-case
                // name lands in a basket that `listOutputs`, which lowercases, never finds. Sending
                // them as `validateBasketInsertion` normalises them keeps internalized outputs in
                // the basket every other call names.
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
            // The transaction travels as a JSON byte array, the shape storage sends and takes BEEF.
            "tx": .array(try request.transaction.serialized(
                limits: StorageLimits.beef
            ).map { .number(Double($0)) }),
            "description": .string(request.description),
            // TS storage reads labels from its own `validateInternalizeActionArgs`, which
            // normalises each as `validateLabel` does; sending them normalised gives the same rows.
            "labels": .array(try ActionBatchWire.identifiers(request.labels, name: "label").map { .string($0) }),
            "outputs": .array(outputs),
        ]

        let result = try await call(
            "internalizeAction", [.object(auth.jsonObject), .object(arguments)]
        )
        return WalletInternalizeActionResult(accepted: result["accepted"]?.boolValue ?? true)
    }
}
