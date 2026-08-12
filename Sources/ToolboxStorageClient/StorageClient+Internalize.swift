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
        let outputs = request.outputs.map { output -> JSONValue in
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
                return .object([
                    "outputIndex": .number(Double(output.outputIndex)),
                    "protocol": .string("basket insertion"),
                    "insertionRemittance": .object([
                        "basket": .string(insertion.basket),
                        "tags": .array(insertion.tags.map { .string($0) }),
                    ]),
                ])
            }
        }

        let arguments: [String: JSONValue] = [
            // The transaction travels as a JSON byte array, the shape storage sends and takes BEEF.
            "tx": .array(try request.transaction.serialized(
                limits: StorageLimits.beef
            ).map { .number(Double($0)) }),
            "description": .string(request.description),
            "labels": .array(request.labels.map { .string($0) }),
            "outputs": .array(outputs),
        ]

        let result = try await call(
            "internalizeAction", [.object(auth.jsonObject), .object(arguments)]
        )
        return WalletInternalizeActionResult(accepted: result["accepted"]?.boolValue ?? true)
    }
}
