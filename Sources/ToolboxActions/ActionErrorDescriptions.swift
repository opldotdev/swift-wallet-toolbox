import Foundation
import ToolboxCore

// Short user text for building and signing errors. The detail each case carries stays in
// `String(reflecting:)`, for the log.

extension ActionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notImplemented(let operation):
            "This wallet does not support \(operation) yet."
        case .storageAlteredOutputs:
            "The wallet storage server changed the transaction's outputs, so nothing was signed."
        case .insufficientFunds(let required, let available):
            "Not enough funds: this needs \(required) satoshis and \(available) are available."
        case .unusableInput(let detail):
            "One of the coins chosen for this transaction can't be used: \(ErrorDetail.oneLine(detail))."
        case .unresolvableChange:
            "The wallet storage server sent change this wallet can't verify, so nothing was signed."
        case .feeTooHigh(let paid, let maximum):
            "The fee of \(paid) satoshis is above the \(maximum)-satoshi limit, so nothing was signed."
        case .malformedOutputs:
            "The wallet storage server sent the transaction's outputs out of order, so nothing was signed."
        }
    }
}
