import Foundation

// Short user text for the wallet's own errors. The values each case carries (txid, output index,
// detail string) are what `String(reflecting:)` prints, so the log keeps them.

extension WalletError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notImplemented(let operation):
            "This wallet does not support \(operation) yet."
        case .identityMismatch:
            "This wallet's identity does not match the account it was asked to use."
        case .chainInformationServiceUnavailable:
            "This wallet has no chain service to read block headers from."
        case .chainHeaderHeightMismatch(let requested, let returned):
            "The chain service answered with block \(returned) instead of block \(requested)."
        case .chainHeaderBytesUnavailable(let height):
            "The chain service did not send the full header for block \(height)."
        case .invalidReference:
            "The storage reference for this action is not valid."
        case .paymailDeliveryFailed:
            "The payment was sent on chain, but the recipient's paymail provider could not be told about it."
        case .broadcastFailed:
            "The transaction could not be broadcast, so it is not on chain."
        case .internalizeSubjectMissing:
            "The incoming transaction is missing from the data that came with it."
        case .internalizeOutputOutOfRange(let index):
            "Output \(index) is not in the incoming transaction."
        case .outputIsNotBRC29Payment(let index):
            "Output \(index) of the incoming transaction does not pay this wallet."
        case .invalidCertificate:
            "The certificate could not be verified, so it was not saved."
        case .storageMutationIncomplete:
            "The wallet storage server did not confirm the change. Try again."
        }
    }
}

extension WalletActionLifecycleError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unknownReference: "This wallet holds no unsigned action with that reference."
        case .pendingActionLimit: "Too many actions are waiting to be signed. Finish or abort one first."
        case .invalidFunding: "The wallet storage server funded the action in a way this wallet can't sign."
        case .invalidSpend: "An unlocking script for the action is not valid."
        case .unsupportedBatch: "This kind of batched action is not supported."
        }
    }
}

extension BRC29PaymentError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .outputNotUniquelyIdentified(let matches):
            "The payment output appears \(matches) times in the transaction instead of once, so nothing was sent."
        case .notReleased:
            "Nothing was sent, but the wallet storage server did not confirm releasing the coins it reserved."
        }
    }
}

extension RemoteWalletPermissionTokenAdapterError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidListRequest: "The permission token lookup was not valid."
        }
    }
}
