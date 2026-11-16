import Foundation
import ToolboxCore

/// Logs where a permission check turns a failure into a denial or skips a token, so the reason
/// is not lost.
enum PermissionLog {
    static func error(_ message: @autoclosure () -> String) {
        ToolboxLog.error("ToolboxPermissions", message())
    }
}

// Short user text for permission errors. The values each case carries are what
// `String(reflecting:)` prints, so the log keeps them.

extension PermissionModuleRegistryError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidScheme: "The permission module's scheme is not valid."
        case .duplicateScheme: "A permission module is already registered for this scheme."
        case .invalidTimeout: "The permission module's timeout must be positive."
        case .permissionDenied: Self.permissionDeniedMessage
        }
    }
}

extension PermissionTokenMutationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .emptyMutation: "The permission change names nothing to change."
        case .accountMismatch: "The permission belongs to a different account."
        case .duplicateConsumedOutpoint: "The permission change names the same token twice."
        case .invalidConsumedValue: "A permission token to replace does not hold exactly 1 satoshi."
        case .noRenewalCandidate: "There is no permission to renew."
        case .renewalNotSupported: "This permission can't be renewed."
        case .replacementScopeMismatch: "The new permission does not cover the same scope as the old one."
        case .invalidStorageReference: "The wallet storage server returned a reference that is not valid."
        case .untrustworthyFundedBEEF:
            "The wallet storage server funded the permission change without proof of its coins, so nothing was signed."
        case .mutationInFlight: "This permission is already being changed. Try again in a moment."
        }
    }
}

extension PermissionTokenRepositoryError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidAccountID: "The permission lookup names an account that is not valid."
        case .invalidated: "The account changed while its permissions were being read. Try again."
        case .missingBEEF: "The wallet storage server sent permissions without their transactions."
        case .untrustworthyBEEF: "The wallet storage server sent a permission whose transaction does not prove it."
        case .candidateLimitExceeded(let total, let maximum):
            "There are \(total) permission tokens to check, more than the \(maximum) this wallet reads."
        case .paginationDidNotProgress, .paginationOverflow:
            "The wallet storage server paged the permission list incorrectly."
        }
    }
}

extension PermissionTokenError: LocalizedError {
    public var errorDescription: String? {
        "A permission token could not be read."
    }
}

extension PermissionPolicyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .missingOriginator: "The request does not say which app sent it."
        case .invalidCounterparty: "The request names a counterparty that is not a valid key."
        case .invalidProtocolSecurityLevel(let level): "Protocol security level \(level) is not valid."
        case .missingLevelTwoCounterparty: "A level-2 protocol request must name its counterparty."
        }
    }
}

extension SpendingReview.ReviewError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .missingTransaction: "The spending request has no transaction to review."
        case .missingSourceOutput: "A coin the request spends is missing from its transaction data."
        case .duplicateInput: "The request spends the same coin twice."
        case .missingRequestedInput: "A coin the request names is not in its transaction."
        case .missingRequestedOutput: "An output the request names is not in its transaction."
        case .amountOverflow: "The request's amounts are too large to add up."
        case .outputsExceedInputs: "The request pays out more than it spends."
        }
    }
}
