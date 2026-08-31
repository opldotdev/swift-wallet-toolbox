import BSVCore
import BSVTransaction

/// One atomic change to an account's canonical BRC-116 permission state.
public struct PermissionTokenMutationRequest: Sendable {
    public let accountID: PermissionAccountID
    public let consumed: [PermissionTokenMatch]
    public let created: [PermissionToken]

    package init(
        accountID: PermissionAccountID,
        consumed: [PermissionTokenMatch],
        created: [PermissionToken]
    ) throws {
        guard !consumed.isEmpty || !created.isEmpty else {
            throw PermissionTokenMutationError.emptyMutation
        }
        var outpoints = Set<Outpoint>()
        for match in consumed {
            guard match.accountID == accountID else {
                throw PermissionTokenMutationError.accountMismatch
            }
            guard match.satoshis == 1 else {
                throw PermissionTokenMutationError.invalidConsumedValue(
                    outpoint: match.outpoint, satoshis: match.satoshis
                )
            }
            guard outpoints.insert(match.outpoint).inserted else {
                throw PermissionTokenMutationError.duplicateConsumedOutpoint(match.outpoint)
            }
        }
        self.accountID = accountID
        self.consumed = consumed
        self.created = created
    }
}

public struct PermissionTokenMutationResult: Sendable {
    public let transactionID: TransactionID
    public let reference: String

    public init(transactionID: TransactionID, reference: String) {
        self.transactionID = transactionID
        self.reference = reference
    }
}

public enum PermissionTokenMutationError: Error, Equatable, Sendable {
    case emptyMutation
    case accountMismatch
    case duplicateConsumedOutpoint(Outpoint)
    case invalidConsumedValue(outpoint: Outpoint, satoshis: UInt64)
    case noRenewalCandidate
    case renewalNotSupported
    case replacementScopeMismatch
    case invalidStorageReference
    case untrustworthyFundedBEEF
    case mutationInFlight(outpoint: Outpoint)
}
