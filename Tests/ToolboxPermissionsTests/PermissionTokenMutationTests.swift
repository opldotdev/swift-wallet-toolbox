import BSVCore
import BSVScript
import BSVTransaction
import XCTest
@testable import ToolboxPermissions

final class PermissionTokenMutationTests: XCTestCase {
    func testMutationRejectsEmptyCrossAccountDuplicateAndNonOneSatInputs() throws {
        let first = try PermissionAccountID("first")
        let second = try PermissionAccountID("second")
        let token = PermissionToken.dsap(.init(
            scope: .init(originator: try CanonicalOriginator("example.com")),
            authorizedAmount: 5
        ))
        let oneSat = try match(accountID: first, token: token, satoshis: 1)
        let twoSat = PermissionTokenMatch(
            accountID: first,
            token: token,
            outpoint: oneSat.outpoint,
            satoshis: 2,
            lockingScript: oneSat.lockingScript,
            sourceBEEF: oneSat.sourceBEEF
        )

        assertMutationError(.emptyMutation) {
            _ = try PermissionTokenMutationRequest(
                accountID: first, consumed: [], created: []
            )
        }
        assertMutationError(.accountMismatch) {
            _ = try PermissionTokenMutationRequest(
                accountID: second, consumed: [oneSat], created: []
            )
        }
        assertMutationError(.duplicateConsumedOutpoint(oneSat.outpoint)) {
            _ = try PermissionTokenMutationRequest(
                accountID: first, consumed: [oneSat, oneSat], created: []
            )
        }
        assertMutationError(.invalidConsumedValue(outpoint: twoSat.outpoint, satoshis: 2)) {
            _ = try PermissionTokenMutationRequest(
                accountID: first, consumed: [twoSat], created: []
            )
        }
    }

    private func match(
        accountID: PermissionAccountID,
        token: PermissionToken,
        satoshis: UInt64
    ) throws -> PermissionTokenMatch {
        let script = try Script(bytes: [0x51], maximumByteCount: 1)
        let transaction = Transaction(outputs: [TransactionOutput(
            satoshis: satoshis, lockingScript: script
        )])
        let transactionID = try transaction.transactionID(
            limits: PermissionTokenRepository.standardTransactionLimits
        )
        return PermissionTokenMatch(
            accountID: accountID,
            token: token,
            outpoint: Outpoint(transactionID: transactionID, outputIndex: 0),
            satoshis: satoshis,
            lockingScript: script.bytes,
            sourceBEEF: try BEEF(
                merklePaths: [],
                transactions: [.raw(transaction)],
                limits: PermissionTokenRepository.standardBEEFLimits
            )
        )
    }
}

private func assertMutationError(
    _ expected: PermissionTokenMutationError,
    operation: () throws -> Void
) {
    do {
        try operation()
        XCTFail("Expected \(expected)")
    } catch let error as PermissionTokenMutationError {
        XCTAssertEqual(error, expected)
    } catch {
        XCTFail("Unexpected error: \(error)")
    }
}
