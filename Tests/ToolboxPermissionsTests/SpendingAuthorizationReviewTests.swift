import XCTest
import BSVScript
import BSVTransaction
import BSVWallet
@testable import ToolboxPermissions

final class SpendingAuthorizationReviewTests: XCTestCase {
    func testWalletFundingCountsRecipientAndFeeButNotChange() throws {
        let tx = try transaction()
        let review = try SpendingAuthorizationReview(transaction: tx, request: request())
        XCTAssertEqual(review.requestedOutputSatoshis, 600)
        XCTAssertEqual(review.suppliedInputSatoshis, 0)
        XCTAssertEqual(review.networkFee, 10)
        XCTAssertEqual(review.authorizationSatoshis, 610)
    }

    func testCallerFundingCreditsActualSourceValue() throws {
        let tx = try transaction()
        let input = try WalletCreateActionInput(
            outpoint: tx.inputs[0].previousOutput,
            inputDescription: "Caller funds", unlockingScriptLength: 1
        )
        let review = try SpendingAuthorizationReview(transaction: tx, request: request(inputs: [input]))
        XCTAssertEqual(review.suppliedInputSatoshis, 1000)
        XCTAssertEqual(review.authorizationSatoshis, 0)
    }

    func testSubstitutedRecipientAndCollapsedDuplicateAreRejected() throws {
        var tx = try transaction()
        tx.outputs[0].lockingScript = try Script(bytes: [0x53], maximumByteCount: 100)
        XCTAssertThrowsError(try SpendingAuthorizationReview(transaction: tx, request: request()))
        let output = try WalletCreateActionOutput(lockingScript: [0x51], satoshis: 600, outputDescription: "Recipient")
        let duplicateRequest = try WalletCreateActionRequest(description: "Send twice", outputs: [output, output])
        XCTAssertThrowsError(try SpendingAuthorizationReview(transaction: transaction(), request: duplicateRequest))
    }

    func testMixedFundingCreditsOnlyCallerInputAndAcceptsReorderedOutputs() throws {
        var tx = try transaction()
        var callerInput = tx.inputs[0]
        callerInput.previousOutput = try Outpoint(String(repeating: "02", count: 32) + ".0")
        callerInput.sourceOutput?.satoshis = 400
        tx.inputs.append(callerInput)
        tx.outputs[1].satoshis += 400
        tx.outputs.reverse()
        let supplied = try WalletCreateActionInput(
            outpoint: callerInput.previousOutput, inputDescription: "Caller funds",
            unlockingScriptLength: 1
        )
        let review = try SpendingAuthorizationReview(transaction: tx, request: request(inputs: [supplied]))
        XCTAssertEqual(review.networkFee, 10)
        XCTAssertEqual(review.suppliedInputSatoshis, 400)
        XCTAssertEqual(review.authorizationSatoshis, 210)
    }

    func testUnresolvedSourcesAndNegativeFeeAreRejected() throws {
        var tx = try transaction()
        tx.inputs[0].sourceOutput = nil
        XCTAssertThrowsError(try SpendingAuthorizationReview(transaction: tx, request: request()))
        tx = try transaction()
        tx.outputs[1].satoshis = 401
        XCTAssertThrowsError(try SpendingAuthorizationReview(transaction: tx, request: request()))
    }

    func testRepeatedInputCannotReduceSpend() throws {
        var tx = try transaction()
        tx.inputs.append(tx.inputs[0])
        XCTAssertThrowsError(try SpendingAuthorizationReview(transaction: tx, request: request()))
    }

    private func request(inputs: [WalletCreateActionInput]? = nil) throws -> WalletCreateActionRequest {
        try WalletCreateActionRequest(description: "Send funds", inputs: inputs, outputs: [
            WalletCreateActionOutput(lockingScript: [0x51], satoshis: 600, outputDescription: "Recipient")
        ])
    }

    private func transaction() throws -> Transaction {
        Transaction(inputs: [TransactionInput(
            previousOutput: try Outpoint(String(repeating: "01", count: 32) + ".0"),
            unlockingScript: try Script(bytes: [], maximumByteCount: 100),
            sourceOutput: TransactionOutput(satoshis: 1000, lockingScript: try Script(bytes: [0x51], maximumByteCount: 100))
        )], outputs: [
            TransactionOutput(satoshis: 600, lockingScript: try Script(bytes: [0x51], maximumByteCount: 100)),
            TransactionOutput(satoshis: 390, lockingScript: try Script(bytes: [0x52], maximumByteCount: 100))
        ])
    }
}
