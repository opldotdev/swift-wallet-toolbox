import BSVScript
import BSVTransaction
import BSVWallet
import XCTest
@testable import ToolboxPermissions

final class SpendingReviewTests: XCTestCase {
    func testStorageCommissionIsIncludedInActualWalletDebit() throws {
        let outpoint = try Outpoint(String(repeating: "08", count: 32) + ".0")
        let request = try WalletCreateActionRequest(description: "Pay recipient", outputs: [
            .init(lockingScript: [0x51], satoshis: 90, outputDescription: "Recipient")
        ])
        let transaction = try Transaction(inputs: [.init(previousOutput: outpoint, unlockingScript: script())], outputs: [
            .init(satoshis: 90, lockingScript: script()), .init(satoshis: 4, lockingScript: script(0x52))
        ])
        let review = try SpendingReview(request: request, transaction: transaction, sourceOutputs: [
            outpoint: .init(satoshis: 100, lockingScript: script())
        ], storageCommissionSatoshis: 4)
        XCTAssertEqual(review.feeSatoshis, 6)
        XCTAssertEqual(review.storageCommissionSatoshis, 4)
        XCTAssertEqual(review.walletSpendSatoshis, 100)
    }

    private func script(_ byte: UInt8 = 0x51) throws -> Script {
        try Script(bytes: [byte], maximumByteCount: 100)
    }

    func testNetSpendIncludesFeeAndSubtractsOnlyCallerInputs() throws {
        let caller = try Outpoint(String(repeating: "01", count: 32) + ".0")
        let wallet = try Outpoint(String(repeating: "02", count: 32) + ".0")
        let request = try WalletCreateActionRequest(
            description: "Pay recipient",
            inputs: [.init(outpoint: caller, inputDescription: "Caller funds", unlockingScript: [0x51])],
            outputs: [.init(lockingScript: [0x51], satoshis: 700, outputDescription: "Recipient")]
        )
        let tx = try Transaction(inputs: [
            .init(previousOutput: caller, unlockingScript: script()),
            .init(previousOutput: wallet, unlockingScript: script())
        ], outputs: [
            .init(satoshis: 700, lockingScript: script()),
            .init(satoshis: 790, lockingScript: script(0x52))
        ])
        let review = try SpendingReview(request: request, transaction: tx, sourceOutputs: [
            caller: .init(satoshis: 500, lockingScript: script()),
            wallet: .init(satoshis: 1_000, lockingScript: script())
        ])
        XCTAssertEqual(review.feeSatoshis, 10)
        XCTAssertEqual(review.walletSpendSatoshis, 210)
        XCTAssertEqual(review.callerInputSatoshis, 500)
    }

    func testRejectsSubstitutedOrMissingDuplicateOutputs() throws {
        let output = try WalletCreateActionOutput(lockingScript: [0x51], satoshis: 1, outputDescription: "Output")
        for outputs in [[output], [output, output]] {
            let request = try WalletCreateActionRequest(description: "Create outputs", outputs: outputs)
            let actualScript: UInt8 = outputs.count == 1 ? 0x52 : 0x51
            let tx = try Transaction(outputs: [.init(satoshis: 1, lockingScript: script(actualScript))])
            XCTAssertThrowsError(try SpendingReview(request: request, transaction: tx, sourceOutputs: [:])) {
                XCTAssertEqual($0 as? SpendingReview.ReviewError, .missingRequestedOutput)
            }
        }
    }

    func testRejectsMissingFundingDataAndDuplicateInputs() throws {
        let outpoint = try Outpoint(String(repeating: "03", count: 32) + ".0")
        let input = try TransactionInput(previousOutput: outpoint, unlockingScript: script())
        let request = try WalletCreateActionRequest(description: "Funding data")
        XCTAssertThrowsError(try SpendingReview(request: request, transaction: .init(inputs: [input]), sourceOutputs: [:])) {
            XCTAssertEqual($0 as? SpendingReview.ReviewError, .missingSourceOutput)
        }
        XCTAssertThrowsError(try SpendingReview(request: request, transaction: .init(inputs: [input, input]), sourceOutputs: [:])) {
            XCTAssertEqual($0 as? SpendingReview.ReviewError, .duplicateInput)
        }
    }

    func testCallerSurplusDoesNotBecomeWalletSpending() throws {
        let caller = try Outpoint(String(repeating: "04", count: 32) + ".0")
        let request = try WalletCreateActionRequest(
            description: "Deposit surplus",
            inputs: [.init(outpoint: caller, inputDescription: "Caller funds", unlockingScript: [0x51])],
            outputs: [.init(lockingScript: [0x51], satoshis: 100, outputDescription: "Recipient")]
        )
        let tx = try Transaction(inputs: [.init(previousOutput: caller, unlockingScript: script())], outputs: [
            .init(satoshis: 100, lockingScript: script()),
            .init(satoshis: 890, lockingScript: script(0x52))
        ])
        let review = try SpendingReview(request: request, transaction: tx, sourceOutputs: [
            caller: .init(satoshis: 1_000, lockingScript: script())
        ])
        XCTAssertEqual(review.feeSatoshis, 10)
        XCTAssertEqual(review.walletSpendSatoshis, 0)
    }

    func testRejectsRequestedInputAbsentFromPreparedTransaction() throws {
        let caller = try Outpoint(String(repeating: "05", count: 32) + ".0")
        let request = try WalletCreateActionRequest(description: "Missing caller input", inputs: [
            .init(outpoint: caller, inputDescription: "Caller funds", unlockingScript: [0x51])
        ])
        XCTAssertThrowsError(try SpendingReview(request: request, transaction: .init(), sourceOutputs: [:])) {
            XCTAssertEqual($0 as? SpendingReview.ReviewError, .missingRequestedInput)
        }
    }

    func testRejectsOutputsExceedingFunding() throws {
        let request = try WalletCreateActionRequest(description: "Invalid funding")
        let tx = try Transaction(outputs: [.init(satoshis: 1, lockingScript: script())])
        XCTAssertThrowsError(try SpendingReview(request: request, transaction: tx, sourceOutputs: [:])) {
            XCTAssertEqual($0 as? SpendingReview.ReviewError, .outputsExceedInputs)
        }
    }

    func testResolvesFundingAmountsFromAtomicBEEF() throws {
        let transactionLimits = try TransactionLimits(
            maximumTransactionByteCount: 100_000, maximumInputCount: 100,
            maximumOutputCount: 100, maximumScriptByteCount: 10_000
        )
        let beefLimits = try BEEFLimits(
            maximumByteCount: 1_000_000, maximumMerklePathCount: 100,
            maximumTransactionCount: 1_000, transactionLimits: transactionLimits,
            merklePathLimits: .init(maximumByteCount: 100_000, maximumLeavesPerLevel: 100, maximumTotalLeaves: 1_000)
        )
        let parent = try Transaction(outputs: [.init(satoshis: 1_000, lockingScript: script())])
        let parentID = try parent.transactionID(limits: transactionLimits)
        let outpoint = Outpoint(transactionID: parentID, outputIndex: 0)
        let tx = try Transaction(inputs: [.init(previousOutput: outpoint, unlockingScript: script())], outputs: [
            .init(satoshis: 700, lockingScript: script()),
            .init(satoshis: 290, lockingScript: script(0x52))
        ])
        let beef = try BEEF(merklePaths: [], transactions: [.raw(parent), .raw(tx)], limits: beefLimits)
        let atomic = try AtomicBEEF(
            subjectTransactionID: tx.transactionID(limits: transactionLimits),
            beef: beef, limits: beefLimits
        )
        let request = try WalletCreateActionRequest(description: "Prepared payment", outputs: [
            .init(lockingScript: [0x51], satoshis: 700, outputDescription: "Recipient")
        ])
        let review = try SpendingReview(request: request, prepared: atomic, limits: transactionLimits)
        XCTAssertEqual(review.feeSatoshis, 10)
        XCTAssertEqual(review.walletSpendSatoshis, 710)
    }
}
