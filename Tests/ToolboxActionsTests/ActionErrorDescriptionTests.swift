import XCTest
@testable import ToolboxActions

/// Building and signing failures read as one short sentence; the detail stays for the log.
final class ActionErrorDescriptionTests: XCTestCase {

    func test_descriptionsAreShortAndKeepTheNumbers() {
        XCTAssertEqual(
            ActionError.insufficientFunds(required: 1_000, available: 400).localizedDescription,
            "Not enough funds: this needs 1000 satoshis and 400 are available."
        )
        XCTAssertEqual(
            ActionError.feeTooHigh(paid: 900, maximum: 500).localizedDescription,
            "The fee of 900 satoshis is above the 500-satoshi limit, so nothing was signed."
        )
    }

    func test_anUnusableInputGivesItsReasonOnOneLine() {
        let text = ActionError.unusableInput("missing\nsource   transaction").localizedDescription
        XCTAssertEqual(text, "One of the coins chosen for this transaction can't be used: missing source transaction.")
    }

    func test_theDetailStaysInTheLogText() {
        let detail = String(reflecting: ActionError.storageAlteredOutputs("output 2 changed"))
        XCTAssertTrue(detail.contains("output 2 changed"), detail)
    }
}
