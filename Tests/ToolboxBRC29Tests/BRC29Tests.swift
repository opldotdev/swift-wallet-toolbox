import XCTest
@testable import ToolboxBRC29

/// The derivation constants.
///
/// These are checked because they are not negotiable: an address derived under any other protocol
/// string is a different address, and money sent to it is gone. The values match the TypeScript
/// and Go implementations character for character.
final class BRC29Tests: XCTestCase {

    func test_theProtocolIdentifierMatchesTheOtherImplementations() {
        XCTAssertEqual(BRC29.protocolID, "3241645161d8")
        XCTAssertEqual(BRC29.securityLevel, 2)
    }

    func test_theKeyIdentifierJoinsPrefixAndSuffixWithOneSpace() {
        XCTAssertEqual(BRC29.keyID(prefix: "abc", suffix: "def"), "abc def")
    }

    func test_theInvoiceNumberCarriesLevelProtocolAndKey() {
        XCTAssertEqual(
            BRC29.invoiceNumber(prefix: "abc", suffix: "def"),
            "2-3241645161d8-abc def"
        )
    }
}
