import Foundation
import XCTest
@testable import ToolboxWallet

/// The wallet's own errors read as one short sentence for a person.
final class WalletErrorDescriptionTests: XCTestCase {

    func test_walletErrorDescriptions() {
        XCTAssertEqual(
            WalletError.paymailDeliveryFailed(txid: "ab").localizedDescription,
            "The payment was sent on chain, but the recipient's paymail provider could not be told about it."
        )
        XCTAssertEqual(
            WalletError.chainHeaderHeightMismatch(requested: 10, returned: 11).localizedDescription,
            "The chain service answered with block 11 instead of block 10."
        )
        XCTAssertTrue(String(reflecting: WalletError.broadcastFailed(txid: "abcd")).contains("abcd"))
    }

    func test_paymentErrorDescriptions() {
        XCTAssertEqual(
            BRC29PaymentError.outputNotUniquelyIdentified(matches: 2).localizedDescription,
            "The payment output appears 2 times in the transaction instead of once, so nothing was sent."
        )
        XCTAssertEqual(
            WalletActionLifecycleError.pendingActionLimit.localizedDescription,
            "Too many actions are waiting to be signed. Finish or abort one first."
        )
    }
}
