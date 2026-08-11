import XCTest
import BSVWallet
@testable import ToolboxActions

/// The check that stops a storage operator redirecting money.
///
/// Storage is remote and run by somebody else. It returns the action it funded, including the
/// outputs it claims we asked for. If the wallet signs those without comparing them to the real
/// request, an operator can change where the money goes and have the wallet authorise it.
final class OutputVerificationTests: XCTestCase {

    private func output(satoshis: UInt64, script: [UInt8] = [0x76, 0xa9],
                        description: String = "payment") throws -> WalletCreateActionOutput {
        try WalletCreateActionOutput(
            lockingScript: script, satoshis: satoshis, outputDescription: description
        )
    }

    func test_identicalOutputsPass() throws {
        let requested = [try output(satoshis: 1_000), try output(satoshis: 2_000)]

        XCTAssertNoThrow(try OutputVerification.verify(requested: requested, returned: requested))
    }

    func test_anAlteredLockingScriptIsRefused() throws {
        let requested = [try output(satoshis: 1_000, script: [0x76, 0xa9, 0x01])]
        let returned = [try output(satoshis: 1_000, script: [0x76, 0xa9, 0x02])]

        XCTAssertThrowsError(try OutputVerification.verify(requested: requested, returned: returned)) {
            XCTAssertEqual($0 as? ActionError, .storageAlteredOutputs("storage altered output 0"))
        }
    }

    func test_anAlteredAmountIsRefused() throws {
        let requested = [try output(satoshis: 1_000)]
        let returned = [try output(satoshis: 999)]

        XCTAssertThrowsError(try OutputVerification.verify(requested: requested, returned: returned))
    }

    /// An added output is as much a change as an altered one. Comparing sets, or only the outputs
    /// we know about, would let a whole extra payment through.
    func test_anExtraOutputIsRefused() throws {
        let requested = [try output(satoshis: 1_000)]
        let returned = [try output(satoshis: 1_000), try output(satoshis: 5_000, description: "theirs")]

        XCTAssertThrowsError(try OutputVerification.verify(requested: requested, returned: returned))
    }

    func test_aMissingOutputIsRefused() throws {
        let requested = [try output(satoshis: 1_000), try output(satoshis: 2_000)]
        let returned = [try output(satoshis: 1_000)]

        XCTAssertThrowsError(try OutputVerification.verify(requested: requested, returned: returned))
    }

    /// Same outputs, different order, is a different transaction. Two payees swapped is exactly
    /// the attack this check exists to stop.
    func test_reorderedOutputsAreRefused() throws {
        let first = try output(satoshis: 1_000, description: "to Ana")
        let second = try output(satoshis: 2_000, description: "to Bo")

        XCTAssertThrowsError(
            try OutputVerification.verify(requested: [first, second], returned: [second, first])
        )
    }

    func test_noOutputsIsNotAnError() throws {
        XCTAssertNoThrow(try OutputVerification.verify(requested: [], returned: []))
    }
}
