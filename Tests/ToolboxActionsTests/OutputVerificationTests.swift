import XCTest
import BSVWallet
import ToolboxStorage
@testable import ToolboxActions

/// The two checks that stop a storage operator redirecting money.
///
/// An earlier version of this file tested only exact equality between requested and returned
/// outputs. That was wrong twice over: it rejected every ordinary payment, because storage appends
/// change after the caller's outputs; and it left the real attack open, which is to leave the
/// requested outputs untouched and simply *add* one, funded by shrinking the change.
final class OutputVerificationTests: XCTestCase {

    private func requested(
        satoshis: UInt64, script: [UInt8] = [0x76, 0xa9]
    ) throws -> WalletCreateActionOutput {
        try WalletCreateActionOutput(
            lockingScript: script, satoshis: satoshis, outputDescription: "payment"
        )
    }

    private func echoed(
        _ output: WalletCreateActionOutput, vout: UInt32 = 0
    ) -> StorageActionOutput {
        StorageActionOutput(
            vout: vout, satoshis: output.satoshis, lockingScript: output.lockingScript,
            providedBy: .you, purpose: nil, derivationSuffix: nil
        )
    }

    private func change(satoshis: UInt64, vout: UInt32) -> StorageActionOutput {
        StorageActionOutput(
            vout: vout, satoshis: satoshis, lockingScript: [0xaa],
            providedBy: .storage, purpose: .change, derivationSuffix: "Su=="
        )
    }

    private func commission(
        satoshis: UInt64, vout: UInt32, purpose: StorageActionOutput.Purpose = .storageCommission
    ) -> StorageActionOutput {
        StorageActionOutput(
            vout: vout, satoshis: satoshis, lockingScript: [0xbb],
            providedBy: .storage, purpose: purpose, derivationSuffix: nil
        )
    }

    // MARK: - Ordinary payments

    /// The case the previous version rejected. Nearly every real payment looks like this.
    func test_arequestedOutputFollowedByChangeIsAccepted() throws {
        let payment = try requested(satoshis: 1_000)

        XCTAssertNoThrow(try OutputVerification.verify(
            requested: [payment],
            returned: [echoed(payment), change(satoshis: 3_900, vout: 1)]
        ))
    }

    func test_severalChangeOutputsAreAccepted() throws {
        let payment = try requested(satoshis: 1_000)

        XCTAssertNoThrow(try OutputVerification.verify(
            requested: [payment],
            returned: [
                echoed(payment), change(satoshis: 2_000, vout: 1),
                change(satoshis: 1_900, vout: 2),
            ]
        ))
    }

    func test_aBoundedCommissionIsAccepted() throws {
        let payment = try requested(satoshis: 1_000)

        XCTAssertNoThrow(try OutputVerification.verify(
            requested: [payment],
            returned: [
                echoed(payment), commission(satoshis: 500, vout: 1),
                change(satoshis: 3_400, vout: 2),
            ]
        ))
    }

    /// An older store labels the same thing differently. Refusing that spelling would fail closed
    /// on an honest server.
    func test_theOlderCommissionLabelIsAccepted() throws {
        let payment = try requested(satoshis: 1_000)

        XCTAssertNoThrow(try OutputVerification.verify(
            requested: [payment],
            returned: [
                echoed(payment), commission(satoshis: 500, vout: 1, purpose: .serviceCharge),
            ]
        ))
    }

    func test_exactlyTheRequestedOutputsAreAccepted() throws {
        let payment = try requested(satoshis: 1_000)

        XCTAssertNoThrow(
            try OutputVerification.verify(requested: [payment], returned: [echoed(payment)])
        )
    }

    // MARK: - The first check: the caller's outputs

    func test_analteredScriptIsRefused() throws {
        let payment = try requested(satoshis: 1_000, script: [0x76, 0xa9, 0x01])
        let tampered = try requested(satoshis: 1_000, script: [0x76, 0xa9, 0x02])

        XCTAssertThrowsError(
            try OutputVerification.verify(requested: [payment], returned: [echoed(tampered)])
        ) {
            XCTAssertEqual($0 as? ActionError,
                           .storageAlteredOutputs("storage altered output 0"))
        }
    }

    func test_analteredAmountIsRefused() throws {
        let payment = try requested(satoshis: 1_000)
        let tampered = try requested(satoshis: 999)

        XCTAssertThrowsError(
            try OutputVerification.verify(requested: [payment], returned: [echoed(tampered)])
        )
    }

    /// Two payees swapped is a different transaction, so position is part of the check.
    func test_reorderedOutputsAreRefused() throws {
        let first = try requested(satoshis: 1_000, script: [0x11])
        let second = try requested(satoshis: 2_000, script: [0x22])

        XCTAssertThrowsError(try OutputVerification.verify(
            requested: [first, second],
            returned: [echoed(second, vout: 0), echoed(first, vout: 1)]
        ))
    }

    func test_amissingOutputIsRefused() throws {
        let first = try requested(satoshis: 1_000)
        let second = try requested(satoshis: 2_000)

        XCTAssertThrowsError(
            try OutputVerification.verify(requested: [first, second], returned: [echoed(first)])
        )
    }

    func test_requestedOutputReclassifiedAsStorageChangeIsRefused() throws {
        let payment = try requested(satoshis: 1_000)
        let reclassified = StorageActionOutput(
            vout: 0,
            satoshis: payment.satoshis,
            lockingScript: payment.lockingScript,
            providedBy: .storage,
            purpose: .change,
            derivationSuffix: "Su=="
        )

        XCTAssertThrowsError(try OutputVerification.verify(
            requested: [payment], returned: [reclassified]
        )) {
            XCTAssertEqual(
                $0 as? ActionError,
                .storageAlteredOutputs("storage altered output 0")
            )
        }
    }

    // MARK: - The second check: what storage added

    /// The attack the first check does not catch. Requested outputs untouched, and an extra one
    /// paying somebody else funded out of the change.
    func test_anInjectedOutputIsRefused() throws {
        let payment = try requested(satoshis: 1_000)
        let injected = StorageActionOutput(
            vout: 1, satoshis: 9_000, lockingScript: [0xde, 0xad],
            providedBy: .storage, purpose: nil, derivationSuffix: nil
        )

        XCTAssertThrowsError(try OutputVerification.verify(
            requested: [payment], returned: [echoed(payment), injected]
        )) {
            guard case .storageAlteredOutputs(let reason) = ($0 as? ActionError) else {
                return XCTFail("expected storageAlteredOutputs")
            }
            XCTAssertTrue(reason.contains("neither change nor commission"))
        }
    }

    /// Without a ceiling, "commission" is an unlimited payment to the operator with a respectable
    /// name.
    func test_anOversizedCommissionIsRefused() throws {
        let payment = try requested(satoshis: 1_000)

        XCTAssertThrowsError(try OutputVerification.verify(
            requested: [payment],
            returned: [
                echoed(payment),
                commission(satoshis: OutputVerification.maximumCommission + 1, vout: 1),
            ]
        ))
    }

    /// One bounded commission is allowed; several bounded ones together are not.
    func test_asecondCommissionIsRefused() throws {
        let payment = try requested(satoshis: 1_000)

        XCTAssertThrowsError(try OutputVerification.verify(
            requested: [payment],
            returned: [
                echoed(payment), commission(satoshis: 100, vout: 1),
                commission(satoshis: 100, vout: 2),
            ]
        ))
    }

    /// An output claiming to be change but not provided by storage is not change.
    func test_changeNotProvidedByStorageIsRefused() throws {
        let payment = try requested(satoshis: 1_000)
        let pretend = StorageActionOutput(
            vout: 1, satoshis: 9_000, lockingScript: [0xde, 0xad],
            providedBy: .you, purpose: .change, derivationSuffix: "Su=="
        )

        XCTAssertThrowsError(try OutputVerification.verify(
            requested: [payment], returned: [echoed(payment), pretend]
        ))
    }

    func test_noOutputsIsNotAnError() throws {
        XCTAssertNoThrow(try OutputVerification.verify(requested: [], returned: []))
    }
}
