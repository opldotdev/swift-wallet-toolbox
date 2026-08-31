import XCTest
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxBRC29
import ToolboxStorage
@testable import ToolboxActions

final class BRC116ActionSignerTests: XCTestCase {
    private let brc29TXID =
        "8ac7230489e80000000000000000000000000000000000000000000000000001"
    private let tokenTXID =
        "8ac7230489e80000000000000000000000000000000000000000000000000002"
    private let otherTXID =
        "8ac7230489e80000000000000000000000000000000000000000000000000003"
    private let prefix = "Pr=="
    private let suffix = "Su=="

    private func key(_ byte: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [byte])
    }

    private func requestedOutput(
        satoshis: UInt64 = 1_000, script: [UInt8] = [0x51]
    ) throws -> WalletCreateActionOutput {
        try WalletCreateActionOutput(
            lockingScript: script,
            satoshis: satoshis,
            outputDescription: "payment"
        )
    }

    private func storageOutput(
        _ requested: WalletCreateActionOutput
    ) -> StorageActionOutput {
        StorageActionOutput(
            vout: 0,
            satoshis: requested.satoshis,
            lockingScript: requested.lockingScript,
            providedBy: .you,
            purpose: nil,
            derivationSuffix: nil
        )
    }

    private func brc29Input(
        identity: PrivateKey,
        sender: PublicKey,
        txid: String? = nil,
        satoshis: Int64 = 5_000,
        lockingScript: [UInt8]? = nil
    ) throws -> StorageActionInput {
        let spendingKey = try BRC29.receivingPrivateKey(
            recipient: identity,
            sender: sender,
            prefix: prefix,
            suffix: suffix
        )
        return StorageActionInput(
            sourceTXID: txid ?? brc29TXID,
            sourceVout: 0,
            sourceSatoshis: satoshis,
            sourceLockingScript: try lockingScript
                ?? BRC29.lockingScript(for: spendingKey.publicKey).bytes,
            unlockingScriptLength: 108,
            derivationPrefix: prefix,
            derivationSuffix: suffix
        )
    }

    private func funded(
        requested: [WalletCreateActionOutput],
        inputs: [StorageActionInput],
        returned: [StorageActionOutput]? = nil
    ) -> StorageCreateActionResult {
        StorageCreateActionResult(
            reference: "ref",
            version: 1,
            lockTime: 0,
            outputs: returned ?? requested.map(storageOutput),
            inputs: inputs,
            inputBEEF: nil,
            derivationPrefix: prefix
        )
    }

    private func tokenFixture(
        txid: String? = nil,
        vout: UInt32 = 4,
        satoshis: Int64 = 1
    ) async throws -> (
        input: StorageActionInput,
        declaration: ActionSigner.BRC116PermissionTokenSpend,
        signer: CountingSignatureWallet
    ) {
        let rootKey = try key(11)
        let protoWallet = ProtoWallet(rootKey: rootKey)
        let signer = CountingSignatureWallet(wallet: protoWallet)
        let protocolID = try WalletProtocolID.walletInternalAdmin(
            securityLevel: .everyAppAndCounterparty,
            name: "admin permission token encryption"
        )
        let script = try await PushDrop.lockingScript(
            fields: [[0xaa], [0xbb]],
            using: protoWallet,
            protocolID: protocolID,
            keyID: WalletKeyID("1"),
            counterparty: .self,
            lockPosition: .beforeCompatibility
        )
        let sourceTXID = txid ?? tokenTXID
        let input = StorageActionInput(
            sourceTXID: sourceTXID,
            sourceVout: vout,
            sourceSatoshis: satoshis,
            sourceLockingScript: script.bytes,
            unlockingScriptLength: 73,
            derivationPrefix: nil,
            derivationSuffix: nil
        )
        let declaration = ActionSigner.BRC116PermissionTokenSpend(
            outpoint: try Outpoint("\(sourceTXID).\(vout)"),
            satoshis: satoshis,
            lockingScript: script.bytes,
            signer: signer
        )
        return (input, declaration, signer)
    }

    private func copied(
        _ input: StorageActionInput,
        txid: String? = nil,
        satoshis: Int64? = nil,
        lockingScript: [UInt8]? = nil
    ) -> StorageActionInput {
        StorageActionInput(
            sourceTXID: txid ?? input.sourceTXID,
            sourceVout: input.sourceVout,
            sourceSatoshis: satoshis ?? input.sourceSatoshis,
            sourceLockingScript: lockingScript ?? input.sourceLockingScript,
            unlockingScriptLength: input.unlockingScriptLength,
            derivationPrefix: input.derivationPrefix,
            derivationSuffix: input.derivationSuffix,
            senderIdentityKey: input.senderIdentityKey
        )
    }

    func test_mixedInputsAreMatchedByOutpointAfterFundingReordersThem() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let token = try await tokenFixture()
        let requested = [try requestedOutput()]
        // The token is at vin 1, not an index supplied by the declaration.
        let action = funded(requested: requested, inputs: [
            try brc29Input(identity: identity, sender: sender),
            token.input,
        ])

        let signed = try await ActionSigner.signBRC116PermissionTokenAction(
            action,
            requested: requested,
            identityKey: identity,
            senderPublicKey: sender,
            permissionTokenSpends: [token.declaration],
            maximumFee: 10_000
        )

        XCTAssertEqual(signed.inputs.count, 2)
        XCTAssertTrue(signed.inputs.allSatisfy { !$0.unlockingScript.bytes.isEmpty })
        let tokenSignature = try XCTUnwrap(
            signed.inputs[1].unlockingScript.operations(
                maximumPushDataByteCount: 80
            ).first?.pushedData
        )
        XCTAssertEqual(tokenSignature.last, ForkIDSignatureHashType.all.rawValue)
        let signatureCount = await token.signer.signatureCount()
        XCTAssertEqual(signatureCount, 1)
    }

    func test_tokenOutpointScriptAndValueSubstitutionAreRefusedBeforeSigning() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let token = try await tokenFixture()
        let requested = [try requestedOutput(satoshis: 0)]
        let substitutions = [
            copied(token.input, txid: otherTXID),
            copied(token.input, lockingScript: [0x51]),
            copied(token.input, satoshis: token.input.sourceSatoshis + 1),
        ]

        for substituted in substitutions {
            do {
                _ = try await ActionSigner.signBRC116PermissionTokenAction(
                    funded(requested: requested, inputs: [substituted]),
                    requested: requested,
                    identityKey: identity,
                    senderPublicKey: sender,
                    permissionTokenSpends: [token.declaration],
                    maximumFee: 10_000
                )
                XCTFail("a substituted token source must be refused")
            } catch {
                XCTAssertTrue(error is ActionError)
            }
        }
        let signatureCount = await token.signer.signatureCount()
        XCTAssertEqual(signatureCount, 0)
    }

    func test_declaredTokenMustBePositiveAndValidPushDropBeforeSigning() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let requested = [try requestedOutput(satoshis: 0)]

        let token = try await tokenFixture()
        let malformedInput = copied(token.input, lockingScript: [0x51])
        let malformedDeclaration = ActionSigner.BRC116PermissionTokenSpend(
            outpoint: token.declaration.outpoint,
            satoshis: token.declaration.satoshis,
            lockingScript: [0x51],
            signer: token.signer
        )
        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(requested: requested, inputs: [malformedInput]),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [malformedDeclaration],
                maximumFee: 10_000
            )
            XCTFail("a malformed declared PushDrop lock must be refused")
        } catch {
            XCTAssertTrue(error is ActionError)
        }
        let malformedSignatureCount = await token.signer.signatureCount()
        XCTAssertEqual(malformedSignatureCount, 0)

        let zeroValueToken = try await tokenFixture(txid: otherTXID, satoshis: 0)
        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(requested: requested, inputs: [zeroValueToken.input]),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [zeroValueToken.declaration],
                maximumFee: 10_000
            )
            XCTFail("a zero-value PushDrop token must be refused")
        } catch {
            XCTAssertTrue(error is ActionError)
        }
        let zeroValueSignatureCount = await zeroValueToken.signer.signatureCount()
        XCTAssertEqual(zeroValueSignatureCount, 0)
    }

    func test_missingTokenDeclarationIsRefused() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let token = try await tokenFixture()
        let requested = [try requestedOutput(satoshis: 0)]

        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(requested: requested, inputs: [token.input]),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [],
                maximumFee: 10_000
            )
            XCTFail("an undeclared token input must be refused")
        } catch {
            XCTAssertTrue(error is ActionError)
        }
        let signatureCount = await token.signer.signatureCount()
        XCTAssertEqual(signatureCount, 0)
    }

    func test_duplicateTokenDeclarationsAreRefused() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let token = try await tokenFixture()
        let requested = [try requestedOutput(satoshis: 0)]

        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(requested: requested, inputs: [token.input]),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [token.declaration, token.declaration],
                maximumFee: 10_000
            )
            XCTFail("duplicate declarations must be refused")
        } catch {
            XCTAssertTrue(error is ActionError)
        }
        let signatureCount = await token.signer.signatureCount()
        XCTAssertEqual(signatureCount, 0)
    }

    func test_extraTokenDeclarationIsRefused() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let token = try await tokenFixture()
        let requested = [try requestedOutput()]

        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(
                    requested: requested,
                    inputs: [try brc29Input(identity: identity, sender: sender)]
                ),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [token.declaration],
                maximumFee: 10_000
            )
            XCTFail("a declaration absent from the funded inputs must be refused")
        } catch {
            XCTAssertTrue(error is ActionError)
        }
        let signatureCount = await token.signer.signatureCount()
        XCTAssertEqual(signatureCount, 0)
    }

    func test_duplicateFundedOutpointsAreRefused() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let token = try await tokenFixture()
        let requested = [try requestedOutput(satoshis: 0)]

        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(requested: requested, inputs: [token.input, token.input]),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [token.declaration],
                maximumFee: 10_000
            )
            XCTFail("duplicate funded outpoints must be refused")
        } catch {
            XCTAssertTrue(error is ActionError)
        }
        let signatureCount = await token.signer.signatureCount()
        XCTAssertEqual(signatureCount, 0)
    }

    func test_ordinaryBRC29OnlyActionStillSigns() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let requested = [try requestedOutput()]

        let signed = try await ActionSigner.signBRC116PermissionTokenAction(
            funded(
                requested: requested,
                inputs: [try brc29Input(identity: identity, sender: sender)]
            ),
            requested: requested,
            identityKey: identity,
            senderPublicKey: sender,
            permissionTokenSpends: [],
            maximumFee: 10_000
        )

        XCTAssertFalse(signed.inputs[0].unlockingScript.bytes.isEmpty)
    }

    func test_nonBRC29InputWithFakeDerivationIsRefused() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let requested = [try requestedOutput()]
        let fake = try brc29Input(
            identity: identity,
            sender: sender,
            lockingScript: [0x51]
        )

        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(requested: requested, inputs: [fake]),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [],
                maximumFee: 10_000
            )
            XCTFail("a non-BRC-29 script must not be accepted as an ordinary input")
        } catch {
            XCTAssertTrue(error is ActionError)
        }
    }

    func test_outputEchoRefusalHappensBeforeTokenKeyUse() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let token = try await tokenFixture()
        let requested = [try requestedOutput(satoshis: 0)]
        let altered = [storageOutput(try requestedOutput(satoshis: 0, script: [0x52]))]

        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(requested: requested, inputs: [token.input], returned: altered),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [token.declaration],
                maximumFee: 10_000
            )
            XCTFail("altered outputs must be refused")
        } catch {
            XCTAssertEqual(
                error as? ActionError,
                .storageAlteredOutputs("storage altered output 0")
            )
        }
        let signatureCount = await token.signer.signatureCount()
        XCTAssertEqual(signatureCount, 0)
    }

    func test_feeRefusalHappensBeforeTokenKeyUse() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let token = try await tokenFixture(satoshis: 1_000)
        let requested = [try requestedOutput(satoshis: 0)]

        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                funded(requested: requested, inputs: [token.input]),
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [token.declaration],
                maximumFee: 10
            )
            XCTFail("an excessive fee must be refused")
        } catch {
            XCTAssertEqual(error as? ActionError, .feeTooHigh(paid: 1_000, maximum: 10))
        }
        let signatureCount = await token.signer.signatureCount()
        XCTAssertEqual(signatureCount, 0)
    }

    func test_aggregateProjectionRefusesBeforeEitherTokenSignerRuns() async throws {
        let identity = try key(1)
        let sender = try key(2).publicKey
        let first = try await tokenFixture()
        let second = try await tokenFixture(txid: otherTXID)
        let requested = [try requestedOutput(satoshis: 0)]
        let action = funded(
            requested: requested,
            inputs: [first.input, second.input]
        )
        let generous = try TransactionLimits(
            maximumTransactionByteCount: 10_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )
        var oneTokenProjected = try ActionAssembler.assemble(
            action,
            requested: requested,
            changeKey: identity,
            limits: generous
        )
        oneTokenProjected.inputs[0].unlockingScript = try Script(
            bytes: [UInt8](
                repeating: 0,
                count: TransactionInput.pushDropUnlockingScriptByteCount
            ),
            maximumByteCount: 1_000
        )
        let oneTokenMaximum = try oneTokenProjected.serializedByteCount(limits: generous)
        var bothTokensProjected = oneTokenProjected
        bothTokensProjected.inputs[1].unlockingScript = try Script(
            bytes: [UInt8](
                repeating: 0,
                count: TransactionInput.pushDropUnlockingScriptByteCount
            ),
            maximumByteCount: 1_000
        )
        let bothTokensByteCount = try bothTokensProjected.serializedByteCount(limits: generous)
        let tight = try TransactionLimits(
            maximumTransactionByteCount: oneTokenMaximum,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )

        do {
            _ = try await ActionSigner.signBRC116PermissionTokenAction(
                action,
                requested: requested,
                identityKey: identity,
                senderPublicKey: sender,
                permissionTokenSpends: [first.declaration, second.declaration],
                maximumFee: 10_000,
                limits: tight
            )
            XCTFail("the completed two-token projection must exceed the one-token limit")
        } catch {
            XCTAssertEqual(
                error as? TransactionError,
                .transactionTooLarge(
                    actual: bothTokensByteCount,
                    maximum: oneTokenMaximum
                )
            )
        }

        let firstSignatureCount = await first.signer.signatureCount()
        let secondSignatureCount = await second.signer.signatureCount()
        XCTAssertEqual(firstSignatureCount, 0)
        XCTAssertEqual(secondSignatureCount, 0)
    }
}

private actor CountingSignatureWallet: WalletSignatureOperations {
    private let wallet: ProtoWallet
    private var count = 0

    init(wallet: ProtoWallet) {
        self.wallet = wallet
    }

    func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        count += 1
        return try await wallet.createSignature(request)
    }

    func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        try await wallet.verifySignature(request)
    }

    func signatureCount() -> Int {
        count
    }
}
