import XCTest
import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet
@testable import ToolboxPermissions

final class PermissionClassifierSurfaceTests: XCTestCase {
    private let originator = "https://App.Example:443/path"

    func testEveryBRC100MethodHasAnExplicitClassification() throws {
        let classifier = try makeClassifier()
        let requests = try makeAllRequests()
        XCTAssertEqual(requests.map(\.call.rawValue).sorted(), WalletCall.allCases.map(\.rawValue).sorted())
        XCTAssertEqual(requests.count, 28)

        let bootstrap: Set<UInt8> = [23, 24, 28]
        let passThrough: Set<UInt8> = [2, 3, 25, 26, 27]
        for request in requests {
            let decision = classifier.classify(request, originator: originator).decision
            if bootstrap.contains(request.call.rawValue) {
                XCTAssertEqual(decision, .bootstrapNoPrompt, "call \(request.call)")
            } else if passThrough.contains(request.call.rawValue) {
                XCTAssertEqual(decision, .authenticatedPassThrough, "call \(request.call)")
            } else if case .authorizationRequired(let plan) = decision {
                XCTAssertEqual(
                    Set(plan.requirements.map(\.usage)),
                    expectedUsages(for: request.call),
                    "call \(request.call)"
                )
                XCTAssertEqual(plan.spending != nil, request.call == .createAction)
            } else {
                XCTFail("call \(request.call) was not protected: \(decision)")
            }
        }
    }

    func testBootstrapMethodsDoNotRequireAnOriginator() throws {
        let classifier = try makeClassifier()
        let requests: [WalletRequest] = [
            .keyQuery(.isAuthenticated(.init())),
            .keyQuery(.waitForAuthentication(.init())),
            .keyQuery(.getVersion(.init())),
        ]
        for request in requests {
            XCTAssertEqual(classifier.classify(request, originator: "").decision, .bootstrapNoPrompt)
        }
    }

    func testAuthenticatedPassThroughStillRequiresAnOriginator() throws {
        let classifier = try makeClassifier()
        let request = WalletRequest.keyQuery(.getNetwork(.init()))
        XCTAssertEqual(classifier.classify(request, originator: "").decision, .denied(.missingOriginator))
    }

    private func makeClassifier() throws -> WalletPermissionClassifier {
        try WalletPermissionClassifier(policy: .init(adminOriginator: "wallet.example"))
    }

    private func makeAllRequests() throws -> [WalletRequest] {
        let protocolID = try WalletProtocolID(securityLevel: .everyApp, name: "sample access")
        let keyID = try WalletKeyID("key")
        let subject = try testKey(2)
        let certifier = try testKey(3)
        let verifier = try testKey(4)
        let reference = try WalletBase64Data([1])
        let outpoint = try testOutpoint()
        let signature = try ECDSASignature(derBytes: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
        let field = try CertificateFieldName("name")
        let type = try CertificateTypeID(Array(repeating: 7, count: 32))
        let serial = try CertificateSerialNumber(Array(repeating: 8, count: 32))
        let certificate = try Certificate(
            type: type,
            serialNumber: serial,
            subject: subject,
            certifier: certifier,
            revocationOutpoint: outpoint,
            fields: [field: try CertificateCiphertext([9])]
        )
        let actionOutput = try WalletCreateActionOutput(
            lockingScript: [0x51],
            satoshis: 12,
            outputDescription: "send sats",
            basket: "sample basket"
        )
        let insertion = try WalletBasketInsertion(basket: "sample basket")
        let internalizedOutput = WalletInternalizeOutput(
            outputIndex: 0,
            remittance: .basketInsertion(insertion)
        )

        return [
            .action(.createAction(try .init(
                description: "create action",
                outputs: [actionOutput],
                labels: ["orders"]
            ))),
            .action(.signAction(try .init(reference: reference, spends: [:]))),
            .action(.abortAction(.init(reference: reference))),
            .action(.listActions(try .init(labels: ["orders"]))),
            .action(.internalizeAction(try .init(
                transaction: testAtomicBEEF(),
                description: "internalize",
                labels: ["orders"],
                outputs: [internalizedOutput]
            ))),
            .action(.listOutputs(try .init(basket: "sample basket"))),
            .action(.relinquishOutput(try .init(basket: "sample basket", output: outpoint))),
            .keyQuery(.getPublicKey(.init(selection: .derived(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .self,
                forSelf: false
            )))),
            .certificate(.revealCounterpartyKeyLinkage(.init(counterparty: subject, verifier: verifier))),
            .certificate(.revealSpecificKeyLinkage(try .init(
                counterparty: .publicKey(subject),
                verifier: verifier,
                protocolID: protocolID,
                keyID: keyID
            ))),
            .keyQuery(.encrypt(.init(protocolID: protocolID, keyID: keyID, plaintext: [1]))),
            .keyQuery(.decrypt(.init(protocolID: protocolID, keyID: keyID, ciphertext: [1]))),
            .keyQuery(.createHMAC(.init(protocolID: protocolID, keyID: keyID, data: [1]))),
            .keyQuery(.verifyHMAC(.init(
                protocolID: protocolID,
                keyID: keyID,
                data: [1],
                hmac: try WalletHMAC(bytes: Array(repeating: 0, count: 32))
            ))),
            .keyQuery(.createSignature(.init(
                protocolID: protocolID,
                keyID: keyID,
                payload: .data([1])
            ))),
            .keyQuery(.verifySignature(.init(
                protocolID: protocolID,
                keyID: keyID,
                payload: .data([1]),
                signature: signature
            ))),
            .certificate(.acquireCertificate(try .init(
                type: type,
                certifier: certifier,
                fields: [field: "Alice"],
                acquisition: .issuance(try .init(certifierURL: "https://certifier.example"))
            ))),
            .certificate(.listCertificates(try .init(certifiers: [certifier], types: [type]))),
            .certificate(.proveCertificate(try .init(
                certificate: certificate,
                fieldsToReveal: [field],
                verifier: verifier
            ))),
            .certificate(.relinquishCertificate(.init(
                type: type,
                serialNumber: serial,
                certifier: certifier
            ))),
            .certificate(.discoverByIdentityKey(.init(identityKey: subject))),
            .certificate(.discoverByAttributes(try .init(attributes: [field: "Alice"]))),
            .keyQuery(.isAuthenticated(.init())),
            .keyQuery(.waitForAuthentication(.init())),
            .keyQuery(.getHeight(.init())),
            .keyQuery(.getHeaderForHeight(.init(height: 42))),
            .keyQuery(.getNetwork(.init())),
            .keyQuery(.getVersion(.init())),
        ]
    }

    private func expectedUsages(for call: WalletCall) -> Set<PermissionUsage> {
        switch call {
        case .createAction, .internalizeAction:
            return [.basketInsertion, .actionLabelApplication]
        case .listActions: return [.actionLabelListing]
        case .listOutputs: return [.basketListing]
        case .relinquishOutput: return [.basketRemoval]
        case .getPublicKey: return [.publicKey]
        case .revealCounterpartyKeyLinkage, .revealSpecificKeyLinkage:
            return [.linkageRevelation]
        case .encrypt: return [.encrypt]
        case .decrypt: return [.decrypt]
        case .createHMAC, .verifyHMAC: return [.hmac]
        case .createSignature, .verifySignature: return [.signing]
        case .acquireCertificate: return [.certificateAcquisition]
        case .listCertificates: return [.certificateListing]
        case .proveCertificate: return [.certificateDisclosure]
        case .relinquishCertificate: return [.certificateRelinquishment]
        case .discoverByIdentityKey, .discoverByAttributes: return [.identityResolution]
        case .signAction, .abortAction, .isAuthenticated, .waitForAuthentication,
             .getHeight, .getHeaderForHeight, .getNetwork, .getVersion:
            return []
        }
    }
}

func testPrivateKey(_ scalar: UInt8) throws -> PrivateKey {
    try PrivateKey(Array(repeating: 0, count: 31) + [scalar])
}

func testKey(_ scalar: UInt8) throws -> PublicKey {
    try testPrivateKey(scalar).publicKey
}

func testTransactionID() throws -> TransactionID {
    try TransactionID(wireBytes: Array(repeating: 0x11, count: 32))
}

func testOutpoint() throws -> Outpoint {
    Outpoint(transactionID: try testTransactionID(), outputIndex: 0)
}

func testAtomicBEEF() throws -> AtomicBEEF {
    let transactionID = try testTransactionID()
    let limits = try testBEEFLimits()
    let beef = try BEEF(
        version: .v2,
        merklePaths: [],
        transactions: [.transactionID(transactionID)],
        limits: limits
    )
    return try AtomicBEEF(
        subjectTransactionID: transactionID,
        beef: beef,
        limits: limits
    )
}

private func testBEEFLimits() throws -> BEEFLimits {
    try BEEFLimits(
        maximumByteCount: 1_000_000,
        maximumMerklePathCount: 100,
        maximumTransactionCount: 1_000,
        transactionLimits: try TransactionLimits(
            maximumTransactionByteCount: 100_000,
            maximumInputCount: 100,
            maximumOutputCount: 100,
            maximumScriptByteCount: 10_000
        ),
        merklePathLimits: try MerklePathLimits(
            maximumByteCount: 100_000,
            maximumLeavesPerLevel: 100,
            maximumTotalLeaves: 1_000
        )
    )
}
