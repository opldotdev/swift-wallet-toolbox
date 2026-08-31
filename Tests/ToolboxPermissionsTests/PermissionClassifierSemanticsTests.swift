import Foundation
import XCTest
import BSVKeys
import BSVWallet
@testable import ToolboxPermissions

final class PermissionClassifierSemanticsTests: XCTestCase {
    private var originator: String { "HTTPS://Example.COM:443/app" }

    func testProtocolLevelsUseBRC43CounterpartySemantics() throws {
        let classifier = try makeClassifier()
        let key = try testKey(9)
        let cases: [(WalletSecurityLevel, PermissionDecision)] = [
            (.silent, .authenticatedPassThrough),
            (.everyApp, .authorizationRequired(.init(requirements: [
                .init(
                    scope: .protocolAccess(try .init(
                        originator: try CanonicalOriginator("example.com"),
                        privileged: false,
                        securityLevel: .application,
                        protocolName: "sample access",
                        counterparty: nil
                    )),
                    usage: .signing,
                    whenMissing: .promptUser
                ),
            ]))),
            (.everyAppAndCounterparty, .authorizationRequired(.init(requirements: [
                .init(
                    scope: .protocolAccess(try .init(
                        originator: try CanonicalOriginator("example.com"),
                        privileged: false,
                        securityLevel: .applicationAndCounterparty,
                        protocolName: "sample access",
                        counterparty: .init(publicKey: key)
                    )),
                    usage: .signing,
                    whenMissing: .promptUser
                ),
            ]))),
        ]

        for (level, expected) in cases {
            let request = WalletRequest.keyQuery(.createSignature(.init(
                protocolID: try .init(securityLevel: level, name: "Sample Access"),
                keyID: try .init("1"),
                counterparty: .publicKey(key),
                payload: .data([1])
            )))
            XCTAssertEqual(classifier.classify(request, originator: originator).decision, expected)
        }
    }

    func testSeekPermissionFalseProducesNoPromptMissingBehavior() throws {
        let classifier = try makeClassifier()
        let access = try WalletKeyAccess(seekPermission: false)
        let request = WalletRequest.keyQuery(.encrypt(.init(
            protocolID: try .init(securityLevel: .everyApp, name: "sample access"),
            keyID: try .init("1"),
            plaintext: [1],
            access: access
        )))
        let plan = try authorizationPlan(classifier.classify(request, originator: originator).decision)
        XCTAssertEqual(plan.requirements.map(\.whenMissing), [.denyWithoutPrompt])
    }

    func testIdentityDiscoveryDefaultsToNoPromptButCanOptIn() throws {
        let classifier = try makeClassifier()
        let key = try testKey(2)
        for explicit in [nil, false] as [Bool?] {
            let request = WalletRequest.certificate(.discoverByIdentityKey(.init(
                identityKey: key,
                seekPermission: explicit
            )))
            let plan = try authorizationPlan(classifier.classify(request, originator: originator).decision)
            XCTAssertEqual(plan.requirements.single?.whenMissing, .denyWithoutPrompt)
        }
        let optingIn = WalletRequest.certificate(.discoverByIdentityKey(.init(
            identityKey: key,
            seekPermission: true
        )))
        let plan = try authorizationPlan(classifier.classify(optingIn, originator: originator).decision)
        XCTAssertEqual(plan.requirements.single?.whenMissing, .promptUser)
    }

    func testLevelOneScopeIgnoresCounterpartyAndLevelTwoIncludesIt() throws {
        let origin = try CanonicalOriginator("example.com")
        let first = try testKey(2)
        let second = try testKey(3)
        let levelOneA = try ProtocolPermissionScope(originator: origin, privileged: false, securityLevel: .application, protocolName: "sample access", counterparty: .init(publicKey: first))
        let levelOneB = try ProtocolPermissionScope(originator: origin, privileged: false, securityLevel: .application, protocolName: "sample access", counterparty: .init(publicKey: second))
        XCTAssertEqual(levelOneA, levelOneB)
        XCTAssertNil(levelOneA.counterparty)
        XCTAssertNotEqual(
            try ProtocolPermissionScope(originator: origin, privileged: false, securityLevel: .applicationAndCounterparty, protocolName: "sample access", counterparty: .init(publicKey: first)),
            try ProtocolPermissionScope(originator: origin, privileged: false, securityLevel: .applicationAndCounterparty, protocolName: "sample access", counterparty: .init(publicKey: second))
        )
    }

    func testCertificateFieldSetIdentityIsOrderIndependentAndVerifierSpecific() throws {
        let origin = try CanonicalOriginator("example.com")
        let first = CertificatePermissionScope(
            originator: origin,
            privileged: false,
            certificateType: "type",
            verifier: .init(publicKey: try testKey(2)),
            fields: ["email", "name", "email"]
        )
        let reordered = CertificatePermissionScope(
            originator: origin,
            privileged: false,
            certificateType: "type",
            verifier: .init(publicKey: try testKey(2)),
            fields: ["name", "email"]
        )
        XCTAssertEqual(first, reordered)
        XCTAssertEqual(first.fields, ["email", "name"])
        XCTAssertNotEqual(first, .init(
            originator: origin,
            privileged: false,
            certificateType: "type",
            verifier: .init(publicKey: try testKey(3)),
            fields: ["name", "email"]
        ))
    }

    func testCertificateScopeDecodeRestoresExactSetCanonicalization() throws {
        let canonical = CertificatePermissionScope(
            originator: try .init("example.com"),
            privileged: false,
            certificateType: "type",
            verifier: .init(publicKey: try testKey(2)),
            fields: ["email", "name"]
        )
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(canonical)) as? [String: Any]
        )
        object["fields"] = ["name", "email", "name"]
        let decoded = try JSONDecoder().decode(
            CertificatePermissionScope.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
        XCTAssertEqual(decoded, canonical)
        XCTAssertEqual(decoded.fields, ["email", "name"])
    }

    func testProtocolScopeDecodeEnforcesLevelInvariants() throws {
        let counterparty = CanonicalCounterparty(publicKey: try testKey(2))
        let levelTwo = try ProtocolPermissionScope(
            originator: .init("example.com"),
            privileged: false,
            securityLevel: .applicationAndCounterparty,
            protocolName: "sample access",
            counterparty: counterparty
        )
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(levelTwo)) as? [String: Any]
        )
        object["securityLevel"] = 1
        let levelOne = try JSONDecoder().decode(
            ProtocolPermissionScope.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
        XCTAssertNil(levelOne.counterparty)

        object["securityLevel"] = 3
        XCTAssertThrowsError(try JSONDecoder().decode(
            ProtocolPermissionScope.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))

        object["securityLevel"] = 2
        object.removeValue(forKey: "counterparty")
        XCTAssertThrowsError(try JSONDecoder().decode(
            ProtocolPermissionScope.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))
    }

    func testAuthorizationPlanDecodePreservesRequirementDeduplication() throws {
        let scope = try ProtocolPermissionScope(
            originator: .init("example.com"),
            privileged: false,
            securityLevel: .application,
            protocolName: "sample access",
            counterparty: nil
        )
        let requirement = PermissionRequirement(
            scope: .protocolAccess(scope),
            usage: .encrypt,
            whenMissing: .promptUser
        )
        let plan = PermissionAuthorizationPlan(requirements: [requirement])
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(plan)) as? [String: Any]
        )
        let requirements = try XCTUnwrap(object["requirements"] as? [Any])
        object["requirements"] = requirements + requirements
        let decoded = try JSONDecoder().decode(
            PermissionAuthorizationPlan.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
        XCTAssertEqual(decoded, plan)
        XCTAssertEqual(decoded.requirements.count, 1)
    }

    func testBRC114ControlsAreExcludedButOtherActionTimeLabelsAreScoped() throws {
        let classifier = try makeClassifier()
        let request = WalletRequest.action(.listActions(try .init(labels: [
            "action time from 100",
            "orders",
            "action time to 200",
            "action time 150",
        ])))
        let plan = try authorizationPlan(classifier.classify(request, originator: originator).decision)
        let names = plan.requirements.compactMap { requirement -> String? in
            guard case .protocolAccess(let scope) = requirement.scope else { return nil }
            return scope.protocolName
        }
        XCTAssertEqual(names, ["action label orders", "action label action time 150"])
    }

    func testInvalidBRC114ControlsFailClosed() throws {
        let classifier = try makeClassifier()
        for labels in [
            ["action time from nope"],
            ["action time from 2", "action time to 2"],
            ["action time to 2", "action time to 3"],
        ] {
            let request = WalletRequest.action(.listActions(try .init(labels: labels)))
            guard case .denied(.invalidActionTimeLabel) = classifier.classify(request, originator: originator).decision else {
                return XCTFail("expected invalid time-label denial for \(labels)")
            }
        }
    }

    func testReservedAndUnsupportedNamespacesFailClosed() throws {
        let classifier = try makeClassifier()
        let outpoint = try testOutpoint()
        let basketCases: [(String, PermissionPolicyRejection)] = [
            ("default", .reservedBasket("default")),
            ("admin tokens", .reservedBasket("admin tokens")),
            ("p btms tokens", .unsupportedPermissionScheme(kind: "basket", scheme: "btms")),
        ]
        for (basket, expected) in basketCases {
            let request = WalletRequest.action(.relinquishOutput(try .init(basket: basket, output: outpoint)))
            XCTAssertEqual(classifier.classify(request, originator: originator).decision, .denied(expected))
        }

        let adminProtocol = try WalletProtocolID.walletInternalAdmin(
            securityLevel: .silent,
            name: "admin secret"
        )
        let adminRequest = WalletRequest.keyQuery(.encrypt(.init(
            protocolID: adminProtocol,
            keyID: try .init("1"),
            plaintext: [1]
        )))
        XCTAssertEqual(
            classifier.classify(adminRequest, originator: originator).decision,
            .denied(.reservedProtocol("admin secret"))
        )

        let pProtocol = try WalletProtocolID(securityLevel: .silent, name: "p btms private")
        let pRequest = WalletRequest.keyQuery(.encrypt(.init(
            protocolID: pProtocol,
            keyID: try .init("1"),
            plaintext: [1]
        )))
        XCTAssertEqual(
            classifier.classify(pRequest, originator: originator).decision,
            .denied(.unsupportedPermissionScheme(kind: "protocol", scheme: "btms"))
        )
    }

    func testAdminOriginatorBypassesReservedNamespaces() throws {
        let classifier = try makeClassifier(admin: "wallet.example")
        let request = WalletRequest.action(.listOutputs(try .init(basket: "admin tokens")))
        XCTAssertEqual(classifier.classify(request, originator: "HTTPS://WALLET.EXAMPLE:443").decision, .adminPassThrough)
    }

    func testUnknownMethodFailsClosed() throws {
        let classifier = try makeClassifier()
        XCTAssertEqual(
            classifier.classify(.unsupported(method: "futureWalletCall"), originator: originator).decision,
            .denied(.unsupportedMethod("futureWalletCall"))
        )
    }

    func testDescriptionsAreNotPartOfDecisionIdentity() throws {
        let classifier = try makeClassifier()
        let protocolID = try WalletProtocolID(securityLevel: .everyApp, name: "sample access")
        let first = WalletRequest.keyQuery(.encrypt(.init(
            protocolID: protocolID,
            keyID: try .init("1"),
            plaintext: [1],
            access: try .init(privileged: true, privilegedReason: "first untrusted reason")
        )))
        let second = WalletRequest.keyQuery(.encrypt(.init(
            protocolID: protocolID,
            keyID: try .init("1"),
            plaintext: [1],
            access: try .init(privileged: true, privilegedReason: "different untrusted reason")
        )))
        let a = classifier.classify(first, originator: originator)
        let b = classifier.classify(second, originator: originator)
        XCTAssertEqual(a.decision, b.decision)
        XCTAssertNotEqual(a.display.reason, b.display.reason)
    }

    func testCanonicalScopeCodableAndHashIdentityAreDeterministic() throws {
        let scope = PermissionScopeKey.certificateAccess(.init(
            originator: try .init("HTTPS://EXAMPLE.COM:443/path"),
            privileged: true,
            certificateType: "type",
            verifier: .init(publicKey: try testKey(2)),
            fields: ["name", "email"]
        ))
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let first = try encoder.encode(scope)
        let second = try encoder.encode(scope)
        XCTAssertEqual(first, second)
        XCTAssertEqual(try JSONDecoder().decode(PermissionScopeKey.self, from: first), scope)
        XCTAssertEqual(Set([scope, scope]).count, 1)
    }

    func testCreateActionCarriesAuthoritativeSpendingSeedSeparateFromDisplayText() throws {
        let classifier = try makeClassifier()
        let output = try WalletCreateActionOutput(
            lockingScript: [0x51],
            satoshis: 42,
            outputDescription: "untrusted forty two"
        )
        let request = WalletRequest.action(.createAction(try .init(
            description: "untrusted action",
            outputs: [output]
        )))
        let classification = classifier.classify(request, originator: originator)
        let plan = try authorizationPlan(classification.decision)
        XCTAssertEqual(plan.spending?.scope.originator.rawValue, "example.com")
        XCTAssertEqual(plan.spending?.outputs.map(\.satoshis), [42])
        XCTAssertEqual(classification.display.reason, "untrusted action")
        XCTAssertEqual(classification.display.spendingLineItems.single?.description, "untrusted forty two")
    }

    private func makeClassifier(admin: String = "wallet.example") throws -> WalletPermissionClassifier {
        try .init(policy: .init(adminOriginator: admin))
    }

    private func authorizationPlan(_ decision: PermissionDecision) throws -> PermissionAuthorizationPlan {
        guard case .authorizationRequired(let plan) = decision else {
            throw TestError.expectedAuthorization(decision)
        }
        return plan
    }

    private enum TestError: Error {
        case expectedAuthorization(PermissionDecision)
    }
}

private extension Collection {
    var single: Element? { count == 1 ? first : nil }
}
