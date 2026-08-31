import BSVWallet

public struct WalletPermissionPolicy: Hashable, Codable, Sendable {
    public let adminOriginator: CanonicalOriginator

    public init(adminOriginator: String) throws {
        self.adminOriginator = try CanonicalOriginator(adminOriginator)
    }
}

/// Keeps unsupported dispatch discriminators fail-closed alongside decoded BRC-100 requests.
public enum PermissionPolicyInput: Sendable {
    case wallet(WalletRequest)
    case unsupported(method: String)
}

/// Pure BRC-116 request classification. It performs no I/O and grants no permission.
public struct WalletPermissionClassifier: Sendable {
    public let policy: WalletPermissionPolicy

    public init(policy: WalletPermissionPolicy) {
        self.policy = policy
    }

    public func classify(
        _ input: PermissionPolicyInput,
        originator rawOriginator: String
    ) -> PermissionClassification {
        switch input {
        case .unsupported(let method):
            return denied(.unsupportedMethod(method))
        case .wallet(let request):
            return classify(request, originator: rawOriginator)
        }
    }

    public func classify(
        _ request: WalletRequest,
        originator rawOriginator: String
    ) -> PermissionClassification {
        if Self.isBootstrap(request.call) {
            return PermissionClassification(decision: .bootstrapNoPrompt)
        }

        guard let originator = try? CanonicalOriginator(rawOriginator) else {
            return denied(.missingOriginator)
        }
        if originator == policy.adminOriginator {
            return PermissionClassification(decision: .adminPassThrough)
        }

        switch request {
        case .action(let action):
            return classify(action, originator: originator)
        case .certificate(let certificate):
            return classify(certificate, originator: originator)
        case .keyQuery(let query):
            return classify(query, originator: originator)
        }
    }

    private func classify(
        _ request: WalletWireActionRequest,
        originator: CanonicalOriginator
    ) -> PermissionClassification {
        switch request {
        case .createAction(let request):
            return classifyCreateAction(request, originator: originator)
        case .signAction, .abortAction:
            return authenticated()
        case .listActions(let request):
            switch Self.ordinaryListActionLabels(request.labels) {
            case .failure(let rejection): return denied(rejection)
            case .success(let labels):
                return requirementsForLabels(
                    labels,
                    usage: .actionLabelListing,
                    originator: originator,
                    seekPermission: request.seekPermission ?? true
                )
            }
        case .internalizeAction(let request):
            var requirements = [PermissionRequirement]()
            let missing = Self.missingBehavior(request.seekPermission ?? true)
            for output in request.outputs {
                guard case .basketInsertion(let insertion) = output.remittance else { continue }
                switch basketRequirement(
                    insertion.basket,
                    usage: .basketInsertion,
                    originator: originator,
                    missing: missing
                ) {
                case .success(let requirement): requirements.append(requirement)
                case .failure(let rejection): return denied(rejection)
                }
            }
            switch appendLabelRequirements(
                request.labels,
                usage: .actionLabelApplication,
                originator: originator,
                missing: missing,
                to: &requirements
            ) {
            case .success: break
            case .failure(let rejection): return denied(rejection)
            }
            return authorize(requirements, display: .init(reason: request.description))
        case .listOutputs(let request):
            return oneBasket(
                request.basket,
                usage: .basketListing,
                originator: originator,
                seekPermission: request.seekPermission ?? true
            )
        case .relinquishOutput(let request):
            return oneBasket(
                request.basket,
                usage: .basketRemoval,
                originator: originator,
                seekPermission: true
            )
        }
    }

    private func classifyCreateAction(
        _ request: WalletCreateActionRequest,
        originator: CanonicalOriginator
    ) -> PermissionClassification {
        var requirements = [PermissionRequirement]()
        for output in request.outputs ?? [] {
            guard let basket = output.basket else { continue }
            switch basketRequirement(
                basket,
                usage: .basketInsertion,
                originator: originator,
                missing: .promptUser
            ) {
            case .success(let requirement): requirements.append(requirement)
            case .failure(let rejection): return denied(rejection)
            }
        }
        switch appendLabelRequirements(
            request.labels ?? [],
            usage: .actionLabelApplication,
            originator: originator,
            missing: .promptUser,
            to: &requirements
        ) {
        case .success: break
        case .failure(let rejection): return denied(rejection)
        }

        let spending = SpendingAuthorizationSeed(
            scope: .init(originator: originator),
            inputOutpoints: (request.inputs ?? []).map { $0.outpoint.description },
            outputs: (request.outputs ?? []).map { .init(satoshis: $0.satoshis) }
        )
        let displayItems = (request.inputs ?? []).map {
            PermissionDisplayMetadata.LineItem(
                kind: .input,
                description: $0.inputDescription,
                satoshis: nil
            )
        } + (request.outputs ?? []).map {
            PermissionDisplayMetadata.LineItem(
                kind: .output,
                description: $0.outputDescription,
                satoshis: $0.satoshis
            )
        }
        return PermissionClassification(
            decision: .authorizationRequired(.init(requirements: requirements, spending: spending)),
            display: .init(reason: request.description, spendingLineItems: displayItems)
        )
    }

    private func classify(
        _ request: WalletWireCertificateRequest,
        originator: CanonicalOriginator
    ) -> PermissionClassification {
        switch request {
        case .revealCounterpartyKeyLinkage(let request):
            let disclosedCounterparty = CanonicalCounterparty(publicKey: request.counterparty).rawValue
            return syntheticProtocol(
                level: 2,
                name: "counterparty key linkage revelation \(disclosedCounterparty)",
                counterparty: CanonicalCounterparty(publicKey: request.verifier),
                privileged: request.privilege.privileged ?? false,
                usage: .linkageRevelation,
                originator: originator,
                reason: request.privilege.privilegedReason
            )
        case .revealSpecificKeyLinkage(let request):
            let suffix = request.protocolID.securityLevel == .everyAppAndCounterparty
                ? request.keyID.value
                : "all"
            return syntheticProtocol(
                level: 2,
                name: "specific key linkage revelation \(request.protocolID.name) \(suffix)",
                counterparty: CanonicalCounterparty(publicKey: request.verifier),
                privileged: request.privilege.privileged ?? false,
                usage: .linkageRevelation,
                originator: originator,
                reason: request.privilege.privilegedReason
            )
        case .acquireCertificate(let request):
            return syntheticProtocol(
                level: 1,
                name: "certificate acquisition \(request.type.base64)",
                counterparty: .selfCounterparty,
                privileged: request.privilege.privileged ?? false,
                usage: .certificateAcquisition,
                originator: originator,
                reason: request.privilege.privilegedReason
            )
        case .listCertificates(let request):
            return syntheticProtocol(
                level: 1,
                name: "certificate list",
                counterparty: .selfCounterparty,
                privileged: request.privilege.privileged ?? false,
                usage: .certificateListing,
                originator: originator,
                reason: request.privilege.privilegedReason
            )
        case .proveCertificate(let request):
            let scope = CertificatePermissionScope(
                originator: originator,
                privileged: request.privilege.privileged ?? false,
                certificateType: request.certificate.type.base64,
                verifier: .init(publicKey: request.verifier),
                fields: request.fieldsToReveal.map(\.value)
            )
            return authorize(
                [.init(scope: .certificateAccess(scope), usage: .certificateDisclosure, whenMissing: .promptUser)],
                display: .init(reason: request.privilege.privilegedReason)
            )
        case .relinquishCertificate(let request):
            return syntheticProtocol(
                level: 1,
                name: "certificate relinquishment \(request.type.base64)",
                counterparty: .selfCounterparty,
                privileged: false,
                usage: .certificateRelinquishment,
                originator: originator,
                reason: nil
            )
        case .discoverByIdentityKey(let request):
            return identityResolution(
                originator: originator,
                seekPermission: request.seekPermission ?? false
            )
        case .discoverByAttributes(let request):
            return identityResolution(
                originator: originator,
                seekPermission: request.seekPermission ?? false
            )
        }
    }

    private func classify(
        _ request: WalletWireKeyQueryRequest,
        originator: CanonicalOriginator
    ) -> PermissionClassification {
        switch request {
        case .getPublicKey(let request):
            let seek = request.access.seekPermission ?? true
            switch request.selection {
            case .identity:
                return syntheticProtocol(
                    level: 1,
                    name: "identity key retrieval",
                    counterparty: .selfCounterparty,
                    privileged: request.access.privileged,
                    usage: .identityKey,
                    originator: originator,
                    reason: request.access.privilegedReason,
                    seekPermission: seek
                )
            case .derived(let protocolID, _, let counterparty, _):
                return protocolUse(
                    protocolID,
                    counterparty: counterparty,
                    privileged: request.access.privileged,
                    usage: .publicKey,
                    originator: originator,
                    reason: request.access.privilegedReason,
                    seekPermission: seek
                )
            }
        case .encrypt(let request):
            return protocolUse(request.protocolID, counterparty: request.counterparty, privileged: request.access.privileged, usage: .encrypt, originator: originator, reason: request.access.privilegedReason, seekPermission: request.access.seekPermission ?? true)
        case .decrypt(let request):
            return protocolUse(request.protocolID, counterparty: request.counterparty, privileged: request.access.privileged, usage: .decrypt, originator: originator, reason: request.access.privilegedReason, seekPermission: request.access.seekPermission ?? true)
        case .createHMAC(let request):
            return protocolUse(request.protocolID, counterparty: request.counterparty, privileged: request.access.privileged, usage: .hmac, originator: originator, reason: request.access.privilegedReason, seekPermission: request.access.seekPermission ?? true)
        case .verifyHMAC(let request):
            return protocolUse(request.protocolID, counterparty: request.counterparty, privileged: request.access.privileged, usage: .hmac, originator: originator, reason: request.access.privilegedReason, seekPermission: request.access.seekPermission ?? true)
        case .createSignature(let request):
            return protocolUse(request.protocolID, counterparty: request.counterparty, privileged: request.access.privileged, usage: .signing, originator: originator, reason: request.access.privilegedReason, seekPermission: request.access.seekPermission ?? true)
        case .verifySignature(let request):
            return protocolUse(request.protocolID, counterparty: request.counterparty, privileged: request.access.privileged, usage: .signing, originator: originator, reason: request.access.privilegedReason, seekPermission: request.access.seekPermission ?? true)
        case .isAuthenticated, .waitForAuthentication, .getVersion:
            return PermissionClassification(decision: .bootstrapNoPrompt)
        case .getHeight, .getHeaderForHeight, .getNetwork:
            return authenticated()
        }
    }

    private func protocolUse(
        _ protocolID: WalletProtocolID,
        counterparty: WalletCounterparty,
        privileged: Bool,
        usage: PermissionUsage,
        originator: CanonicalOriginator,
        reason: String?,
        seekPermission: Bool
    ) -> PermissionClassification {
        syntheticProtocol(
            level: protocolID.securityLevel.rawValue,
            name: protocolID.name,
            counterparty: .init(counterparty),
            privileged: privileged,
            usage: usage,
            originator: originator,
            reason: reason,
            seekPermission: seekPermission
        )
    }

    private func syntheticProtocol(
        level: UInt8,
        name: String,
        counterparty: CanonicalCounterparty,
        privileged: Bool,
        usage: PermissionUsage,
        originator: CanonicalOriginator,
        reason: String?,
        seekPermission: Bool = true
    ) -> PermissionClassification {
        switch protocolRequirement(
            level: level,
            name: name,
            counterparty: counterparty,
            privileged: privileged,
            usage: usage,
            originator: originator,
            missing: Self.missingBehavior(seekPermission)
        ) {
        case .failure(let rejection): return denied(rejection)
        case .success(nil): return authenticated()
        case .success(let requirement?):
            return authorize([requirement], display: .init(reason: reason))
        }
    }

    private func protocolRequirement(
        level: UInt8,
        name: String,
        counterparty: CanonicalCounterparty,
        privileged: Bool,
        usage: PermissionUsage,
        originator: CanonicalOriginator,
        missing: MissingPermissionBehavior
    ) -> Result<PermissionRequirement?, PermissionPolicyRejection> {
        if name.hasPrefix("admin") { return .failure(.reservedProtocol(name)) }
        if name.hasPrefix("p ") {
            return .failure(.unsupportedPermissionScheme(kind: "protocol", scheme: Self.scheme(in: name)))
        }
        if level == 0 { return .success(nil) }
        guard let protectedLevel = ProtocolPermissionLevel(rawValue: level),
              let scope = try? ProtocolPermissionScope(
                originator: originator,
                privileged: privileged,
                securityLevel: protectedLevel,
                protocolName: name,
                counterparty: counterparty
              ) else {
            return .failure(.unsupportedSecurityLevel(level))
        }
        return .success(.init(scope: .protocolAccess(scope), usage: usage, whenMissing: missing))
    }

    private func identityResolution(
        originator: CanonicalOriginator,
        seekPermission: Bool
    ) -> PermissionClassification {
        syntheticProtocol(
            level: 1,
            name: "identity resolution",
            counterparty: .selfCounterparty,
            privileged: false,
            usage: .identityResolution,
            originator: originator,
            reason: nil,
            seekPermission: seekPermission
        )
    }

    private func oneBasket(
        _ basket: String,
        usage: PermissionUsage,
        originator: CanonicalOriginator,
        seekPermission: Bool
    ) -> PermissionClassification {
        switch basketRequirement(
            basket,
            usage: usage,
            originator: originator,
            missing: Self.missingBehavior(seekPermission)
        ) {
        case .success(let requirement): return authorize([requirement])
        case .failure(let rejection): return denied(rejection)
        }
    }

    private func basketRequirement(
        _ basket: String,
        usage: PermissionUsage,
        originator: CanonicalOriginator,
        missing: MissingPermissionBehavior
    ) -> Result<PermissionRequirement, PermissionPolicyRejection> {
        if basket == "default" || basket.hasPrefix("admin") {
            return .failure(.reservedBasket(basket))
        }
        if basket.hasPrefix("p ") {
            return .failure(.unsupportedPermissionScheme(kind: "basket", scheme: Self.scheme(in: basket)))
        }
        return .success(.init(
            scope: .basketAccess(.init(originator: originator, basket: basket)),
            usage: usage,
            whenMissing: missing
        ))
    }

    private func requirementsForLabels(
        _ labels: [String],
        usage: PermissionUsage,
        originator: CanonicalOriginator,
        seekPermission: Bool
    ) -> PermissionClassification {
        var requirements = [PermissionRequirement]()
        switch appendLabelRequirements(
            labels,
            usage: usage,
            originator: originator,
            missing: Self.missingBehavior(seekPermission),
            to: &requirements
        ) {
        case .success: return authorize(requirements)
        case .failure(let rejection): return denied(rejection)
        }
    }

    private func appendLabelRequirements(
        _ labels: [String],
        usage: PermissionUsage,
        originator: CanonicalOriginator,
        missing: MissingPermissionBehavior,
        to requirements: inout [PermissionRequirement]
    ) -> Result<Void, PermissionPolicyRejection> {
        for label in labels {
            if label.hasPrefix("admin") { return .failure(.reservedLabel(label)) }
            if label.hasPrefix("p ") {
                return .failure(.unsupportedPermissionScheme(kind: "label", scheme: Self.scheme(in: label)))
            }
            switch protocolRequirement(
                level: 1,
                name: "action label \(label)",
                counterparty: .selfCounterparty,
                privileged: false,
                usage: usage,
                originator: originator,
                missing: missing
            ) {
            case .success(let requirement?): requirements.append(requirement)
            case .success(nil): break
            case .failure(let rejection): return .failure(rejection)
            }
        }
        return .success(())
    }

    private static func ordinaryListActionLabels(
        _ labels: [String]
    ) -> Result<[String], PermissionPolicyRejection> {
        var ordinary = [String]()
        var from: UInt64?
        var to: UInt64?
        for label in labels {
            if label.hasPrefix("action time from ") {
                guard from == nil,
                      let value = timestamp(after: "action time from ", in: label) else {
                    return .failure(.invalidActionTimeLabel(label))
                }
                from = value
            } else if label.hasPrefix("action time to ") {
                guard to == nil,
                      let value = timestamp(after: "action time to ", in: label) else {
                    return .failure(.invalidActionTimeLabel(label))
                }
                to = value
            } else {
                ordinary.append(label)
            }
        }
        if let from, let to, from >= to {
            return .failure(.invalidActionTimeLabel("action time range"))
        }
        return .success(ordinary)
    }

    private static func timestamp(after prefix: String, in label: String) -> UInt64? {
        let text = String(label.dropFirst(prefix.count))
        guard !text.isEmpty,
              text.utf8.allSatisfy({ (48...57).contains($0) }) else { return nil }
        return UInt64(text)
    }

    private static func scheme(in name: String) -> String {
        let parts = name.split(separator: " ", omittingEmptySubsequences: true)
        return parts.count > 1 ? String(parts[1]) : ""
    }

    private static func missingBehavior(_ seekPermission: Bool) -> MissingPermissionBehavior {
        seekPermission ? .promptUser : .denyWithoutPrompt
    }

    private static func isBootstrap(_ call: WalletCall) -> Bool {
        call == .isAuthenticated || call == .waitForAuthentication || call == .getVersion
    }

    private func authorize(
        _ requirements: [PermissionRequirement],
        display: PermissionDisplayMetadata = .init()
    ) -> PermissionClassification {
        guard !requirements.isEmpty else { return authenticated() }
        return PermissionClassification(
            decision: .authorizationRequired(.init(requirements: requirements)),
            display: display
        )
    }

    private func authenticated() -> PermissionClassification {
        PermissionClassification(decision: .authenticatedPassThrough)
    }

    private func denied(_ rejection: PermissionPolicyRejection) -> PermissionClassification {
        PermissionClassification(decision: .denied(rejection))
    }
}
