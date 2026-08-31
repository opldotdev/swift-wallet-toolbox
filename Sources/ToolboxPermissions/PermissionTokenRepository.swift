import BSVScript
import BSVTransaction
import BSVWallet

/// Immutable identity of the wallet account whose administrative baskets are queried.
public struct PermissionAccountID: Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        guard !rawValue.isEmpty else { throw PermissionTokenRepositoryError.invalidAccountID }
        self.rawValue = rawValue
    }
}

/// Canonical token plus the exact unspent output that carried it.
public struct PermissionTokenMatch: Hashable, Sendable {
    public let accountID: PermissionAccountID
    public let token: PermissionToken
    public let outpoint: Outpoint
    public let satoshis: UInt64
    public let lockingScript: [UInt8]
    public let sourceBEEF: BEEF

    package init(
        accountID: PermissionAccountID,
        token: PermissionToken,
        outpoint: Outpoint,
        satoshis: UInt64,
        lockingScript: [UInt8],
        sourceBEEF: BEEF
    ) {
        self.accountID = accountID
        self.token = token
        self.outpoint = outpoint
        self.satoshis = satoshis
        self.lockingScript = lockingScript
        self.sourceBEEF = sourceBEEF
    }
}

public enum PermissionTokenRepositoryError: Error, Equatable, Sendable {
    case invalidAccountID
    case invalidated
    case missingBEEF
    case untrustworthyBEEF(outpoint: Outpoint)
    case candidateLimitExceeded(total: UInt64, maximum: UInt64)
    case paginationDidNotProgress(offset: UInt32)
    case paginationOverflow(offset: UInt32, returned: UInt32)
}

/// Account-bound, read-only access to BRC-116's canonical on-chain permission state.
///
/// No positive authorization result is cached. Every lookup re-queries the wallet's
/// spendable admin basket and validates the returned output against its source BEEF.
public actor PermissionTokenRepository {
    public nonisolated let accountID: PermissionAccountID

    nonisolated static let standardTransactionLimits: TransactionLimits = {
        try! TransactionLimits(
            maximumTransactionByteCount: 4 << 20,
            maximumInputCount: 100_000,
            maximumOutputCount: 100_000,
            maximumScriptByteCount: 1 << 20
        )
    }()

    private static let pageSize: UInt32 = 100
    private static let maximumCandidateCount = UInt64(WalletABILimits.standard.maximumCollectionCount)

    private let wallet: any PermissionTokenWallet
    private let transactionLimits: TransactionLimits
    private var invalidationEpoch: UInt64 = 0
    private var isInvalidated = false

    public init(wallet: any PermissionTokenWallet) {
        self.accountID = wallet.permissionAccountID
        self.wallet = wallet
        self.transactionLimits = Self.standardTransactionLimits
    }

    package init(
        wallet: any PermissionTokenWallet,
        transactionLimits: TransactionLimits
    ) {
        self.accountID = wallet.permissionAccountID
        self.wallet = wallet
        self.transactionLimits = transactionLimits
    }

    /// Permanently invalidates this account-bound repository. It cannot be rebound.
    public func invalidate() {
        isInvalidated = true
        invalidationEpoch &+= 1
    }

    /// Finds a valid on-chain token covering `scope`, if one exists.
    ///
    /// Malformed token scripts and correctly-authenticated tokens for another scope are
    /// ignored candidate-by-candidate. Missing or inconsistent BEEF is a repository
    /// integrity failure, not "no permission".
    public func findCovering(
        _ scope: PermissionScopeKey,
        nowUnixTime: UInt64
    ) async throws -> PermissionTokenMatch? {
        try Task.checkCancellation()
        let epoch = try activeEpoch()
        let query = queryIdentity(for: scope)
        var offset: UInt32 = 0
        var scannedCandidateCount: UInt64 = 0
        var seenOutpoints = Set<Outpoint>()
        var matches = [PermissionTokenMatch]()

        while true {
            try Task.checkCancellation()
            try requireActive(epoch)
            let request = try WalletListOutputsRequest(
                basket: query.basket.rawValue,
                tags: query.tags,
                tagQueryMode: .all,
                include: .entireTransactions,
                includeTags: true,
                pagination: WalletPagination(limit: Self.pageSize, offset: offset),
                seekPermission: false
            )

            let page: WalletListOutputsResult
            do {
                page = try await wallet.listPermissionTokenOutputs(request)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try Task.checkCancellation()
                try requireActive(epoch)
                throw error
            }
            try Task.checkCancellation()
            try requireActive(epoch)

            let returned = try exactUInt32(page.outputs.count, offset: offset)
            guard UInt64(page.totalOutputs) <= Self.maximumCandidateCount else {
                throw PermissionTokenRepositoryError.candidateLimitExceeded(
                    total: UInt64(page.totalOutputs),
                    maximum: Self.maximumCandidateCount
                )
            }
            let nextScannedCount = scannedCandidateCount + UInt64(returned)
            guard nextScannedCount <= Self.maximumCandidateCount else {
                throw PermissionTokenRepositoryError.candidateLimitExceeded(
                    total: nextScannedCount,
                    maximum: Self.maximumCandidateCount
                )
            }
            scannedCandidateCount = nextScannedCount

            if page.outputs.isEmpty {
                if offset < page.totalOutputs {
                    throw PermissionTokenRepositoryError.paginationDidNotProgress(offset: offset)
                }
                break
            }
            guard let beef = page.beef else {
                throw PermissionTokenRepositoryError.missingBEEF
            }

            var newOutpointCount = 0
            for output in page.outputs {
                try Task.checkCancellation()
                try requireActive(epoch)
                guard seenOutpoints.insert(output.outpoint).inserted else { continue }
                newOutpointCount += 1

                let source = try sourceOutput(for: output, in: beef)
                guard output.spendable, source.satoshis == 1 else { continue }

                let token: PermissionToken
                do {
                    try requireActive(epoch)
                    token = try await PermissionTokenCodec.decode(
                        source.lockingScript,
                        from: query.basket,
                        using: wallet
                    )
                    try Task.checkCancellation()
                    try requireActive(epoch)
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    try Task.checkCancellation()
                    try requireActive(epoch)
                    continue
                }

                guard covers(token, requested: scope, nowUnixTime: nowUnixTime) else { continue }
                matches.append(PermissionTokenMatch(
                    accountID: accountID,
                    token: token,
                    outpoint: output.outpoint,
                    satoshis: source.satoshis,
                    lockingScript: source.lockingScript.bytes,
                    sourceBEEF: beef
                ))
            }

            let nextOffset = try Self.checkedNextOffset(offset: offset, returned: returned)
            if nextOffset >= page.totalOutputs { break }
            guard newOutpointCount > 0 else {
                throw PermissionTokenRepositoryError.paginationDidNotProgress(offset: offset)
            }
            offset = nextOffset
        }

        try Task.checkCancellation()
        try requireActive(epoch)
        return bestMatch(in: matches, for: scope)
    }

    private func activeEpoch() throws -> UInt64 {
        guard !isInvalidated else { throw PermissionTokenRepositoryError.invalidated }
        return invalidationEpoch
    }

    private func requireActive(_ epoch: UInt64) throws {
        guard !isInvalidated, invalidationEpoch == epoch else {
            throw PermissionTokenRepositoryError.invalidated
        }
    }

    private func sourceOutput(
        for metadata: WalletOutput,
        in beef: BEEF
    ) throws -> TransactionOutput {
        let transaction: Transaction
        do {
            guard let candidate = try beef.transaction(
                for: metadata.outpoint.transactionID,
                limits: transactionLimits
            ) else {
                throw PermissionTokenRepositoryError.untrustworthyBEEF(outpoint: metadata.outpoint)
            }
            transaction = candidate
        } catch let error as PermissionTokenRepositoryError {
            throw error
        } catch {
            throw PermissionTokenRepositoryError.untrustworthyBEEF(outpoint: metadata.outpoint)
        }
        guard let index = Int(exactly: metadata.outpoint.outputIndex),
              transaction.outputs.indices.contains(index) else {
            throw PermissionTokenRepositoryError.untrustworthyBEEF(outpoint: metadata.outpoint)
        }
        let source = transaction.outputs[index]
        guard source.satoshis == metadata.satoshis,
              metadata.lockingScript == nil || metadata.lockingScript == source.lockingScript.bytes else {
            throw PermissionTokenRepositoryError.untrustworthyBEEF(outpoint: metadata.outpoint)
        }
        return source
    }

    private func exactUInt32(_ count: Int, offset: UInt32) throws -> UInt32 {
        guard let value = UInt32(exactly: count) else {
            throw PermissionTokenRepositoryError.paginationOverflow(offset: offset, returned: .max)
        }
        return value
    }

    static func checkedNextOffset(offset: UInt32, returned: UInt32) throws -> UInt32 {
        let (nextOffset, overflow) = offset.addingReportingOverflow(returned)
        guard !overflow, nextOffset > offset else {
            throw PermissionTokenRepositoryError.paginationOverflow(
                offset: offset,
                returned: returned
            )
        }
        return nextOffset
    }
}

private extension PermissionTokenRepository {
    struct QueryIdentity {
        let basket: PermissionTokenBasket
        let tags: [String]
    }

    func queryIdentity(for scope: PermissionScopeKey) -> QueryIdentity {
        switch scope {
        case .protocolAccess(let value):
            var tags = [
                "originator \(value.originator.rawValue)",
                "privileged \(value.privileged)",
                "protocolName \(value.protocolName)",
                "protocolSecurityLevel \(value.securityLevel.rawValue)",
            ]
            if value.securityLevel == .applicationAndCounterparty,
               let counterparty = value.counterparty {
                tags.append("counterparty \(counterparty.rawValue)")
            }
            return QueryIdentity(basket: .protocolPermission, tags: tags)

        case .basketAccess(let value):
            return QueryIdentity(
                basket: .basketAccess,
                tags: ["originator \(value.originator.rawValue)", "basket \(value.basket)"]
            )

        case .certificateAccess(let value):
            return QueryIdentity(
                basket: .certificateAccess,
                tags: [
                    "originator \(value.originator.rawValue)",
                    "privileged \(value.privileged)",
                    "type \(value.certificateType)",
                    "verifier \(value.verifier.rawValue)",
                ]
            )

        case .spendingAuthorization(let value):
            return QueryIdentity(
                basket: .spendingAuthorization,
                tags: ["originator \(value.originator.rawValue)"]
            )
        }
    }

    func covers(
        _ token: PermissionToken,
        requested: PermissionScopeKey,
        nowUnixTime: UInt64
    ) -> Bool {
        guard !token.isExpired(at: nowUnixTime) else { return false }
        switch (token, requested) {
        case (.dpacp(let grant), .protocolAccess(let request)):
            return grant.scope == request
        case (.dbap(let grant), .basketAccess(let request)):
            return grant.scope == request
        case (.dcap(let grant), .certificateAccess(let request)):
            return grant.scope.originator == request.originator
                && grant.scope.privileged == request.privileged
                && grant.scope.certificateType == request.certificateType
                && grant.scope.verifier == request.verifier
                && grant.covers(fields: request.fields)
        case (.dsap(let grant), .spendingAuthorization(let request)):
            return grant.scope == request
        default:
            return false
        }
    }

    func bestMatch(
        in matches: [PermissionTokenMatch],
        for scope: PermissionScopeKey
    ) -> PermissionTokenMatch? {
        guard case .spendingAuthorization = scope else { return matches.first }
        return matches.max { lhs, rhs in
            let lhsAmount = dsapAmount(lhs.token)
            let rhsAmount = dsapAmount(rhs.token)
            if lhsAmount != rhsAmount { return lhsAmount < rhsAmount }
            return lhs.outpoint.description > rhs.outpoint.description
        }
    }

    func dsapAmount(_ token: PermissionToken) -> UInt64 {
        guard case .dsap(let value) = token else { return 0 }
        return value.authorizedAmount
    }
}
