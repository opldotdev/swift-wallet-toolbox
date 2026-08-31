import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import XCTest
@testable import ToolboxPermissions

final class PermissionTokenRepositoryTests: XCTestCase {
    func testExactQueryAndPageTwoValidTokenAfterExpiredCandidate() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(21))
        let scope = BasketPermissionScope(
            originator: try CanonicalOriginator("HTTPS://EXAMPLE.COM:443/path"),
            basket: "payments"
        )
        let expired = PermissionToken.dbap(try .init(scope: scope, expiry: 99))
        let valid = PermissionToken.dbap(try .init(scope: scope, expiry: 0))
        let expiredCandidate = try await candidate(expired, wallet: wallet)
        let validCandidate = try await candidate(valid, wallet: wallet)
        await wallet.setPage(
            offset: 0,
            result: try page(
                total: 101,
                candidates: Array(repeating: expiredCandidate, count: 100)
            )
        )
        await wallet.setPage(offset: 100, result: try page(total: 101, candidates: [validCandidate]))

        let repository = try repository(wallet: wallet)
        let match = try await repository.findCovering(.basketAccess(scope), nowUnixTime: 100)

        XCTAssertEqual(match?.token, valid)
        XCTAssertEqual(match?.satoshis, 1)
        XCTAssertEqual(match?.outpoint, validCandidate.output.outpoint)
        XCTAssertEqual(match?.lockingScript, validCandidate.output.lockingScript)
        let requests = await wallet.recordedRequests()
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests.map(\.basket), ["admin basket-access", "admin basket-access"])
        XCTAssertEqual(requests[0].tags, ["originator example.com", "basket payments"])
        XCTAssertEqual(requests[0].tagQueryMode, .all)
        XCTAssertEqual(requests[0].include, .entireTransactions)
        XCTAssertEqual(requests[0].includeTags, true)
        XCTAssertEqual(requests[0].seekPermission, false)
        XCTAssertEqual(requests[0].pagination.limit, 100)
        XCTAssertEqual(requests.map { $0.pagination.offset }, [0, 100])
    }

    func testTagHitWithDifferentDecryptedScopeNeverAuthorizes() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(22))
        let requested = BasketPermissionScope(
            originator: try CanonicalOriginator("example.com"), basket: "payments"
        )
        let other = PermissionToken.dbap(try .init(
            scope: .init(originator: try CanonicalOriginator("evil.example"), basket: "payments"),
            expiry: 0
        ))
        await wallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [other], wallet: wallet)
        )

        let result = try await repository(wallet: wallet).findCovering(
            .basketAccess(requested), nowUnixTime: 1
        )
        XCTAssertNil(result)
    }

    func testMalformedCandidateDoesNotHideLaterValidToken() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(40))
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        let malformedTransaction = Transaction(outputs: [TransactionOutput(
            satoshis: 1,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )])
        let malformedID = try malformedTransaction.transactionID(
            limits: PermissionTokenRepository.standardTransactionLimits
        )
        let malformed = RepositoryCandidate(
            output: try WalletOutput(
                satoshis: 1,
                lockingScript: [0x51],
                spendable: true,
                outpoint: Outpoint(transactionID: malformedID, outputIndex: 0)
            ),
            transaction: malformedTransaction
        )
        let valid = try await candidate(token, wallet: wallet)
        await wallet.setPage(
            offset: 0,
            result: try page(total: 2, candidates: [malformed, valid])
        )

        let match = try await repository(wallet: wallet).findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        XCTAssertEqual(match?.token, token)
    }

    func testDPACPLevelOneErasesCounterpartyAndLevelTwoRequiresExactCounterparty() async throws {
        let originator = try CanonicalOriginator("example.com")
        let levelOneWallet = RepositoryTestWallet(rootKey: try testPrivateKey(23))
        let levelOneScope = try ProtocolPermissionScope(
            originator: originator,
            privileged: false,
            securityLevel: .application,
            protocolName: "messages",
            counterparty: CanonicalCounterparty(publicKey: try testKey(24))
        )
        XCTAssertNil(levelOneScope.counterparty)
        let levelOne = PermissionToken.dpacp(try .init(scope: levelOneScope, expiry: 0))
        await levelOneWallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [levelOne], wallet: levelOneWallet)
        )
        let levelOneMatch = try await repository(wallet: levelOneWallet).findCovering(
            .protocolAccess(levelOneScope), nowUnixTime: 1
        )
        XCTAssertNotNil(levelOneMatch)
        let levelOneRequests = await levelOneWallet.recordedRequests()
        XCTAssertEqual(levelOneRequests.first?.tags, [
            "originator example.com", "privileged false", "protocolName messages",
            "protocolSecurityLevel 1",
        ])

        let levelTwoWallet = RepositoryTestWallet(rootKey: try testPrivateKey(25))
        let grantedCounterparty = CanonicalCounterparty(publicKey: try testKey(26))
        let otherCounterparty = CanonicalCounterparty(publicKey: try testKey(27))
        let grantedScope = try ProtocolPermissionScope(
            originator: originator,
            privileged: true,
            securityLevel: .applicationAndCounterparty,
            protocolName: "messages",
            counterparty: grantedCounterparty
        )
        let requestedScope = try ProtocolPermissionScope(
            originator: originator,
            privileged: true,
            securityLevel: .applicationAndCounterparty,
            protocolName: "messages",
            counterparty: otherCounterparty
        )
        let granted = PermissionToken.dpacp(try .init(scope: grantedScope, expiry: 0))
        await levelTwoWallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [granted], wallet: levelTwoWallet)
        )
        let levelTwoMatch = try await repository(wallet: levelTwoWallet).findCovering(
            .protocolAccess(requestedScope), nowUnixTime: 1
        )
        XCTAssertNil(levelTwoMatch)
        let levelTwoRequests = await levelTwoWallet.recordedRequests()
        XCTAssertEqual(levelTwoRequests.first?.tags.last,
                       "counterparty \(otherCounterparty.rawValue)")
    }

    func testDCAPRequestedFieldsMustBeSubsetOfGrantedFields() async throws {
        let originator = try CanonicalOriginator("example.com")
        let verifier = CanonicalCounterparty(publicKey: try testKey(28))
        let grantedScope = CertificatePermissionScope(
            originator: originator,
            privileged: false,
            certificateType: "identity",
            verifier: verifier,
            fields: ["name", "email"]
        )
        let granted = PermissionToken.dcap(try .init(scope: grantedScope, expiry: 0))

        let subsetWallet = RepositoryTestWallet(rootKey: try testPrivateKey(29))
        await subsetWallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [granted], wallet: subsetWallet)
        )
        let subset = CertificatePermissionScope(
            originator: originator,
            privileged: false,
            certificateType: "identity",
            verifier: verifier,
            fields: ["name"]
        )
        let subsetMatch = try await repository(wallet: subsetWallet).findCovering(
            .certificateAccess(subset), nowUnixTime: 1
        )
        XCTAssertNotNil(subsetMatch)

        let supersetWallet = RepositoryTestWallet(rootKey: try testPrivateKey(30))
        let narrowGrant = PermissionToken.dcap(try .init(scope: subset, expiry: 0))
        await supersetWallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [narrowGrant], wallet: supersetWallet)
        )
        let supersetMatch = try await repository(wallet: supersetWallet).findCovering(
            .certificateAccess(grantedScope), nowUnixTime: 1
        )
        XCTAssertNil(supersetMatch)
        let subsetRequests = await subsetWallet.recordedRequests()
        XCTAssertEqual(subsetRequests.first?.tags, [
            "originator example.com", "privileged false", "type identity",
            "verifier \(verifier.rawValue)",
        ])
    }

    func testDSAPSelectsGreatestSingleAuthorizationWithoutSumming() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(31))
        let scope = SpendingPermissionScope(originator: try CanonicalOriginator("example.com"))
        let tokens: [PermissionToken] = [5, 9, 7].map {
            .dsap(.init(scope: scope, authorizedAmount: UInt64($0)))
        }
        await wallet.setPage(
            offset: 0,
            result: try await page(total: 3, tokens: tokens, wallet: wallet)
        )

        let match = try await repository(wallet: wallet).findCovering(
            .spendingAuthorization(scope), nowUnixTime: .max
        )
        guard case .dsap(let token) = match?.token else {
            return XCTFail("Expected DSAP match")
        }
        XCTAssertEqual(token.authorizedAmount, 9)
        XCTAssertNotEqual(token.authorizedAmount, 21)
    }

    func testMissingAndInconsistentBEEFFailClosed() async throws {
        let token = PermissionToken.dbap(try .init(
            scope: .init(originator: try CanonicalOriginator("example.com"), basket: "payments"),
            expiry: 0
        ))
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(32))
        let valid = try await candidate(token, wallet: wallet)

        await wallet.setPage(offset: 0, result: try WalletListOutputsResult(
            totalOutputs: 1, beef: nil, outputs: [valid.output]
        ))
        await assertRepositoryError(.missingBEEF) {
            try await self.repository(wallet: wallet).findCovering(
                .basketAccess(try self.dbapScope()), nowUnixTime: 1
            )
        }

        let unrelated = Transaction(outputs: [TransactionOutput(
            satoshis: 1,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 1)
        )])
        await wallet.setPage(offset: 0, result: try WalletListOutputsResult(
            totalOutputs: 1,
            beef: try beef([unrelated]),
            outputs: [valid.output]
        ))
        await assertUntrustworthy {
            try await self.repository(wallet: wallet).findCovering(
                .basketAccess(try self.dbapScope()), nowUnixTime: 1
            )
        }

        let badVout = try WalletOutput(
            satoshis: 1,
            lockingScript: valid.output.lockingScript,
            spendable: true,
            outpoint: Outpoint(
                transactionID: valid.output.outpoint.transactionID,
                outputIndex: 1
            )
        )
        await wallet.setPage(offset: 0, result: try WalletListOutputsResult(
            totalOutputs: 1, beef: try beef([valid.transaction]), outputs: [badVout]
        ))
        await assertUntrustworthy {
            try await self.repository(wallet: wallet).findCovering(
                .basketAccess(try self.dbapScope()), nowUnixTime: 1
            )
        }

        for output in [
            try WalletOutput(
                satoshis: 2,
                lockingScript: valid.output.lockingScript,
                spendable: true,
                outpoint: valid.output.outpoint
            ),
            try WalletOutput(
                satoshis: 1,
                lockingScript: [0x51],
                spendable: true,
                outpoint: valid.output.outpoint
            ),
        ] {
            await wallet.setPage(offset: 0, result: try WalletListOutputsResult(
                totalOutputs: 1, beef: try beef([valid.transaction]), outputs: [output]
            ))
            await assertUntrustworthy {
                try await self.repository(wallet: wallet).findCovering(
                    .basketAccess(try self.dbapScope()), nowUnixTime: 1
                )
            }
        }
    }

    func testNonSpendableAndNonOneSatOutputsNeverAuthorize() async throws {
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(33))
        let stale = try await candidate(token, wallet: wallet, spendable: false)
        await wallet.setPage(offset: 0, result: try page(total: 1, candidates: [stale]))
        let staleMatch = try await repository(wallet: wallet).findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        XCTAssertNil(staleMatch)

        let twoSat = try await candidate(token, wallet: wallet, satoshis: 2)
        await wallet.setPage(offset: 0, result: try page(total: 1, candidates: [twoSat]))
        let twoSatMatch = try await repository(wallet: wallet).findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        XCTAssertNil(twoSatMatch)
    }

    func testAccountBindingAndPermanentInvalidation() async throws {
        XCTAssertThrowsError(try PermissionAccountID("")) { error in
            XCTAssertEqual(error as? PermissionTokenRepositoryError, .invalidAccountID)
        }
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        let firstID = try PermissionAccountID("account-one")
        let secondID = try PermissionAccountID("account-two")
        let firstWallet = RepositoryTestWallet(rootKey: try testPrivateKey(38), accountID: firstID)
        let secondWallet = RepositoryTestWallet(rootKey: try testPrivateKey(39), accountID: secondID)
        await firstWallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [token], wallet: firstWallet)
        )
        await secondWallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [token], wallet: secondWallet)
        )
        let first = PermissionTokenRepository(wallet: firstWallet)
        let second = PermissionTokenRepository(wallet: secondWallet)
        let firstMatch = try await first.findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        XCTAssertEqual(firstMatch?.accountID, firstID)
        let secondMatch = try await second.findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        XCTAssertEqual(secondMatch?.accountID, secondID)

        await first.invalidate()
        await assertRepositoryError(.invalidated) {
            try await first.findCovering(.basketAccess(try self.dbapScope()), nowUnixTime: 1)
        }
    }

    func testInvalidationAndCancellationDuringPagingFailCurrentLookup() async throws {
        try await assertInterruptedLookup(invalidate: true)
        try await assertInterruptedLookup(invalidate: false)
    }

    func testPaginationNonProgressAndOverflowChecks() async throws {
        XCTAssertThrowsError(try PermissionTokenRepository.checkedNextOffset(
            offset: .max - 1, returned: 2
        )) { error in
            XCTAssertEqual(error as? PermissionTokenRepositoryError,
                           .paginationOverflow(offset: .max - 1, returned: 2))
        }

        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(35))
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        let expired = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 1))
        let candidate = try await candidate(expired, wallet: wallet)
        await wallet.setPage(
            offset: 0,
            result: try page(total: 101, candidates: Array(repeating: candidate, count: 100))
        )
        await wallet.setPage(
            offset: 100,
            result: try WalletListOutputsResult(totalOutputs: 101, beef: nil, outputs: [])
        )
        _ = token // keep the requested scope independently valid; no candidate may authorize it.
        await assertRepositoryError(.paginationDidNotProgress(offset: 100)) {
            try await self.repository(wallet: wallet).findCovering(
                .basketAccess(try self.dbapScope()), nowUnixTime: 2
            )
        }
    }

    func testHostileTotalIsRejectedAfterOneRequest() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(41))
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        await wallet.setPage(
            offset: 0,
            result: try await page(total: .max, tokens: [token], wallet: wallet)
        )

        await assertRepositoryError(
            .candidateLimitExceeded(total: UInt64(UInt32.max), maximum: 10_000)
        ) {
            try await self.repository(wallet: wallet).findCovering(
                .basketAccess(try self.dbapScope()), nowUnixTime: 1
            )
        }
        let requestCount = await wallet.recordedRequestCount()
        XCTAssertEqual(requestCount, 1)
    }

    func testCreateRenewAndRevokeUseNarrowAccountBoundMutations() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(42))
        let scope = try dbapScope()
        let expired = PermissionToken.dbap(try .init(scope: scope, expiry: 10))
        let replacement = PermissionToken.dbap(try .init(scope: scope, expiry: 0))
        let expiredCandidate = try await candidate(expired, wallet: wallet)
        await wallet.setPage(
            offset: 0,
            result: try page(total: 1, candidates: [expiredCandidate])
        )
        let repository = try repository(wallet: wallet)

        _ = try await repository.create(replacement)
        _ = try await repository.renew(
            .basketAccess(scope), with: replacement, nowUnixTime: 100
        )
        let renewalMutations = await wallet.recordedMutations()
        let renewable = try XCTUnwrap(renewalMutations.last?.consumed.first)
        _ = try await repository.revoke(renewable)

        let mutations = await wallet.recordedMutations()
        XCTAssertEqual(mutations.count, 3)
        XCTAssertTrue(mutations[0].consumed.isEmpty)
        XCTAssertEqual(mutations[0].created, [replacement])
        XCTAssertEqual(mutations[1].consumed.map(\.token), [expired])
        XCTAssertEqual(mutations[1].created, [replacement])
        XCTAssertEqual(mutations[2].consumed.map(\.token), [expired])
        XCTAssertTrue(mutations[2].created.isEmpty)
        XCTAssertTrue(mutations.allSatisfy { $0.accountID == repositoryTestAccountID })
    }

    func testRenewalRequiresExactDCAPFieldsEvenWhenSubsetWouldAuthorize() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(43))
        let originator = try CanonicalOriginator("example.com")
        let verifier = CanonicalCounterparty(publicKey: try testKey(44))
        let broad = CertificatePermissionScope(
            originator: originator,
            privileged: false,
            certificateType: "identity",
            verifier: verifier,
            fields: ["email", "name"]
        )
        let narrow = CertificatePermissionScope(
            originator: originator,
            privileged: false,
            certificateType: "identity",
            verifier: verifier,
            fields: ["name"]
        )
        let broadToken = PermissionToken.dcap(try .init(scope: broad, expiry: 1))
        let narrowReplacement = PermissionToken.dcap(try .init(scope: narrow, expiry: 0))
        await wallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [broadToken], wallet: wallet)
        )

        do {
            _ = try await repository(wallet: wallet).renew(
                .certificateAccess(narrow),
                with: narrowReplacement,
                nowUnixTime: 2
            )
            XCTFail("subset coverage must not select a different grant for renewal")
        } catch let error as PermissionTokenMutationError {
            XCTAssertEqual(error, .noRenewalCandidate)
        }
        let mutations = await wallet.recordedMutations()
        XCTAssertTrue(mutations.isEmpty)
    }

    func testDSAPCannotUseExpiryRenewalToEscalateItsAmount() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(48))
        let scope = SpendingPermissionScope(originator: try CanonicalOriginator("example.com"))
        let replacement = PermissionToken.dsap(.init(
            scope: scope, authorizedAmount: UInt64.max
        ))

        do {
            _ = try await repository(wallet: wallet).renew(
                .spendingAuthorization(scope),
                with: replacement,
                nowUnixTime: 1
            )
            XCTFail("DSAP amount changes require a new explicit grant")
        } catch let error as PermissionTokenMutationError {
            XCTAssertEqual(error, .renewalNotSupported)
        }
        let mutations = await wallet.recordedMutations()
        XCTAssertTrue(mutations.isEmpty)
    }

    func testMatchRetainsOnlyItsExactSourceGraphFromAMultiCandidatePage() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(45))
        let requested = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        let unrelated = PermissionToken.dbap(try .init(
            scope: .init(
                originator: try CanonicalOriginator("other.example"), basket: "payments"
            ),
            expiry: 0
        ))
        await wallet.setPage(
            offset: 0,
            result: try await page(total: 2, tokens: [unrelated, requested], wallet: wallet)
        )

        let found = try await repository(wallet: wallet).findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        let match = try XCTUnwrap(found)

        XCTAssertEqual(match.sourceBEEF.transactions.count, 1)
        XCTAssertNotNil(try match.sourceBEEF.transaction(
            for: match.outpoint.transactionID,
            limits: PermissionTokenRepository.standardTransactionLimits
        ))
    }

    func testConflictingMerkleRootsInExactSourceFailClosed() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(49))
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        let value = try await candidate(token, wallet: wallet)
        let transactionID = value.output.outpoint.transactionID
        let transactionHash = try Hash256(transactionID.wireBytes)
        let first = try MerklePath(
            blockHeight: 900_003,
            levels: [[.hash(offset: 0, hash: transactionHash, isTransactionID: true)]]
        )
        let conflicting = try MerklePath(
            blockHeight: 900_003,
            levels: [[
                .hash(offset: 0, hash: transactionHash, isTransactionID: true),
                .hash(
                    offset: 1,
                    hash: try Hash256([UInt8](repeating: 0xa5, count: 32)),
                    isTransactionID: false
                ),
            ]]
        )
        let graph = try BEEF(
            merklePaths: [first, conflicting],
            transactions: [.rawWithMerklePath(
                transaction: value.transaction, merklePathIndex: 0
            )],
            limits: PermissionTokenRepository.standardBEEFLimits
        )
        await wallet.setPage(offset: 0, result: try WalletListOutputsResult(
            totalOutputs: 1,
            beef: graph,
            outputs: [value.output]
        ))

        await assertUntrustworthy {
            try await self.repository(wallet: wallet).findCovering(
                .basketAccess(try self.dbapScope()), nowUnixTime: 1
            )
        }
    }

    func testOverlappingRevokesOfSameOutpointCannotBothCommit() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(46))
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        await wallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [token], wallet: wallet)
        )
        let repository = try repository(wallet: wallet)
        let found = try await repository.findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        let match = try XCTUnwrap(found)
        let gate = AsyncRepositoryGate()
        await wallet.setMutationGate(gate)
        let first = Task { try await repository.revoke(match) }
        await gate.waitUntilEntered()

        do {
            _ = try await repository.revoke(match)
            XCTFail("same outpoint cannot be reserved twice")
        } catch let error as PermissionTokenMutationError {
            XCTAssertEqual(error, .mutationInFlight(outpoint: match.outpoint))
        }
        await gate.release()
        _ = try await first.value
        let mutationCount = await wallet.mutationCount()
        XCTAssertEqual(mutationCount, 1)
    }

    func testSuccessfulMutationInvalidatesAnOlderInFlightLookup() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(47))
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        await wallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [token], wallet: wallet)
        )
        let repository = try repository(wallet: wallet)
        let found = try await repository.findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        let match = try XCTUnwrap(found)
        let gate = AsyncRepositoryGate()
        await wallet.setGate(gate, offset: 0)
        let requestedScope = try dbapScope()
        let staleLookup = Task {
            try await repository.findCovering(
                .basketAccess(requestedScope), nowUnixTime: 1
            )
        }
        await gate.waitUntilEntered()
        _ = try await repository.revoke(match)
        await gate.release()

        await assertRepositoryError(.invalidated) { try await staleLookup.value }
    }

    func testUncertainMutationFailureInvalidatesAnOlderInFlightLookup() async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(50))
        let token = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 0))
        await wallet.setPage(
            offset: 0,
            result: try await page(total: 1, tokens: [token], wallet: wallet)
        )
        let repository = try repository(wallet: wallet)
        let found = try await repository.findCovering(
            .basketAccess(try dbapScope()), nowUnixTime: 1
        )
        let match = try XCTUnwrap(found)
        let gate = AsyncRepositoryGate()
        await wallet.setGate(gate, offset: 0)
        await wallet.setMutationFailure(true)
        let requestedScope = try dbapScope()
        let staleLookup = Task {
            try await repository.findCovering(
                .basketAccess(requestedScope), nowUnixTime: 1
            )
        }
        await gate.waitUntilEntered()

        do {
            _ = try await repository.revoke(match)
            XCTFail("the simulated lost process response must be returned")
        } catch let error as RepositoryMutationFailure {
            XCTAssertEqual(error, .responseLostAfterCommit)
        }
        await gate.release()

        await assertRepositoryError(.invalidated) { try await staleLookup.value }
    }

    private func assertInterruptedLookup(invalidate: Bool) async throws {
        let wallet = RepositoryTestWallet(rootKey: try testPrivateKey(invalidate ? 36 : 37))
        let expired = PermissionToken.dbap(try .init(scope: try dbapScope(), expiry: 1))
        let firstCandidate = try await candidate(expired, wallet: wallet)
        await wallet.setPage(
            offset: 0,
            result: try page(
                total: 101,
                candidates: Array(repeating: firstCandidate, count: 100)
            )
        )
        await wallet.setPage(
            offset: 100,
            result: try WalletListOutputsResult(totalOutputs: 101, beef: nil, outputs: [])
        )
        let gate = AsyncRepositoryGate()
        await wallet.setGate(gate, offset: 100)
        let repository = try repository(wallet: wallet)
        let requestedScope = try dbapScope()
        let task = Task {
            try await repository.findCovering(.basketAccess(requestedScope), nowUnixTime: 2)
        }
        await gate.waitUntilEntered()
        if invalidate {
            await repository.invalidate()
        } else {
            task.cancel()
        }
        await gate.release()
        do {
            _ = try await task.value
            XCTFail("Expected interrupted lookup")
        } catch is CancellationError where !invalidate {
            // Expected.
        } catch let error as PermissionTokenRepositoryError where invalidate {
            XCTAssertEqual(error, .invalidated)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    private func dbapScope() throws -> BasketPermissionScope {
        .init(originator: try CanonicalOriginator("example.com"), basket: "payments")
    }

    private func repository(wallet: RepositoryTestWallet) throws -> PermissionTokenRepository {
        PermissionTokenRepository(wallet: wallet)
    }
}

private struct RepositoryCandidate: Sendable {
    let output: WalletOutput
    let transaction: Transaction
}

private func candidate(
    _ token: PermissionToken,
    wallet: RepositoryTestWallet,
    spendable: Bool = true,
    satoshis: UInt64 = 1
) async throws -> RepositoryCandidate {
    let script = try await PermissionTokenCodec.encode(token, using: wallet)
    let transaction = Transaction(outputs: [TransactionOutput(
        satoshis: satoshis,
        lockingScript: script
    )])
    let transactionID = try transaction.transactionID(
        limits: PermissionTokenRepository.standardTransactionLimits
    )
    return RepositoryCandidate(
        output: try WalletOutput(
            satoshis: satoshis,
            lockingScript: script.bytes,
            spendable: spendable,
            tags: [],
            outpoint: Outpoint(transactionID: transactionID, outputIndex: 0)
        ),
        transaction: transaction
    )
}

private func page(
    total: UInt32,
    tokens: [PermissionToken],
    wallet: RepositoryTestWallet
) async throws -> WalletListOutputsResult {
    var candidates = [RepositoryCandidate]()
    for token in tokens {
        candidates.append(try await candidate(token, wallet: wallet))
    }
    return try page(total: total, candidates: candidates)
}

private func page(
    total: UInt32,
    candidates: [RepositoryCandidate]
) throws -> WalletListOutputsResult {
    try WalletListOutputsResult(
        totalOutputs: total,
        beef: try beef(candidates.map(\.transaction).uniqued()),
        outputs: candidates.map(\.output)
    )
}

private func beef(_ transactions: [Transaction]) throws -> BEEF {
    let transactionLimits = PermissionTokenRepository.standardTransactionLimits
    let merkleLimits = try MerklePathLimits(
        maximumByteCount: 1 << 20,
        maximumLeavesPerLevel: 100_000,
        maximumTotalLeaves: 1_000_000
    )
    let limits = try BEEFLimits(
        maximumByteCount: 8 << 20,
        maximumMerklePathCount: 10_000,
        maximumTransactionCount: 10_000,
        transactionLimits: transactionLimits,
        merklePathLimits: merkleLimits
    )
    return try BEEF(
        version: .v2,
        merklePaths: [],
        transactions: transactions.map(BEEFTransaction.raw),
        limits: limits
    )
}

private extension Array where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}

private actor AsyncRepositoryGate {
    private var entered = false
    private var released = false
    private var entryWaiters = [CheckedContinuation<Void, Never>]()
    private var releaseWaiters = [CheckedContinuation<Void, Never>]()

    func wait() async {
        entered = true
        let entries = entryWaiters
        entryWaiters.removeAll()
        entries.forEach { $0.resume() }
        guard !released else { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
}

private actor RepositoryTestWallet: PermissionTokenWallet {
    nonisolated let protoWallet: ProtoWallet
    nonisolated let permissionAccountID: PermissionAccountID
    private var pages = [UInt32: WalletListOutputsResult]()
    private var requests = [WalletListOutputsRequest]()
    private var gates = [UInt32: AsyncRepositoryGate]()
    private var mutations = [PermissionTokenMutationRequest]()
    private var mutationGate: AsyncRepositoryGate?
    private var mutationFailsAfterRecording = false

    init(rootKey: PrivateKey, accountID: PermissionAccountID = repositoryTestAccountID) {
        protoWallet = ProtoWallet(rootKey: rootKey)
        permissionAccountID = accountID
    }

    func setPage(offset: UInt32, result: WalletListOutputsResult) {
        pages[offset] = result
    }

    func setGate(_ gate: AsyncRepositoryGate, offset: UInt32) {
        gates[offset] = gate
    }
    func setMutationGate(_ gate: AsyncRepositoryGate?) { mutationGate = gate }
    func setMutationFailure(_ enabled: Bool) { mutationFailsAfterRecording = enabled }

    func recordedRequests() -> [WalletListOutputsRequest] { requests }
    func recordedRequestCount() -> Int { requests.count }
    func recordedMutations() -> [PermissionTokenMutationRequest] { mutations }
    func mutationCount() -> Int { mutations.count }

    func listPermissionTokenOutputs(
        _ request: WalletListOutputsRequest
    ) async throws -> WalletListOutputsResult {
        requests.append(request)
        let offset = request.pagination.effectiveOffset
        if let gate = gates[offset] { await gate.wait() }
        try Task.checkCancellation()
        if let result = pages[offset] { return result }
        return try WalletListOutputsResult(totalOutputs: 0, outputs: [])
    }

    func commitPermissionTokenMutation(
        _ request: PermissionTokenMutationRequest
    ) async throws -> PermissionTokenMutationResult {
        if let mutationGate { await mutationGate.wait() }
        mutations.append(request)
        if mutationFailsAfterRecording {
            throw RepositoryMutationFailure.responseLostAfterCommit
        }
        return PermissionTokenMutationResult(
            transactionID: try TransactionID(
                displayHex: String(repeating: "01", count: 32)
            ),
            reference: "cmVm"
        )
    }

    nonisolated func getPublicKey(
        _ request: WalletGetPublicKeyRequest
    ) async throws -> WalletGetPublicKeyResult {
        try await protoWallet.getPublicKey(request)
    }

    nonisolated func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult {
        try await protoWallet.encrypt(request)
    }

    nonisolated func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult {
        try await protoWallet.decrypt(request)
    }

    nonisolated func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        try await protoWallet.createSignature(request)
    }

    nonisolated func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        try await protoWallet.verifySignature(request)
    }
}

private enum RepositoryMutationFailure: Error, Equatable {
    case responseLostAfterCommit
}

private let repositoryTestAccountID = try! PermissionAccountID("account")

private func assertRepositoryError<T>(
    _ expected: PermissionTokenRepositoryError,
    operation: () async throws -> T
) async {
    do {
        _ = try await operation()
        XCTFail("Expected \(expected)")
    } catch let error as PermissionTokenRepositoryError {
        XCTAssertEqual(error, expected)
    } catch {
        XCTFail("Unexpected error: \(error)")
    }
}

private func assertUntrustworthy<T>(operation: () async throws -> T) async {
    do {
        _ = try await operation()
        XCTFail("Expected untrustworthy BEEF")
    } catch PermissionTokenRepositoryError.untrustworthyBEEF {
        // Expected.
    } catch {
        XCTFail("Unexpected error: \(error)")
    }
}
