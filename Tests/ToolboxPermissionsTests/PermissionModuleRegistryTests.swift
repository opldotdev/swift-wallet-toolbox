import Foundation
import XCTest
import BSVTransaction
import BSVWallet
@testable import ToolboxPermissions

final class PermissionModuleRegistryTests: XCTestCase {
    func testDispatchBindsSchemeMethodCanonicalOriginArgumentsAndAuthorizationEffects() async throws {
        let codec = try makeCodec()
        let scheme = try PermissionModuleScheme(rawValue: "assets")
        let request = try listOutputsRequest(basket: "inventory")
        let decision = PermissionDecision.authorizationRequired(.init(requirements: [
            .init(
                scope: .basketAccess(.init(
                    originator: try CanonicalOriginator("app.example"),
                    basket: "inventory"
                )),
                usage: .basketListing,
                whenMissing: .promptUser
            ),
        ]))
        let recorder = RequestRecorder()
        let registry = try PermissionModuleRegistry()
        try await registry.register(AnyPermissionModuleHandler { received in
            await recorder.append(received)
            return .init(
                decision: .continueAuthorization,
                serializedReview: Data("review".utf8)
            )
        }, for: scheme)

        let result = try await registry.dispatch(
            scheme: scheme,
            request: request,
            originator: "HTTPS://App.Example:443/path",
            canonicalDecision: decision,
            codec: codec
        )

        XCTAssertEqual(
            result,
            .reviewed(.init(
                decision: .continueAuthorization,
                serializedReview: Data("review".utf8)
            ))
        )
        let recordedRequests = await recorder.requests
        let received = try XCTUnwrap(recordedRequests.single)
        XCTAssertEqual(received.scheme, scheme)
        XCTAssertEqual(received.method, "listOutputs")
        XCTAssertEqual(received.originator, try CanonicalOriginator("app.example"))
        XCTAssertEqual(received.argumentsJSON, Data(try codec.encodeRequest(request)))
        XCTAssertEqual(received.canonicalDecision, decision)
        XCTAssertEqual(
            try JSONDecoder().decode(
                PermissionModuleRequest.self,
                from: JSONEncoder().encode(received)
            ),
            received
        )
    }

    func testNoHandlerLeavesExistingClassificationUntouched() async throws {
        let registry = try PermissionModuleRegistry()
        let result = try await registry.dispatch(
            scheme: try .init(rawValue: "notinstalled"),
            request: try listOutputsRequest(),
            originator: "app.example",
            canonicalDecision: .authenticatedPassThrough,
            codec: try makeCodec()
        )
        XCTAssertEqual(result, .noHandler)
    }

    func testDenialAndHandlerErrorUseStablePermissionDeniedContract() async throws {
        enum TestFailure: Error { case failed }
        let scheme = try PermissionModuleScheme(rawValue: "assets")
        for handler in [
            AnyPermissionModuleHandler { _ in .init(decision: .deny) },
            AnyPermissionModuleHandler { _ in throw TestFailure.failed },
        ] {
            let registry = try PermissionModuleRegistry()
            try await registry.register(handler, for: scheme)
            await XCTAssertThrowsPermissionDenied {
                _ = try await registry.dispatch(
                    scheme: scheme,
                    request: try self.listOutputsRequest(),
                    originator: "app.example",
                    canonicalDecision: .authenticatedPassThrough,
                    codec: try self.makeCodec()
                )
            }
        }
        XCTAssertEqual(
            PermissionModuleRegistryError.permissionDeniedMessage,
            "Permission denied."
        )
    }

    func testTimeoutReturnsPromptlyEvenWhenHandlerIgnoresCancellation() async throws {
        let scheme = try PermissionModuleScheme(rawValue: "slow")
        let registry = try PermissionModuleRegistry(timeout: .milliseconds(30))
        try await registry.register(AnyPermissionModuleHandler { _ in
            let clock = ContinuousClock()
            let deadline = clock.now.advanced(by: .milliseconds(250))
            while clock.now < deadline {
                do { try await Task.sleep(for: .milliseconds(10)) }
                catch { /* Deliberately ignore cancellation. */ }
            }
            return .init(decision: .continueAuthorization)
        }, for: scheme)

        let clock = ContinuousClock()
        let start = clock.now
        await XCTAssertThrowsPermissionDenied {
            _ = try await registry.dispatch(
                scheme: scheme,
                request: try self.listOutputsRequest(),
                originator: "app.example",
                canonicalDecision: .authenticatedPassThrough,
                codec: try self.makeCodec()
            )
        }
        XCTAssertLessThan(start.duration(to: clock.now), .milliseconds(150))
    }

    func testCallerCancellationCancelsReviewAndNeverHangs() async throws {
        let scheme = try PermissionModuleScheme(rawValue: "cancel")
        let started = AsyncSignal()
        let registry = try PermissionModuleRegistry(timeout: .seconds(2))
        try await registry.register(AnyPermissionModuleHandler { _ in
            await started.signal()
            try await Task.sleep(for: .seconds(10))
            return .init(decision: .continueAuthorization)
        }, for: scheme)

        let request = try listOutputsRequest()
        let codec = try makeCodec()
        let task = Task {
            try await registry.dispatch(
                scheme: scheme,
                request: request,
                originator: "app.example",
                canonicalDecision: .authenticatedPassThrough,
                codec: codec
            )
        }
        await started.wait()
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("cancelled dispatch unexpectedly succeeded")
        } catch is CancellationError {
            // Expected.
        }
    }

    func testRemovingHandlerCancelsItsInflightLifecycle() async throws {
        let scheme = try PermissionModuleScheme(rawValue: "remove")
        let started = AsyncSignal()
        let registry = try PermissionModuleRegistry(timeout: .seconds(2))
        try await registry.register(AnyPermissionModuleHandler { _ in
            await started.signal()
            try await Task.sleep(for: .seconds(10))
            return .init(decision: .continueAuthorization)
        }, for: scheme)
        let request = try listOutputsRequest()
        let codec = try makeCodec()
        let task = Task {
            try await registry.dispatch(
                scheme: scheme,
                request: request,
                originator: "app.example",
                canonicalDecision: .authenticatedPassThrough,
                codec: codec
            )
        }
        await started.wait()
        await registry.removeHandler(for: scheme)
        do {
            _ = try await task.value
            XCTFail("removed handler unexpectedly completed")
        } catch is CancellationError {
            // Expected.
        }
        let remainsRegistered = await registry.isRegistered(scheme)
        XCTAssertFalse(remainsRegistered)
    }

    func testHandlerCanReenterRegistryWithoutDeadlock() async throws {
        let scheme = try PermissionModuleScheme(rawValue: "reentrant")
        let registry = try PermissionModuleRegistry(timeout: .seconds(1))
        try await registry.register(AnyPermissionModuleHandler { _ in
            guard await registry.isRegistered(scheme) else {
                return .init(decision: .deny)
            }
            return .init(decision: .continueAuthorization)
        }, for: scheme)

        let result = try await registry.dispatch(
            scheme: scheme,
            request: try listOutputsRequest(),
            originator: "app.example",
            canonicalDecision: .authenticatedPassThrough,
            codec: try makeCodec()
        )
        XCTAssertEqual(result, .reviewed(.init(decision: .continueAuthorization)))
    }

    func testConcurrentOriginsRemainDistinctAndCanonical() async throws {
        let scheme = try PermissionModuleScheme(rawValue: "concurrent")
        let recorder = RequestRecorder()
        let registry = try PermissionModuleRegistry(timeout: .seconds(1))
        try await registry.register(AnyPermissionModuleHandler { request in
            await recorder.append(request)
            try await Task.sleep(for: .milliseconds(10))
            return .init(decision: .continueAuthorization)
        }, for: scheme)

        let firstRequest = try listOutputsRequest()
        let secondRequest = try listOutputsRequest()
        let firstCodec = try makeCodec()
        let secondCodec = try makeCodec()
        async let first = registry.dispatch(
            scheme: scheme,
            request: firstRequest,
            originator: "HTTPS://One.Example:443/path",
            canonicalDecision: .authenticatedPassThrough,
            codec: firstCodec
        )
        async let second = registry.dispatch(
            scheme: scheme,
            request: secondRequest,
            originator: "https://two.example:443/other",
            canonicalDecision: .authenticatedPassThrough,
            codec: secondCodec
        )
        _ = try await (first, second)

        let recordedRequests = await recorder.requests
        XCTAssertEqual(Set(recordedRequests.map(\.originator.rawValue)), ["one.example", "two.example"])
        XCTAssertEqual(Set(recordedRequests.map(\.invocationID)).count, 2)
    }

    func testCanonicalDenialCannotBeReplacedByModuleOrNoHandler() async throws {
        let scheme = try PermissionModuleScheme(rawValue: "assets")
        let recorder = RequestRecorder()
        let registry = try PermissionModuleRegistry()
        try await registry.register(AnyPermissionModuleHandler { request in
            await recorder.append(request)
            return .init(decision: .continueAuthorization)
        }, for: scheme)

        await XCTAssertThrowsPermissionDenied {
            _ = try await registry.dispatch(
                scheme: scheme,
                request: try self.listOutputsRequest(),
                originator: "app.example",
                canonicalDecision: .denied(.reservedBasket("admin")),
                codec: try self.makeCodec()
            )
        }
        let recordedRequests = await recorder.requests
        XCTAssertTrue(recordedRequests.isEmpty)
    }

    func testSchemeAndTimeoutValidationAndDuplicateRegistration() async throws {
        for invalid in [
            "", "a", "Upper", "two words", "has-hyphen", "line\nfeed",
            "a" + String(repeating: "1", count: 30),
        ] {
            XCTAssertThrowsError(try PermissionModuleScheme(rawValue: invalid)) {
                XCTAssertEqual($0 as? PermissionModuleRegistryError, .invalidScheme)
            }
        }
        XCTAssertEqual(
            try PermissionModuleScheme(rawValue: "a" + String(repeating: "1", count: 29)).rawValue.count,
            30
        )
        XCTAssertThrowsError(try PermissionModuleRegistry(timeout: .zero)) {
            XCTAssertEqual($0 as? PermissionModuleRegistryError, .invalidTimeout)
        }
        let scheme = try PermissionModuleScheme(rawValue: "once")
        let handler = AnyPermissionModuleHandler { _ in
            PermissionModuleReview(decision: .continueAuthorization)
        }
        let registry = try PermissionModuleRegistry()
        try await registry.register(handler, for: scheme)
        do {
            try await registry.register(handler, for: scheme)
            XCTFail("duplicate registration unexpectedly succeeded")
        } catch {
            XCTAssertEqual(error as? PermissionModuleRegistryError, .duplicateScheme)
        }
    }

    private func listOutputsRequest(basket: String = "inventory") throws -> WalletRequest {
        .action(.listOutputs(try .init(basket: basket)))
    }

    private func makeCodec() throws -> WalletBRC100JSONCodec {
        try WalletBRC100JSONCodec(beefLimits: BEEFLimits(
            maximumByteCount: 1_000_000,
            maximumMerklePathCount: 100,
            maximumTransactionCount: 1_000,
            transactionLimits: TransactionLimits(
                maximumTransactionByteCount: 100_000,
                maximumInputCount: 100,
                maximumOutputCount: 100,
                maximumScriptByteCount: 10_000
            ),
            merklePathLimits: MerklePathLimits(
                maximumByteCount: 100_000,
                maximumLeavesPerLevel: 100,
                maximumTotalLeaves: 1_000
            )
        ))
    }

    private func XCTAssertThrowsPermissionDenied(
        _ operation: () async throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            try await operation()
            XCTFail("operation unexpectedly succeeded", file: file, line: line)
        } catch {
            XCTAssertEqual(
                error as? PermissionModuleRegistryError,
                .permissionDenied,
                file: file,
                line: line
            )
        }
    }
}

private actor RequestRecorder {
    private(set) var requests: [PermissionModuleRequest] = []
    func append(_ request: PermissionModuleRequest) { requests.append(request) }
}

private actor AsyncSignal {
    private var signaled = false
    private var continuations: [CheckedContinuation<Void, Never>] = []

    func signal() {
        signaled = true
        continuations.forEach { $0.resume() }
        continuations.removeAll()
    }

    func wait() async {
        if signaled { return }
        await withCheckedContinuation { continuations.append($0) }
    }
}

private extension Array {
    var single: Element? { count == 1 ? self[0] : nil }
}
