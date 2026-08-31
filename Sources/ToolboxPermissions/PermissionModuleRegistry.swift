import Foundation
import BSVWallet

/// A host-defined permission scheme identifier.
///
/// BRC-98, BRC-99, and BRC-111 reserve the second token after `p ` as a
/// space-free scheme identifier. The toolbox does not assign meaning to it.
public struct PermissionModuleScheme: Hashable, Codable, Sendable {
    public let rawValue: String

    public init(rawValue: String) throws {
        let bytes = Array(rawValue.utf8)
        guard (2...30).contains(bytes.count),
              let first = bytes.first,
              (97...122).contains(first),
              bytes.dropFirst().allSatisfy({ (97...122).contains($0) || (48...57).contains($0) }) else {
            throw PermissionModuleRegistryError.invalidScheme
        }
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// Immutable input delivered to a registered permission module.
///
/// `argumentsJSON` is the canonical BRC-100 JSON encoding of the exact typed
/// request. `canonicalDecision` is the BRC-116 classifier result for that same
/// request. A module can explain or veto the request, but it cannot replace
/// either value or produce a permission grant.
public struct PermissionModuleRequest: Hashable, Codable, Sendable {
    public let invocationID: UUID
    public let scheme: PermissionModuleScheme
    public let method: String
    public let originator: CanonicalOriginator
    public let argumentsJSON: Data
    public let canonicalDecision: PermissionDecision

    fileprivate init(
        invocationID: UUID,
        scheme: PermissionModuleScheme,
        request: WalletRequest,
        originator: CanonicalOriginator,
        canonicalDecision: PermissionDecision,
        codec: WalletBRC100JSONCodec
    ) throws {
        self.invocationID = invocationID
        self.scheme = scheme
        self.method = request.call.jsonMethodName
        self.originator = originator
        self.argumentsJSON = Data(try codec.encodeRequest(request))
        self.canonicalDecision = canonicalDecision
    }
}

/// A module may add opaque, serializable review data for its host UI.
/// Continuing only means the module did not veto; BRC-116 authorization must
/// still be satisfied by the host before it calls the protected wallet.
public struct PermissionModuleReview: Hashable, Codable, Sendable {
    public enum Decision: String, Hashable, Codable, Sendable {
        case continueAuthorization
        case deny
    }

    public let decision: Decision
    public let serializedReview: Data?

    public init(decision: Decision, serializedReview: Data? = nil) {
        self.decision = decision
        self.serializedReview = serializedReview
    }
}

public protocol PermissionModuleHandling: Sendable {
    func review(_ request: PermissionModuleRequest) async throws -> PermissionModuleReview
}

/// Closure adapter for hosts that do not need a named handler type.
public struct AnyPermissionModuleHandler: PermissionModuleHandling, Sendable {
    private let body: @Sendable (PermissionModuleRequest) async throws -> PermissionModuleReview

    public init(
        _ body: @escaping @Sendable (PermissionModuleRequest) async throws -> PermissionModuleReview
    ) {
        self.body = body
    }

    public func review(_ request: PermissionModuleRequest) async throws -> PermissionModuleReview {
        try await body(request)
    }
}

public enum PermissionModuleDispatchResult: Hashable, Codable, Sendable {
    /// No module was registered. The caller retains its existing BRC-116 flow.
    case noHandler
    /// The module did not veto. This is not a permission grant.
    case reviewed(PermissionModuleReview)
}

public enum PermissionModuleRegistryError: Error, Equatable, Sendable {
    public static let permissionDeniedMessage = "Permission denied."

    case invalidScheme
    case duplicateScheme
    case invalidTimeout
    /// Stable denial contract. Handler details are deliberately not exposed.
    case permissionDenied
}

/// Protocol-neutral, veto-only permission-module registry.
///
/// This actor intentionally does not call a wallet and does not own permission
/// tokens. A host performs this preflight before its protected wallet call and
/// separately enforces the unchanged `PermissionDecision` through BRC-116.
public actor PermissionModuleRegistry {
    private enum RaceResult: Sendable {
        case reviewed(PermissionModuleReview)
        case denied
        case cancelled
    }

    private struct InFlight: Sendable {
        let scheme: PermissionModuleScheme
        let handlerTask: Task<Void, Never>
        let timeoutTask: Task<Void, Never>
        let gate: FirstPermissionModuleResult

        func cancel() {
            handlerTask.cancel()
            timeoutTask.cancel()
            Task { await gate.resolve(.cancelled) }
        }
    }

    private let timeout: Duration
    private var handlers: [PermissionModuleScheme: any PermissionModuleHandling] = [:]
    private var inFlight: [UUID: InFlight] = [:]

    public init(timeout: Duration = .seconds(2)) throws {
        guard timeout > .zero else { throw PermissionModuleRegistryError.invalidTimeout }
        self.timeout = timeout
    }

    public func register(
        _ handler: any PermissionModuleHandling,
        for scheme: PermissionModuleScheme
    ) throws {
        guard handlers[scheme] == nil else { throw PermissionModuleRegistryError.duplicateScheme }
        handlers[scheme] = handler
    }

    public func isRegistered(_ scheme: PermissionModuleScheme) -> Bool {
        handlers[scheme] != nil
    }

    /// Removing a handler cancels all of its current reviews. Cancellation is
    /// lifecycle state, not module denial, so waiting callers receive
    /// `CancellationError` and must not invoke the wallet.
    public func removeHandler(for scheme: PermissionModuleScheme) {
        handlers.removeValue(forKey: scheme)
        let matching = inFlight.filter { $0.value.scheme == scheme }
        for (invocationID, entry) in matching {
            inFlight.removeValue(forKey: invocationID)
            entry.cancel()
        }
    }

    /// Cancels every current review without removing registered handlers.
    public func cancelAll() {
        let current = Array(inFlight.values)
        inFlight.removeAll()
        for entry in current { entry.cancel() }
    }

    /// Runs one registered module review without changing the canonical
    /// authorization result. No handler means no change to existing behavior.
    public func dispatch(
        scheme: PermissionModuleScheme,
        request: WalletRequest,
        originator rawOriginator: String,
        canonicalDecision: PermissionDecision,
        codec: WalletBRC100JSONCodec
    ) async throws -> PermissionModuleDispatchResult {
        if case .denied = canonicalDecision {
            throw PermissionModuleRegistryError.permissionDenied
        }
        guard let handler = handlers[scheme] else { return .noHandler }

        let originator: CanonicalOriginator
        do { originator = try CanonicalOriginator(rawOriginator) }
        catch { throw PermissionModuleRegistryError.permissionDenied }

        let invocationID = UUID()
        let moduleRequest: PermissionModuleRequest
        do {
            moduleRequest = try PermissionModuleRequest(
                invocationID: invocationID,
                scheme: scheme,
                request: request,
                originator: originator,
                canonicalDecision: canonicalDecision,
                codec: codec
            )
        } catch {
            throw PermissionModuleRegistryError.permissionDenied
        }

        let gate = FirstPermissionModuleResult()
        let handlerTask = Task {
            do {
                let review = try await handler.review(moduleRequest)
                await gate.resolve(review.decision == .deny ? .denied : .reviewed(review))
            } catch is CancellationError {
                await gate.resolve(Task.isCancelled ? .cancelled : .denied)
            } catch {
                await gate.resolve(.denied)
            }
        }
        let timeout = self.timeout
        let timeoutTask = Task {
            do {
                try await Task.sleep(for: timeout)
                await gate.resolve(.denied)
            } catch {
                // The winning path cancels this task.
            }
        }
        let entry = InFlight(
            scheme: scheme,
            handlerTask: handlerTask,
            timeoutTask: timeoutTask,
            gate: gate
        )
        inFlight[invocationID] = entry
        defer {
            inFlight.removeValue(forKey: invocationID)
            handlerTask.cancel()
            timeoutTask.cancel()
        }

        let result = await withTaskCancellationHandler {
            await gate.wait()
        } onCancel: {
            entry.cancel()
        }
        guard !Task.isCancelled, inFlight[invocationID] != nil else {
            throw CancellationError()
        }
        switch result {
        case .reviewed(let review): return .reviewed(review)
        case .denied: throw PermissionModuleRegistryError.permissionDenied
        case .cancelled: throw CancellationError()
        }
    }

    private actor FirstPermissionModuleResult {
        private var result: RaceResult?
        private var continuation: CheckedContinuation<RaceResult, Never>?

        func wait() async -> RaceResult {
            if let result { return result }
            return await withCheckedContinuation { continuation = $0 }
        }

        func resolve(_ newResult: RaceResult) {
            guard result == nil else { return }
            result = newResult
            continuation?.resume(returning: newResult)
            continuation = nil
        }
    }
}
