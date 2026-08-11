import Foundation

/// An ordered list of providers answering the same question.
///
/// The first provider that succeeds wins. This is the Go toolbox's `servicequeue`, and the reason
/// both implementations have one is that a chain service is somebody else's server: it goes down,
/// rate-limits, and returns nonsense, and a wallet that had one of them had no wallet.
///
/// A failure is never swallowed. If every provider fails the caller gets all of the reasons, named
/// by provider, because "the network failed" cannot be acted on and "ARC rejected it, WhatsOnChain
/// timed out" can.
public struct ServiceQueue<Answer: Sendable>: Sendable {
    public struct Provider: Sendable {
        public let name: String
        public let answer: @Sendable () async throws -> Answer

        public init(name: String, answer: @escaping @Sendable () async throws -> Answer) {
            self.name = name
            self.answer = answer
        }
    }

    private let providers: [Provider]

    public init(_ providers: [Provider]) {
        self.providers = providers
    }

    /// Asks each provider in turn and returns the first answer.
    ///
    /// Order is the caller's priority, preserved exactly. Rotating on failure is deliberately not
    /// done here: a queue that reordered itself would make one run's behaviour depend on the last,
    /// which is not something a wallet should do quietly.
    public func resolve() async throws -> Answer {
        guard !providers.isEmpty else {
            throw ServiceError.allProvidersFailed([])
        }
        var failures: [(provider: String, reason: String)] = []
        for provider in providers {
            do {
                return try await provider.answer()
            } catch {
                failures.append((provider: provider.name, reason: String(describing: error)))
            }
        }
        throw ServiceError.allProvidersFailed(failures)
    }
}
