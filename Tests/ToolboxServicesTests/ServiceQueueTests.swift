import XCTest
@testable import ToolboxServices

/// Falling back between chain providers.
///
/// A chain service is somebody else's server. It goes down, rate-limits, and returns nonsense. A
/// wallet with one provider has, on those days, no wallet.
final class ServiceQueueTests: XCTestCase {

    private struct Refusal: Error {}

    private func provider(_ name: String, answers value: Int) -> ServiceQueue<Int>.Provider {
        .init(name: name) { value }
    }

    private func failing(_ name: String) -> ServiceQueue<Int>.Provider {
        .init(name: name) { throw Refusal() }
    }

    func test_theFirstProviderAnswers() async throws {
        let queue = ServiceQueue([provider("arc", answers: 1), provider("woc", answers: 2)])

        let answer = try await queue.resolve()

        XCTAssertEqual(answer, 1)
    }

    func test_aFailingProviderFallsThroughToTheNext() async throws {
        let queue = ServiceQueue([failing("arc"), provider("woc", answers: 2)])

        let answer = try await queue.resolve()

        XCTAssertEqual(answer, 2, "one provider being down is not an outage")
    }

    func test_severalFailuresFallThroughToTheLast() async throws {
        let queue = ServiceQueue([failing("arc"), failing("woc"), provider("bitails", answers: 3)])

        let answer = try await queue.resolve()

        XCTAssertEqual(answer, 3)
    }

    /// The names matter. "The network failed" cannot be acted on; "ARC and WhatsOnChain both
    /// refused" tells somebody where to look.
    func test_everyFailureIsReportedByProviderName() async {
        let queue = ServiceQueue([failing("arc"), failing("woc")])

        do {
            _ = try await queue.resolve()
            XCTFail("a queue where every provider failed must not return an answer")
        } catch let error as ServiceError {
            guard case .allProvidersFailed(let failures) = error else {
                return XCTFail("expected allProvidersFailed, got \(error)")
            }
            XCTAssertEqual(failures.map(\.provider), ["arc", "woc"])
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func test_anEmptyQueueFailsRatherThanHanging() async {
        let queue = ServiceQueue<Int>([])

        do {
            _ = try await queue.resolve()
            XCTFail("an empty queue has no answer to give")
        } catch let error as ServiceError {
            XCTAssertEqual(error, .allProvidersFailed([]))
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    /// A later provider is never consulted once one has answered — these are network calls, and a
    /// queue that asked everybody would cost real requests on every lookup.
    func test_providersAfterTheAnswerAreNotAsked() async throws {
        actor Counter {
            var count = 0
            func increment() { count += 1 }
        }
        let counter = Counter()
        let queue = ServiceQueue([
            provider("arc", answers: 1),
            .init(name: "woc") { await counter.increment(); return 2 },
        ])

        _ = try await queue.resolve()

        let asked = await counter.count
        XCTAssertEqual(asked, 0)
    }
}
