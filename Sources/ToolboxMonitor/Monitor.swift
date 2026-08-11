import Foundation

/// Scheduled background work.
///
/// The TypeScript toolbox runs seventeen tasks; most serve a server deployment that owns its own
/// storage. A remote-first client needs two: send what is waiting, and collect proofs for what was
/// sent. The rest arrive with the deployments that need them.
public protocol MonitorTask: Sendable {
    var name: String { get }
    /// How long to wait between runs.
    var interval: Duration { get }
    func run() async throws
}

public enum MonitorError: Error, Equatable, Sendable {
    case notImplemented(String)
}
