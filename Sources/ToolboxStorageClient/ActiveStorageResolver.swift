import Foundation
import ToolboxStorage

/// Where a wallet's active storage is, read from the stores themselves.
public enum ActiveStorageResolution: Sendable {
    /// The store whose user record names itself, the only one that takes writes. When the record
    /// names no store at all, this is the store that was read, and writes there are refused.
    case active(StorageClient)
    /// The records lead to a store none of the candidate addresses reach: another wallet using
    /// these keys moved the account there. The store that was read takes no writes until the
    /// moved-to store's address is supplied.
    ///
    /// `unreachable` lists candidates that could not be read, any of which may have been the
    /// moved-to store: when it isn't empty, trying again may find it without asking the user.
    case moved(storageIdentityKey: String, unreachable: [URL])
    /// The records don't settle on one store: two name each other, or a store they lead to names
    /// none. No store takes writes; the account has to be made active on one store from a wallet
    /// that runs the full sync (the web wallet or the CLI).
    case unsettled(reason: String)
}

/// Follows the user's `activeStorage` record from one store to the store it names.
///
/// One store is active for a set of keys; every other syncs through it. The TypeScript
/// `WalletStorageManager` picks it in `makeAvailable` (`selectActiveFromStore`): the store whose
/// user record names its own `storageIdentityKey`. When a wallet using the same keys moves the
/// account (`setActive`), the old store's record is rewritten to name the new one. A wallet that
/// still opens the old store must follow that record rather than write there or claim it back;
/// either would leave two copies of the wallet that diverge.
///
/// The record holds a storage identity key, not an address, so the next store can only be
/// reached when one of `candidates` turns out to be it. When none does, the result is
/// `.moved`, and the caller asks the user for the address the other wallet uses.
///
/// A candidate's `storageIdentityKey` is what that server reports in `makeAvailable`. A server
/// the user enters is trusted to report its own key, as the TypeScript manager trusts it.
public enum ActiveStorageResolver {

    /// Follows the records from `start`.
    ///
    /// - Parameters:
    ///   - start: the store this wallet is configured to use. It is returned as is when its own
    ///     record names it, so an unmoved wallet costs one user read.
    ///   - candidates: other addresses the account may have been moved to, such as a chain's
    ///     default storage and a host saved for the account. An unreachable one is skipped.
    ///   - identityKey: the user's identity key.
    ///   - connect: builds a client for a candidate address.
    /// - Throws: when `start` itself can't be read, or the task is cancelled. A candidate that
    ///   can't be read is skipped and listed in `.moved`.
    public static func resolve(
        from start: StorageClient,
        candidates: [URL],
        identityKey: String,
        connect: @Sendable (URL) async throws -> StorageClient
    ) async throws -> ActiveStorageResolution {
        let auth = AuthID(identityKey: identityKey)
        var current = start
        var visited: Set<String> = []
        var candidateKeys: [String: (client: StorageClient, key: String)] = [:]
        var unreachable: [URL] = []

        for _ in 0..<16 {
            let settings = try await current.makeAvailable(auth)
            visited.insert(settings.storageIdentityKey)
            let user = try await current.findOrInsertUser(identityKey)
            // TS treats an empty `activeStorage` as none, like a missing one.
            let record = user.activeStorage.flatMap { $0.isEmpty ? nil : $0 }
            guard let named = record else {
                // The configured store with no record of an active store stays as it is, and its
                // writes are refused. A store the records led to must name itself to be active.
                if current === start { return .active(current) }
                return .unsettled(reason:
                    "\(current.endpoint.absoluteString) is named as active but names no active storage")
            }
            if named == settings.storageIdentityKey { return .active(current) }
            // A switch that stopped halfway can leave two records naming each other.
            guard !visited.contains(named) else {
                return .unsettled(reason:
                    "the records of \(current.endpoint.absoluteString) and \(named) name each other")
            }
            var next: StorageClient?
            for url in candidates {
                let place = endpointKey(url)
                guard place != endpointKey(current.endpoint),
                      !unreachable.contains(where: { endpointKey($0) == place }) else { continue }
                if let known = candidateKeys[place] {
                    if known.key == named { next = known.client; break }
                    continue
                }
                do {
                    let client = try await connect(url)
                    let key = try await client.makeAvailable(auth).storageIdentityKey
                    candidateKeys[place] = (client, key)
                    if key == named { next = client; break }
                } catch {
                    // A cancelled open is not a move; let the caller see it.
                    if error is CancellationError || Task.isCancelled { throw error }
                    StorageClient.log(
                        "active storage: candidate \(url.absoluteString) unreachable, skipped: \(error)"
                    )
                    unreachable.append(url)
                }
            }
            guard let next else {
                StorageClient.log(
                    "active storage: \(current.endpoint.absoluteString) names \(named), which no known address reaches"
                )
                return .moved(storageIdentityKey: named, unreachable: unreachable)
            }
            StorageClient.log(
                "active storage: following \(current.endpoint.absoluteString) to \(next.endpoint.absoluteString)"
            )
            current = next
        }
        return .unsettled(reason: "the records lead through more stores than any real chain of moves")
    }

    /// An address compared without its trailing slash or letter case of the host, so the same
    /// store written two ways is connected once.
    static func endpointKey(_ url: URL) -> String {
        var text = url.absoluteString
        while text.hasSuffix("/") { text.removeLast() }
        guard var parts = URLComponents(string: text) else { return text }
        parts.scheme = parts.scheme?.lowercased()
        parts.host = parts.host?.lowercased()
        return parts.string ?? text
    }
}
