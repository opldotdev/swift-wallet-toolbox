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
    case moved(storageIdentityKey: String)
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
    /// - Throws: when `start` itself can't be read. A candidate that can't be read is skipped.
    public static func resolve(
        from start: StorageClient,
        candidates: [URL],
        identityKey: String,
        connect: @Sendable (URL) async throws -> StorageClient
    ) async throws -> ActiveStorageResolution {
        let auth = AuthID(identityKey: identityKey)
        var current = start
        var visited: Set<String> = []
        var candidateKeys: [URL: (client: StorageClient, key: String)] = [:]
        var unreachable: Set<URL> = []

        for _ in 0..<16 {
            let settings = try await current.makeAvailable(auth)
            visited.insert(settings.storageIdentityKey)
            let user = try await current.findOrInsertUser(identityKey)
            guard let named = user.activeStorage, named != settings.storageIdentityKey else {
                return .active(current)
            }
            // A switch that stopped halfway can leave two records naming each other. Neither
            // takes writes; report the store the record names, as there is nothing to follow.
            guard !visited.contains(named) else {
                return .moved(storageIdentityKey: named)
            }
            var next: StorageClient?
            for url in candidates where url != current.endpoint && !unreachable.contains(url) {
                if let known = candidateKeys[url] {
                    if known.key == named { next = known.client; break }
                    continue
                }
                do {
                    let client = try await connect(url)
                    let key = try await client.makeAvailable(auth).storageIdentityKey
                    candidateKeys[url] = (client, key)
                    if key == named { next = client; break }
                } catch {
                    StorageClient.log(
                        "active storage: candidate \(url.absoluteString) unreachable, skipped: \(error)"
                    )
                    unreachable.insert(url)
                }
            }
            guard let next else {
                StorageClient.log(
                    "active storage: \(current.endpoint.absoluteString) names \(named), which no known address reaches"
                )
                return .moved(storageIdentityKey: named)
            }
            StorageClient.log(
                "active storage: following \(current.endpoint.absoluteString) to \(next.endpoint.absoluteString)"
            )
            current = next
        }
        // More hops than any real chain of moves: report where the records point now.
        let settings = try await current.makeAvailable(auth)
        return .moved(storageIdentityKey: settings.storageIdentityKey)
    }
}
