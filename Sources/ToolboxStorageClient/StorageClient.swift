import Foundation
import ToolboxAuth
import ToolboxCore
import ToolboxStorage

/// Remote storage over JSON-RPC.
///
/// The wire format is fixed by the servers that already speak it, `https://wallet.1sat.app` among
/// them:
///
///     POST <endpoint>
///     {"jsonrpc": "2.0", "method": <name>, "params": [...], "id": n}
///     → {"result": ...} | {"error": {"name": "WERR_...", "message": ...}}
///
/// Parameters are positional and the first is always the caller's `AuthID`. Every request travels
/// over an authenticated transport, because the server answers no other kind.
///
/// This is the only storage engine in v1. The TypeScript toolbox's mobile build ships the same
/// single option — it exports no on-device engine at all. See `docs/DESIGN.md` §5.
public actor StorageClient {
    public let endpoint: URL
    private let transport: any AuthenticatedTransport
    private var nextID = 1
    private var settings: StorageSettings?
    /// The in-flight settings read, so concurrent first callers share one request rather than each
    /// issuing their own. Actor reentrancy across the `await` otherwise lets two callers both see
    /// no cached settings and both go to the network.
    private var settingsTask: Task<StorageSettings, Error>?

    public init(endpoint: URL, transport: any AuthenticatedTransport) {
        self.endpoint = endpoint
        self.transport = transport
    }

    /// True once settings have been read, which is the only proof the far end is really there.
    public var isAvailable: Bool { settings != nil }

    /// This is a client, not an engine: it forwards to storage rather than owning the records.
    ///
    /// A caller holding only this must not assume it can perform operations that need the records
    /// themselves, which is exactly what this flag is for.
    public nonisolated var isStorageProvider: Bool { false }

    // MARK: - JSON-RPC

    /// Issues one call and returns its `result` member.
    ///
    /// A server-side failure is raised as a `WireError` carrying the server's own name for it. An
    /// application has to tell "you do not have enough money" from "the server broke", and a
    /// client that kept only the message would make both of them prose.
    public func call(_ method: String, _ params: [JSONValue]) async throws -> JSONValue {
        let id = nextID
        nextID += 1

        let request = JSONValue.object([
            "jsonrpc": .string("2.0"),
            "method": .string(method),
            "params": .array(params),
            "id": .number(Double(id)),
        ])

        let response = try await transport.send(
            method: "POST",
            path: endpoint.path.isEmpty ? "/" : endpoint.path,
            query: nil,
            headers: ["Content-Type": "application/json"],
            body: Array(try JSONEncoder().encode(request))
        )

        let envelope: JSONValue
        do {
            envelope = try JSONDecoder().decode(JSONValue.self, from: Data(response.body))
        } catch {
            throw StorageClientError.unreadableResponse(method: method)
        }

        // A well-formed JSON-RPC reply names its version and echoes the request's id. The
        // transport already prevents a reply reaching the wrong request, so this is not an
        // authentication check — but an authenticated yet malformed envelope is still not one to
        // read a result out of.
        guard envelope["jsonrpc"]?.stringValue == "2.0", envelope["id"]?.intValue == id else {
            throw StorageClientError.unreadableResponse(method: method)
        }

        // The error member wins over the result member. A server that sent both is malformed, and
        // preferring the result would turn a reported failure into a silent success.
        if let failure = envelope["error"], failure != .null {
            throw WireError.decode(jsonObject: failure)
        }
        // A missing `result` is not the same as a null one. JSON-RPC allows a null result, and
        // treating an absent member as null would hide a truncated response.
        guard let result = envelope["result"] else {
            // An HTTP failure with no error member is worth reporting as itself rather than as a
            // parse problem.
            guard (200..<300).contains(response.statusCode) else {
                throw StorageClientError.httpFailure(
                    method: method, statusCode: response.statusCode
                )
            }
            throw StorageClientError.unreadableResponse(method: method)
        }
        return result
    }

    // MARK: - Storage

    /// Reads the store's settings, which is what makes the client available.
    ///
    /// Called before anything else, because it is the first proof that the endpoint exists, speaks
    /// this protocol, and accepts our identity.
    @discardableResult
    public func makeAvailable(_ auth: AuthID) async throws -> StorageSettings {
        if let settings { return settings }
        if let settingsTask { return try await settingsTask.value }

        let task = Task { try await readSettings(auth) }
        settingsTask = task
        defer { settingsTask = nil }

        let read = try await task.value
        settings = read
        return read
    }

    private func readSettings(_ auth: AuthID) async throws -> StorageSettings {
        let result = try await call("makeAvailable", [.object(auth.jsonObject)])
        guard let identityKey = result["storageIdentityKey"]?.stringValue,
              let name = result["storageName"]?.stringValue,
              let chainName = result["chain"]?.stringValue,
              let chain = Chain(rawValue: chainName) else {
            throw StorageClientError.unreadableResponse(method: "makeAvailable")
        }
        return StorageSettings(
            storageIdentityKey: identityKey, storageName: name, chain: chain
        )
    }
}

public enum StorageClientError: Error, Equatable, Sendable {
    /// The server answered, but not in this protocol.
    case unreadableResponse(method: String)
    case httpFailure(method: String, statusCode: Int)
}

extension AuthID {
    /// The shape the server expects as the first positional parameter of every method.
    var jsonObject: [String: JSONValue] {
        var object: [String: JSONValue] = ["identityKey": .string(identityKey)]
        if let userID {
            object["userId"] = .number(Double(userID))
        }
        return object
    }
}
