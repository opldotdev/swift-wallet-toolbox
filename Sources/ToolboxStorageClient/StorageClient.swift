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
    public nonisolated let endpoint: URL
    private let transport: any AuthenticatedTransport
    private var nextID = 1
    private var settings: StorageSettings?
    /// The in-flight settings read, so concurrent first callers share one request rather than each
    /// issuing their own. Actor reentrancy across the `await` otherwise lets two callers both see
    /// no cached settings and both go to the network.
    private var settingsTask: Task<StorageSettings, Error>?
    /// The user's record as last read, which says whether this store is the active one.
    private var user: StorageUser?
    /// Whether requests carry bytes as base64 (`X-BSV-Binary-Request-Encoding: base64`), which
    /// storage said it reads by echoing `X-BSV-Binary-Encoding` on the settings read.
    ///
    /// Bytes written as a JSON array of numbers cost one JSON value each, and storage's
    /// authentication layer (`@bsv/auth-express-middleware`) refuses any request with more than
    /// 100,000 values, or an array longer than that, with an unsigned `400 ERR_AUTH_MALFORMED`.
    /// A transaction over ~100 KB, such as an inscription carrying a photo, then never reaches
    /// storage. The reference client sends bytes as base64 for the same reason (`binaryRequests:
    /// true` in every 1Sat wallet) once a response has carried that header.
    private var binaryRequests = false

    public init(endpoint: URL, transport: any AuthenticatedTransport) {
        self.endpoint = endpoint
        self.transport = transport
    }

    /// True once settings have been read, which is the only proof the far end is really there.
    public var isAvailable: Bool { settings != nil }

    /// Whether this store is the user's active storage, once both records have been read; `nil`
    /// before the first write has checked.
    public var isActive: Bool? {
        guard let settings, let user else { return nil }
        return user.activeStorage == settings.storageIdentityKey
    }

    /// The identity key of the store the user's record names as active, once read.
    public var activeStorageIdentityKey: String? { user?.activeStorage ?? nil }

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
    ///
    /// The body is written with `JSON.stringify`'s rules, never `JSONEncoder`'s. The storage server
    /// (`@bsv/auth-express-middleware` behind `express.json()`) does not verify the bytes it
    /// received: it rebuilds the signed BRC-104 payload from `JSON.stringify(req.body)`. Any byte
    /// where our text differs from that re-serialisation breaks the signature, and the server
    /// answers an unsigned 401 that looks exactly like an evicted session. `JSONEncoder` writes
    /// `/` as `\/`, so every call carrying a slash failed: a `type:text/plain` inscription tag on
    /// every inscribe, and a server-issued base64 `reference` on roughly one send in five, in
    /// `processAction` and then again in the `abortAction` meant to release its inputs. The
    /// TypeScript `StorageClient` sends `JSON.stringify(body)`, which is what this matches.
    public func call(_ method: String, _ params: [JSONValue]) async throws -> JSONValue {
        try await call(method, rawParams: params.map { OrderedJSON($0) })
    }

    /// Issues one call whose parameters are written member for member as given.
    ///
    /// `call(_:_:)` starts from a dictionary, which has no key order, and writes members sorted by
    /// key. That is fine for every argument a server reads by name, and wrong for one it hashes:
    /// the action-batch manifest's digest is recomputed by storage from the key order it receives.
    /// Parameters passed here are written with `JSON.stringify`'s rules and in their own order.
    public func call(_ method: String, rawParams params: [OrderedJSON]) async throws -> JSONValue {
        try await call(method, rawParams: params, negotiatingBinary: false)
    }

    /// The header naming a binary request body, and the one asking for (and confirming) binary.
    static let binaryRequestHeader = "X-BSV-Binary-Request-Encoding"
    static let binaryHeader = "X-BSV-Binary-Encoding"

    /// `negotiatingBinary` asks storage, with `X-BSV-Binary-Encoding: base64`, whether it reads
    /// binary requests; its echo of that header turns `binaryRequests` on. Only the settings read
    /// asks, because storage then writes the response's own bytes as base64 too, and a settings
    /// record has none.
    private func call(
        _ method: String, rawParams params: [OrderedJSON], negotiatingBinary: Bool
    ) async throws -> JSONValue {
        if Self.writerMethods.contains(method) {
            try await requireActive(params.first)
        }
        let id = nextID
        nextID += 1

        let request = OrderedJSON.object([
            .init("jsonrpc", .string("2.0")),
            .init("method", .string(method)),
            .init("params", .array(params)),
            .init("id", .integer(Int64(id))),
        ])
        let binary = binaryRequests
        var headers = ["Content-Type": "application/json"]
        if binary { headers[Self.binaryRequestHeader] = "base64" }
        if negotiatingBinary { headers[Self.binaryHeader] = "base64" }
        return try await send(
            method, id: id, body: request.utf8Bytes(binary: binary), headers: headers,
            negotiatingBinary: negotiatingBinary
        )
    }

    private func send(
        _ method: String, id: Int, body: [UInt8], headers: [String: String],
        negotiatingBinary: Bool
    ) async throws -> JSONValue {
        let response: AuthenticatedResponse
        do {
            response = try await transport.send(
                method: "POST",
                path: endpoint.path.isEmpty ? "/" : endpoint.path,
                query: nil,
                headers: headers,
                body: body
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            // Rethrown as it is; the log adds which storage call it was.
            Self.log("storage \(method) on \(ErrorDetail.hostPath(endpoint)) failed: \(ErrorDetail.describe(error))")
            throw error
        }
        if negotiatingBinary {
            binaryRequests = response.headers.contains {
                $0.key.lowercased() == Self.binaryHeader.lowercased() && $0.value == "base64"
            }
        }

        let envelope: JSONValue
        do {
            envelope = try JSONDecoder().decode(JSONValue.self, from: Data(response.body))
        } catch {
            throw logged(.unreadableResponse(method: method), response, "not JSON: \(ErrorDetail.describe(error))")
        }

        // A well-formed JSON-RPC reply names its version and echoes the request's id. The
        // transport already prevents a reply reaching the wrong request, so this is not an
        // authentication check — but an authenticated yet malformed envelope is still not one to
        // read a result out of.
        guard envelope["jsonrpc"]?.stringValue == "2.0", envelope["id"]?.intValue == id else {
            throw logged(.unreadableResponse(method: method), response, "not a JSON-RPC reply to id \(id)")
        }

        // The error member wins over the result member. A server that sent both is malformed, and
        // preferring the result would turn a reported failure into a silent success.
        if let failure = envelope["error"], failure != .null {
            let error = WireError.decode(jsonObject: failure)
            Self.log("storage \(method) on \(ErrorDetail.hostPath(endpoint)) answered HTTP "
                + "\(response.statusCode): \(ErrorDetail.describe(error))")
            throw error
        }
        // A missing `result` is not the same as a null one. JSON-RPC allows a null result, and
        // treating an absent member as null would hide a truncated response.
        guard let result = envelope["result"] else {
            // An HTTP failure with no error member is worth reporting as itself rather than as a
            // parse problem.
            guard (200..<300).contains(response.statusCode) else {
                throw logged(
                    .httpFailure(method: method, statusCode: response.statusCode), response, "no error member"
                )
            }
            throw logged(.unreadableResponse(method: method), response, "no result member")
        }
        return result
    }

    /// Logs a reply that could not be used, with the storage call, status and body, and returns
    /// the error to throw.
    private func logged(
        _ error: StorageClientError, _ response: AuthenticatedResponse, _ why: String
    ) -> StorageClientError {
        Self.log("storage \(error.method) on \(ErrorDetail.hostPath(endpoint)) answered HTTP "
            + "\(response.statusCode) (\(why)); body: \(ErrorDetail.bodyPreview(response.body))")
        return error
    }

    static func log(_ message: String) {
        ToolboxLog.error("ToolboxStorageClient", message)
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

    /// Finds the user's record on this store, creating it if the store allows that.
    ///
    /// The record's `activeStorage` is what makes this store writable: see `requireActive`.
    public func findOrInsertUser(_ identityKey: String) async throws -> StorageUser {
        let result = try await call("findOrInsertUser", [.string(identityKey)])
        guard let user = result["user"], let userId = user["userId"]?.intValue else {
            throw StorageClientError.unreadableResponse(method: "findOrInsertUser")
        }
        // A record with no `activeStorage` names no store active, so this one is not: writes are
        // refused as `WERR_NOT_ACTIVE`, as TS `isActiveEnabled` is false for it.
        let read = StorageUser(
            userId: userId,
            identityKey: user["identityKey"]?.stringValue ?? identityKey,
            activeStorage: user["activeStorage"]?.stringValue
        )
        self.user = read
        return read
    }

    /// The calls that change the user's records, which only the active store may take.
    ///
    /// The TypeScript `WalletStorageManager` runs each of these through
    /// `runAsAuthorizedWriter`, whose `getAuth(true)` throws `WERR_NOT_ACTIVE` unless the store's
    /// `storageIdentityKey` is the user's `activeStorage`. Readers are not gated there and are not
    /// here. Two wallets on the same keys writing to different stores diverge; one is active and
    /// the others sync through it.
    static let writerMethods: Set<String> = [
        "abortAction", "createAction", "internalizeAction", "processAction",
        "relinquishCertificate", "relinquishOutput", "insertCertificateAuth",
        "prepareNoSendExpiry", "activateNoSendExpiry", "armNoSendExpiry",
        "beginActionBatch", "extendActionBatch", "renewActionBatch",
        "commitActionBatch", "abortActionBatch",
    ]

    /// Throws `WERR_NOT_ACTIVE` unless this store is the user's active storage.
    ///
    /// The answer is cached once it is yes. A no is read again before it is believed, so making
    /// this store active from the other wallet takes effect without a relaunch.
    private func requireActive(_ authParameter: OrderedJSON?) async throws {
        guard let identityKey = authParameter?["identityKey"]?.stringValue else {
            throw WireError.missingParameter(
                name: "auth", message: "A storage write must name the caller's identity."
            )
        }
        let settings = try await makeAvailable(AuthID(identityKey: identityKey))
        if let user, user.identityKey == identityKey,
           user.activeStorage == settings.storageIdentityKey {
            return
        }
        let read = try await findOrInsertUser(identityKey)
        guard read.activeStorage == settings.storageIdentityKey else {
            throw WireError.notActive(
                "\(settings.storageName) is not this wallet's active storage. Another wallet "
                    + "using these keys has made a different storage active, so writing here "
                    + "would make the two diverge. Make this storage active there, then try again."
            )
        }
    }

    private func readSettings(_ auth: AuthID) async throws -> StorageSettings {
        let result = try await call(
            "makeAvailable", rawParams: [OrderedJSON(.object(auth.jsonObject))],
            negotiatingBinary: true
        )
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

public enum StorageClientError: Error, Equatable, Sendable, LocalizedError {
    /// The server answered, but not in this protocol.
    case unreadableResponse(method: String)
    case httpFailure(method: String, statusCode: Int)

    /// The storage call that failed.
    public var method: String {
        switch self {
        case .unreadableResponse(let method), .httpFailure(let method, _): method
        }
    }

    public var errorDescription: String? {
        switch self {
        case .unreadableResponse(let method):
            "The wallet storage server sent a reply to \(method) that could not be read."
        case .httpFailure(let method, let statusCode) where statusCode >= 500 || statusCode == 429:
            "The wallet storage server could not handle \(method) (HTTP \(statusCode)). Try again later."
        case .httpFailure(let method, let statusCode):
            "The wallet storage server refused \(method) (HTTP \(statusCode))."
        }
    }
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
