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
/// over `AuthenticatedTransport`, because the server answers no other kind.
///
/// This is the only storage engine in v1. The TypeScript toolbox's mobile build ships the same
/// single option — it exports no on-device engine at all. See `docs/DESIGN.md` §5.
public actor StorageClient {
    public let endpoint: URL
    private let transport: any AuthenticatedTransport
    private var nextID = 1
    private var settings: StorageSettings?

    public init(endpoint: URL, transport: any AuthenticatedTransport) {
        self.endpoint = endpoint
        self.transport = transport
    }

    /// True once settings have been read, which is the only proof the far end is really there.
    public var isAvailable: Bool { settings != nil }

    /// Issues one JSON-RPC call.
    ///
    /// A failure carries the server's own error name rather than a flattened string: an
    /// application has to tell "not enough money" from "the server broke", and only the name
    /// distinguishes them.
    func call<Result: Decodable & Sendable>(
        _ method: String, params: [Any]
    ) async throws -> Result {
        throw StorageError.notImplemented(
            "JSON-RPC transport is not built yet: \(method)"
        )
    }
}
