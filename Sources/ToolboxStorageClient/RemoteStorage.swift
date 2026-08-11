import Foundation
import BSVAuth
import ToolboxAuth
import ToolboxStorage

/// Builds a storage client for a remote endpoint.
///
/// The two parts depend on each other in a cycle: the client authenticates using the wallet's
/// identity, and the wallet needs storage. Swift's initialisation rules will not let that be
/// papered over, so construction is explicitly two-phase, and this is where the order lives.
///
/// 1. Key operations come first. They need nothing but the identity key.
/// 2. The authenticated transport is built from those.
/// 3. The storage client is built on the transport.
///
/// A wallet is then assembled around the client. TypeScript hides the same sequence inside a
/// factory function; naming it here means nobody has to rediscover why it cannot be one step.
public enum RemoteStorage {

    /// The endpoint every new Yours Wallet account uses, and the one this library is tested
    /// against. Named rather than typed into call sites, so there is one place to change it.
    public static let defaultEndpoint = URL(string: "https://wallet.1sat.app")!

    /// Connects to a remote store as the given identity.
    ///
    /// Nothing reaches the network here. The handshake happens on the first call, which keeps
    /// construction cheap and failure attributable to the call that caused it.
    public static func client(
        at endpoint: URL = defaultEndpoint,
        wallet: any AuthenticationWallet
    ) -> StorageClient {
        StorageClient(
            endpoint: endpoint,
            transport: AuthenticatedSession(baseURL: endpoint, wallet: wallet)
        )
    }
}
