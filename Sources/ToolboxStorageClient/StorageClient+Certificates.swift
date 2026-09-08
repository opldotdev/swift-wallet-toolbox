import Foundation
import BSVWallet
import ToolboxCore
import ToolboxStorage

extension StorageClient {
    /// Lists stored certificates using the same authenticated storage RPC as the reference wallets.
    public func listCertificates(
        _ auth: AuthID, _ request: WalletListCertificatesRequest
    ) async throws -> WalletListCertificatesResult {
        let codec = try WalletBRC100JSONCodec(beefLimits: StorageLimits.beef)
        let bytes = try codec.encodeRequest(.certificate(.listCertificates(request)))
        let arguments = try JSONDecoder().decode(JSONValue.self, from: Data(bytes))
        let result = try await call("listCertificates", [.object(auth.jsonObject), arguments])
        do {
            let encoded = try JSONEncoder().encode(result)
            guard case .certificate(.listCertificates(let certificates)) = try codec.decodeResult(
                route: WalletJSONRoute(methodName: "listCertificates")!, from: Array(encoded)
            ) else {
                throw StorageClientError.unreadableResponse(method: "listCertificates")
            }
            return certificates
        } catch {
            throw StorageClientError.unreadableResponse(method: "listCertificates")
        }
    }
}
