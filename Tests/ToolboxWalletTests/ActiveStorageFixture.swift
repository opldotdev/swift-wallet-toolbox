import Foundation
import ToolboxAuth
import ToolboxCore

/// Answers the two reads a storage write makes first, so a fake that scripts only the write
/// itself still sees a store that is the user's active storage.
///
/// `StorageClient` refuses a write unless `findOrInsertUser` names this store, by its
/// `makeAvailable` identity key, as the user's `activeStorage`. A fake calls `reply(to:)` before
/// its own script and returns the answer when there is one; the write's own request then reaches
/// the script as before. A fake whose test scripts `makeAvailable` itself passes
/// `answeringSettings: false`, so only the user read is answered here.
enum ActiveStorageFixture {
    static let storageIdentityKey = "02bb"

    static func reply(
        to body: [UInt8]?, answeringSettings: Bool = true, activeStorage: String = storageIdentityKey
    ) -> AuthenticatedResponse? {
        guard let body,
              let request = try? JSONDecoder().decode(JSONValue.self, from: Data(body)),
              let id = request["id"]?.intValue else { return nil }
        let result: String
        switch request["method"]?.stringValue {
        case "makeAvailable" where answeringSettings:
            result = #"{"storageIdentityKey":"\#(storageIdentityKey)","storageName":"test storage","chain":"main"}"#
        case "findOrInsertUser":
            let identityKey = request["params"]?.arrayValue?.first?.stringValue ?? ""
            result = #"{"user":{"userId":7,"identityKey":"\#(identityKey)","activeStorage":"\#(activeStorage)"},"isNew":false}"#
        default:
            return nil
        }
        return AuthenticatedResponse(
            statusCode: 200, headers: [:],
            body: Array(#"{"jsonrpc":"2.0","id":\#(id),"result":\#(result)}"#.utf8)
        )
    }
}
