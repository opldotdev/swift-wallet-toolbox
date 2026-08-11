import Foundation

/// An error a storage server sent back.
///
/// The remote storage protocol carries typed errors, not strings: a JSON-RPC failure arrives as
/// `{"name": "WERR_INSUFFICIENT_FUNDS", "message": ...}` and the TypeScript client rebuilds a
/// typed error from the name. A client that kept only the message would turn every one of these
/// into text an application cannot branch on — and "not enough money" is exactly the case an
/// application must handle differently from "the server broke".
///
/// The names are the wire format, so they keep their original spelling. They are not this
/// library's error style: everything raised locally uses a Swift error enum in the module that
/// raises it, following `swift-sdk`. This type exists to translate at the boundary, once.
public enum WireError: Error, Equatable, Sendable {
    case badRequest(String)
    case broadcastUnavailable(String)
    case insufficientFunds(String)
    case internalFailure(String)
    case invalidOperation(String)
    case invalidParameter(name: String, message: String)
    case invalidPublicKey(String)
    case missingParameter(name: String, message: String)
    case networkChain(String)
    case notActive(String)
    case notImplemented(String)
    case reviewActions(String)
    case unauthorized(String)
    /// A name this version does not know. Kept rather than flattened, so a server that gains a
    /// code before we do produces a report somebody can act on.
    case unrecognized(name: String, message: String)

    /// The wire name this case came from, which is also what it would serialize back to.
    public var wireName: String {
        switch self {
        case .badRequest: "WERR_BAD_REQUEST"
        case .broadcastUnavailable: "WERR_BROADCAST_UNAVAILABLE"
        case .insufficientFunds: "WERR_INSUFFICIENT_FUNDS"
        case .internalFailure: "WERR_INTERNAL"
        case .invalidOperation: "WERR_INVALID_OPERATION"
        case .invalidParameter: "WERR_INVALID_PARAMETER"
        case .invalidPublicKey: "WERR_INVALID_PUBLIC_KEY"
        case .missingParameter: "WERR_MISSING_PARAMETER"
        case .networkChain: "WERR_NETWORK_CHAIN"
        case .notActive: "WERR_NOT_ACTIVE"
        case .notImplemented: "WERR_NOT_IMPLEMENTED"
        case .reviewActions: "WERR_REVIEW_ACTIONS"
        case .unauthorized: "WERR_UNAUTHORIZED"
        case .unrecognized(let name, _): name
        }
    }

    public var message: String {
        switch self {
        case .badRequest(let message), .broadcastUnavailable(let message),
             .insufficientFunds(let message), .internalFailure(let message),
             .invalidOperation(let message), .invalidPublicKey(let message),
             .networkChain(let message), .notActive(let message),
             .notImplemented(let message), .reviewActions(let message),
             .unauthorized(let message):
            message
        case .invalidParameter(_, let message), .missingParameter(_, let message),
             .unrecognized(_, let message):
            message
        }
    }

    /// Rebuilds the error from the `error` member of a JSON-RPC response.
    ///
    /// An absent or unreadable name does not throw. This runs on a path that is already reporting
    /// a failure, and losing the original failure to a parse error would be the worse outcome.
    public static func decode(jsonObject: JSONValue) -> WireError {
        decode(jsonObject.objectValue ?? [:])
    }

    public static func decode(_ payload: [String: JSONValue]) -> WireError {
        let message = payload["message"]?.stringValue ?? ""
        let name = payload["name"]?.stringValue ?? ""
        let parameter = payload["parameter"]?.stringValue ?? ""

        switch name {
        case "WERR_BAD_REQUEST": return .badRequest(message)
        case "WERR_BROADCAST_UNAVAILABLE": return .broadcastUnavailable(message)
        case "WERR_INSUFFICIENT_FUNDS": return .insufficientFunds(message)
        case "WERR_INTERNAL": return .internalFailure(message)
        case "WERR_INVALID_OPERATION": return .invalidOperation(message)
        case "WERR_INVALID_PARAMETER": return .invalidParameter(name: parameter, message: message)
        case "WERR_INVALID_PUBLIC_KEY": return .invalidPublicKey(message)
        case "WERR_MISSING_PARAMETER": return .missingParameter(name: parameter, message: message)
        case "WERR_NETWORK_CHAIN": return .networkChain(message)
        case "WERR_NOT_ACTIVE": return .notActive(message)
        case "WERR_NOT_IMPLEMENTED": return .notImplemented(message)
        case "WERR_REVIEW_ACTIONS": return .reviewActions(message)
        case "WERR_UNAUTHORIZED": return .unauthorized(message)
        default: return .unrecognized(name: name, message: message)
        }
    }
}
