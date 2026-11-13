import Foundation
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// The BRC-177 storage calls, in the reference client's wire shape.
///
/// `target` is the same validated createAction argument object `createAction` sends, and it is
/// sent identically to `prepareNoSendExpiry` and `activateNoSendExpiry`: storage compares the two
/// and refuses an activation whose target changed.
extension StorageClient: NoSendExpiryStorage {

    /// Whether this storage advertises BRC-177 version 1. Takes no auth, like the reference.
    public func supportsNoSendExpiry() async throws -> Bool {
        let result = try await call("getCapabilities", [])
        return result["brc177NoSendExpiry"]?["version"]?.intValue == 1
    }

    public func prepareNoSendExpiry(
        _ auth: AuthID, _ target: WalletCreateActionRequest
    ) async throws -> NoSendExpiryPrepared {
        let result = try await call(
            "prepareNoSendExpiry",
            [.object(auth.jsonObject), .object(try Self.noSendExpiryTarget(target))]
        )
        return try Self.decodePrepared(result)
    }

    public func activateNoSendExpiry(
        _ auth: AuthID, target: WalletCreateActionRequest, fundingReference: String,
        fundingTxid: String, anchorVout: UInt32
    ) async throws -> NoSendExpiryActivated {
        let result = try await call("activateNoSendExpiry", [
            .object(auth.jsonObject),
            .object([
                "target": .object(try Self.noSendExpiryTarget(target)),
                "fundingReference": .string(fundingReference),
                "fundingTxid": .string(fundingTxid),
                "anchorVout": .number(Double(anchorVout)),
            ]),
        ])
        return try Self.decodeActivated(result)
    }

    public func armNoSendExpiry(_ auth: AuthID, _ arm: NoSendExpiryArm) async throws {
        _ = try await call("armNoSendExpiry", [
            .object(auth.jsonObject),
            .object([
                "reference": .string(arm.reference),
                "reclaimTxid": .string(arm.reclaimTxid),
                "reclaimRawTx": .array(arm.reclaimRawTx.map { .number(Double($0)) }),
                "reclaimDerivationPrefix": .string(arm.reclaimDerivationPrefix),
                "reclaimDerivationSuffix": .string(arm.reclaimDerivationSuffix),
                "reclaimSatoshis": .number(Double(arm.reclaimSatoshis)),
            ]),
        ])
    }

    /// The protected action's arguments, checked the way storage checks them before any call, so
    /// a request storage would refuse is refused here without reserving anything.
    static func noSendExpiryTarget(
        _ target: WalletCreateActionRequest
    ) throws -> [String: JSONValue] {
        guard try NoSendExpiry.parse(labels: target.labels ?? []) != nil else {
            throw NoSendExpiryError.invalidRequest("no BRC-177 expiry label")
        }
        guard !(target.outputs ?? []).isEmpty else {
            throw NoSendExpiryError.invalidRequest("at least one output is required")
        }
        let options = target.options
        guard options?.noSend == true else {
            throw NoSendExpiryError.invalidRequest("options.noSend must be true")
        }
        guard (options?.sendWith ?? []).isEmpty else {
            throw NoSendExpiryError.invalidRequest("options.sendWith must be empty")
        }
        guard (options?.noSendChange ?? []).isEmpty else {
            throw NoSendExpiryError.invalidRequest("options.noSendChange must be empty")
        }
        guard options?.returnTransactionIDOnly != true else {
            throw NoSendExpiryError.invalidRequest("options.returnTXIDOnly must be false")
        }
        return try arguments(for: target)
    }

    static func decodePrepared(_ result: JSONValue) throws -> NoSendExpiryPrepared {
        guard let funding = result["funding"],
              let anchorSatoshis = unsigned(result["anchorSatoshis"]),
              let anchorVout = unsigned(result["anchorVout"]).flatMap(UInt32.init(exactly:)),
              let reclaimFee = unsigned(result["reclaimFee"]),
              let reclaimSatoshis = unsigned(result["reclaimSatoshis"]) else {
            throw StorageClientError.unreadableResponse(method: "prepareNoSendExpiry")
        }
        return NoSendExpiryPrepared(
            funding: try decodeCreateAction(funding),
            anchorSatoshis: anchorSatoshis,
            anchorVout: anchorVout,
            reclaimFee: reclaimFee,
            reclaimSatoshis: reclaimSatoshis
        )
    }

    static func decodeActivated(_ result: JSONValue) throws -> NoSendExpiryActivated {
        guard let action = result["action"],
              let mode = result["expiry"]?["mode"]?.stringValue,
              let anchorTxid = result["anchorTxid"]?.stringValue,
              anchorTxid.count == 64, hexBytes(anchorTxid) != nil,
              let anchorVout = unsigned(result["anchorVout"]).flatMap(UInt32.init(exactly:)) else {
            throw StorageClientError.unreadableResponse(method: "activateNoSendExpiry")
        }
        let deadline: UInt64?
        switch result["deadline"] {
        case nil, .null?: deadline = nil
        case let value?:
            guard let read = unsigned(value) else {
                throw StorageClientError.unreadableResponse(method: "activateNoSendExpiry")
            }
            deadline = read
        }
        return NoSendExpiryActivated(
            action: try decodeCreateAction(action),
            mode: mode,
            deadline: deadline,
            anchorTxid: anchorTxid,
            anchorVout: anchorVout
        )
    }

    private static func unsigned(_ value: JSONValue?) -> UInt64? {
        value?.intValue.flatMap { $0 >= 0 ? UInt64($0) : nil }
    }
}
