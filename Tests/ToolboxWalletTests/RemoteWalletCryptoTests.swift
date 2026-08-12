import XCTest
import BSVKeys
import BSVWallet
import ToolboxStorage
import ToolboxStorageClient
@testable import ToolboxWallet

/// Remote-wallet crypto tests stay offline because the identity key is sufficient for every call.
final class RemoteWalletCryptoTests: XCTestCase {

    /// A fixed identity makes the crypto behavior repeatable without contacting storage.
    private func wallet() throws -> (RemoteWallet, PrivateKey) {
        let identityKey = try PrivateKey([UInt8](repeating: 1, count: 32))
        let identity = identityKey.publicKey.compressedBytes
            .map { String(format: "%02x", $0) }.joined()
        let endpoint = try XCTUnwrap(URL(string: "https://storage.example"))
        let storage = try RemoteStorage.client(
            at: endpoint, wallet: ProtoWallet(rootKey: identityKey)
        )
        return (
            RemoteWallet(
                storage: storage,
                identityKey: identityKey,
                auth: AuthID(identityKey: identity)
            ),
            identityKey
        )
    }

    func test_publicKeyAndSignatureOperationsUseTheIdentityKey() async throws {
        let (wallet, identityKey) = try wallet()
        let publicKey = try await wallet.getPublicKey(
            WalletGetPublicKeyRequest(selection: .identity)
        )
        XCTAssertEqual(publicKey.publicKey, identityKey.publicKey)

        let protocolID = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: "remote crypto"
        )
        let keyID = try WalletKeyID("signature key")
        let payload: WalletSignaturePayload = .data(Array("signed offline".utf8))
        let signature = try await wallet.createSignature(
            WalletCreateSignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                payload: payload
            )
        )
        let verified = try await wallet.verifySignature(
            WalletVerifySignatureRequest(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .anyone,
                payload: payload,
                signature: signature.signature,
                forSelf: true
            )
        )

        XCTAssertTrue(verified.valid)
    }
}
