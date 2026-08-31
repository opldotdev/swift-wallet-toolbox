import XCTest
import BSVKeys
import BSVWallet
import ToolboxStorage
import ToolboxStorageClient
@testable import ToolboxWallet

/// The linkage layer is intentionally offline: storage must not participate in key revelation.
final class RemoteWalletLinkageTests: XCTestCase {
    private func privateKey(_ value: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [value])
    }

    private func wallet(rootKey: PrivateKey) throws -> RemoteWallet {
        let identity = rootKey.publicKey.compressedBytes
            .map { String(format: "%02x", $0) }.joined()
        let endpoint = try XCTUnwrap(URL(string: "https://storage.invalid"))
        let storage = try RemoteStorage.client(
            at: endpoint,
            wallet: ProtoWallet(rootKey: rootKey)
        )
        return RemoteWallet(
            storage: storage,
            identityKey: rootKey,
            auth: AuthID(identityKey: identity)
        )
    }

    func test_counterpartyLinkageDecryptsAndCarriesAValidBRC94Proof() async throws {
        let proverKey = try privateKey(7)
        let counterpartyKey = try privateKey(13)
        let verifierKey = try privateKey(17)
        let wallet = try wallet(rootKey: proverKey)
        let operations: any WalletLinkageOperations = wallet

        let result = try await operations.revealCounterpartyKeyLinkage(
            WalletRevealCounterpartyKeyLinkageRequest(
                counterparty: counterpartyKey.publicKey,
                verifier: verifierKey.publicKey
            )
        )

        XCTAssertEqual(result.prover, proverKey.publicKey)
        XCTAssertEqual(result.counterparty, counterpartyKey.publicKey)
        XCTAssertEqual(result.verifier, verifierKey.publicKey)

        let verifier = ProtoWallet(rootKey: verifierKey)
        let revelationProtocol = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: "counterparty linkage revelation"
        )
        let keyID = try WalletKeyID(result.revelationTime)
        let linkage = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: revelationProtocol,
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkage.bytes
        )).plaintext
        let expectedLinkage = try proverKey.sharedSecret(with: counterpartyKey.publicKey)
        XCTAssertEqual(linkage, expectedLinkage.compressedBytes)

        let proofBytes = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: revelationProtocol,
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkageProof.bytes
        )).plaintext
        let proof = try decodeBRC94Proof(proofBytes)
        XCTAssertTrue(proof.verify(
            proverPublicKey: proverKey.publicKey,
            counterpartyPublicKey: counterpartyKey.publicKey,
            sharedSecret: expectedLinkage
        ))
    }

    func test_specificLinkageDecryptsToTheDerivedOffsetWithProofTypeZero() async throws {
        let proverKey = try privateKey(7)
        let counterpartyKey = try privateKey(13)
        let verifierKey = try privateKey(17)
        let wallet = try wallet(rootKey: proverKey)
        let protocolID = try WalletProtocolID(securityLevel: .silent, name: "tests")
        let keyID = try WalletKeyID("test key id")

        let result = try await wallet.revealSpecificKeyLinkage(
            try WalletRevealSpecificKeyLinkageRequest(
                counterparty: .publicKey(counterpartyKey.publicKey),
                verifier: verifierKey.publicKey,
                protocolID: protocolID,
                keyID: keyID
            )
        )

        XCTAssertEqual(result.prover, proverKey.publicKey)
        XCTAssertEqual(result.counterparty, counterpartyKey.publicKey)
        XCTAssertEqual(result.verifier, verifierKey.publicKey)
        XCTAssertEqual(result.protocolID, protocolID)
        XCTAssertEqual(result.keyID, keyID)
        XCTAssertEqual(result.proofType, 0)

        let verifier = ProtoWallet(rootKey: verifierKey)
        let revelationProtocol = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: "specific linkage revelation 0 tests"
        )
        let linkage = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: revelationProtocol,
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkage.bytes
        )).plaintext
        let expectedLinkage = try WalletKeyDeriver(rootKey: proverKey).revealSpecificSecret(
            counterparty: .publicKey(counterpartyKey.publicKey),
            protocolID: protocolID,
            keyID: keyID
        )
        XCTAssertEqual(linkage, expectedLinkage)

        let proof = try await verifier.decrypt(WalletDecryptRequest(
            protocolID: revelationProtocol,
            keyID: keyID,
            counterparty: .publicKey(proverKey.publicKey),
            ciphertext: result.encryptedLinkageProof.bytes
        )).plaintext
        XCTAssertEqual(proof, [0])
    }

    func test_linkageRejectsSelfAndFailsClosedWithoutPrivilegedPolicy() async throws {
        let proverKey = try privateKey(7)
        let counterpartyKey = try privateKey(13)
        let verifierKey = try privateKey(17)
        let wallet = try wallet(rootKey: proverKey)
        let protocolID = try WalletProtocolID(securityLevel: .silent, name: "tests")
        let keyID = try WalletKeyID("test")

        await XCTAssertThrowsErrorAsync(try await wallet.revealCounterpartyKeyLinkage(
            WalletRevealCounterpartyKeyLinkageRequest(
                counterparty: proverKey.publicKey,
                verifier: verifierKey.publicKey
            )
        )) { error in
            XCTAssertEqual(error as? WalletCryptoError, .counterpartySelfLinkageForbidden)
        }

        for privilege in [
            try WalletPrivilege(privileged: true),
            try WalletPrivilege(privilegedReason: "audit reason"),
        ] {
            await XCTAssertThrowsErrorAsync(try await wallet.revealCounterpartyKeyLinkage(
                WalletRevealCounterpartyKeyLinkageRequest(
                    counterparty: counterpartyKey.publicKey,
                    verifier: verifierKey.publicKey,
                    privilege: privilege
                )
            )) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
            await XCTAssertThrowsErrorAsync(try await wallet.revealSpecificKeyLinkage(
                try WalletRevealSpecificKeyLinkageRequest(
                    counterparty: .publicKey(counterpartyKey.publicKey),
                    verifier: verifierKey.publicKey,
                    protocolID: protocolID,
                    keyID: keyID,
                    privilege: privilege
                )
            )) { error in
                XCTAssertEqual(error as? WalletCryptoError, .permissionPolicyUnavailable)
            }
        }
    }

    private func decodeBRC94Proof(_ bytes: [UInt8]) throws -> SharedSecretProof {
        guard bytes.count > 66, bytes.count <= 98 else {
            throw LinkageTestError.invalidProofLength(bytes.count)
        }
        let encodedResponse = Array(bytes.dropFirst(66))
        let response = [UInt8](repeating: 0, count: 32 - encodedResponse.count)
            + encodedResponse
        return try SharedSecretProof(
            noncePublicKey: PublicKey(Array(bytes[0..<33])),
            nonceSharedSecret: PublicKey(Array(bytes[33..<66])),
            response: response
        )
    }
}

private enum LinkageTestError: Error {
    case invalidProofLength(Int)
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in },
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}
