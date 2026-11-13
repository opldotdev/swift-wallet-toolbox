import Foundation
import BSVAuth
import BSVKeys
import BSVWallet
import ToolboxStorage

extension RemoteWallet {
    /// Lists certificates owned by this wallet, filtered and paginated by storage.
    public func listCertificates(
        _ request: WalletListCertificatesRequest
    ) async throws -> WalletListCertificatesResult {
        try await storage.listCertificates(auth, request)
    }

    /// Stores a certificate a certifier issued to this wallet (`acquisitionProtocol: direct`).
    ///
    /// Mirrors `Wallet.acquireCertificate` in `@bsv/wallet-toolbox`: the subject is always this
    /// wallet's identity key, whatever the caller thinks it is, so a certificate issued to anyone
    /// else fails its signature check. The certificate is stored only after its signature
    /// verifies and every field decrypts with the subject's keyring; any failure is
    /// `WalletError.invalidCertificate` and storage is not called. `issuance` is not built.
    ///
    /// Returns the stored certificate with its fields still encrypted, as the reference does.
    public func acquireCertificate(
        _ request: WalletAcquireCertificateRequest, now: Date = Date()
    ) async throws -> Certificate {
        let direct: WalletDirectCertificateAcquisition
        switch request.acquisition {
        case .direct(let value): direct = value
        case .issuance:
            throw WalletError.notImplemented("acquireCertificate with acquisitionProtocol issuance")
        }
        // This wallet holds no privileged key; refuse rather than decrypt with the everyday one.
        guard request.privilege.privileged != true, request.privilege.privilegedReason == nil else {
            throw WalletCryptoError.permissionPolicyUnavailable
        }

        let master: MasterCertificate
        do {
            var fields: [CertificateFieldName: CertificateCiphertext] = [:]
            for (name, value) in request.fields {
                fields[name] = try CertificateCiphertext(base64: value)
            }
            let certificate = try Certificate(
                type: request.type,
                serialNumber: direct.serialNumber,
                subject: identityKey.publicKey,
                certifier: request.certifier,
                revocationOutpoint: direct.revocationOutpoint,
                fields: fields,
                signature: direct.signature
            )
            master = try MasterCertificate(
                certificate: certificate,
                masterKeyring: try CertificateKeyring(direct.keyringForSubject)
            )
            _ = try await CertificateEngine.acquire(master, using: protoWallet)
        } catch {
            throw WalletError.invalidCertificate(
                "valid encrypted and signed certificate and keyring from revealer. \(error)"
            )
        }

        let verifier: PublicKey
        switch direct.keyringRevealer {
        case .certifier: verifier = request.certifier
        case .publicKey(let key): verifier = key
        }
        _ = try await storage.insertCertificate(
            auth,
            try StorageCertificate(
                certificate: master.certificate,
                verifier: verifier,
                masterKeyring: direct.keyringForSubject
            ),
            now: now
        )
        return master.certificate
    }

    /// Stops holding a certificate. Storage marks it deleted and no longer lists it.
    ///
    /// As in the reference, success needs storage to report exactly one certificate updated;
    /// anything else is `WalletError.storageMutationIncomplete`.
    public func relinquishCertificate(
        _ request: WalletRelinquishCertificateRequest
    ) async throws -> WalletRelinquishCertificateResult {
        let updated = try await storage.relinquishCertificate(auth, request)
        guard updated == 1 else {
            throw WalletError.storageMutationIncomplete("certificate relinquishment")
        }
        return WalletRelinquishCertificateResult(relinquished: true)
    }
}
