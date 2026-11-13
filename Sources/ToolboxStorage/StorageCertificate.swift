import Foundation
import BSVKeys
import BSVWallet

/// A certificate as storage keeps it: the signed BRC-52 core with its encrypted fields, the
/// subject's master keyring, and who revealed that keyring.
///
/// This is the row `insertCertificateAuth` takes (`TableCertificateX` with its fields in
/// `@bsv/wallet-toolbox`). It does not prove anything by itself: the wallet verifies the
/// signature and decrypts every field before it builds one (`RemoteWallet.acquireCertificate`).
public struct StorageCertificate: Equatable, Sendable {
    /// The signed core certificate. Its `fields` are the encrypted values storage keeps.
    public let certificate: Certificate
    /// The key the subject's keyring was revealed by: the certifier, or the revealer it named.
    public let verifier: PublicKey
    /// Each field's master key, encrypted for the subject.
    public let masterKeyring: [CertificateFieldName: CertificateCiphertext]

    public init(
        certificate: Certificate,
        verifier: PublicKey,
        masterKeyring: [CertificateFieldName: CertificateCiphertext]
    ) throws {
        guard certificate.signature != nil else { throw CertificateError.missingSignature }
        self.certificate = certificate
        self.verifier = verifier
        self.masterKeyring = masterKeyring
    }
}
