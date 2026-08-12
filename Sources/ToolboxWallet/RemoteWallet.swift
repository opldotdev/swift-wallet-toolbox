import Foundation
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import ToolboxActions
import ToolboxPaymail
import ToolboxBRC29
import ToolboxStorage
import ToolboxStorageClient

/// A wallet backed by remote storage.
///
/// This is where the pieces compose. A payment is four calls in a fixed order — fund, verify,
/// sign, send — and getting that order right is the whole reason the pieces are separate. The
/// wallet holds the identity key and the fee policy; storage holds the coins; the action layer
/// holds the safety checks. None of them trusts the others by default.
///
/// It is a `struct` around an actor `StorageClient`: the mutable state lives in the client, and
/// concurrent payments serialize there.
public struct RemoteWallet: Sendable {
    private let storage: StorageClient
    private let identityKey: PrivateKey
    private let auth: AuthID
    /// The most this wallet will pay to miners on any single payment, in satoshis. A payment whose
    /// funding would exceed it is refused before signing rather than silently overpaid.
    public let maximumFee: Int64

    public init(
        storage: StorageClient,
        identityKey: PrivateKey,
        auth: AuthID,
        maximumFee: Int64 = 100_000
    ) {
        self.storage = storage
        self.identityKey = identityKey
        self.auth = auth
        self.maximumFee = maximumFee
    }

    /// The offline BRC-100 kernel shares this wallet's identity key for every crypto operation.
    public var protoWallet: ProtoWallet { ProtoWallet(rootKey: identityKey) }

    /// Restores a wallet from its recovery phrase, using the BSV Association reference scheme
    /// (`MnemonicRestore`, matching `bsv-desktop`).
    ///
    /// The phrase is the whole backup: it produces the identity key, which both authenticates to
    /// storage and signs. A phrase written down in `bsv-desktop` restores the same wallet here.
    ///
    /// Nothing reaches the network; the handshake waits for the first call.
    public static func restore(
        fromPhrase phrase: String,
        endpoint: URL = RemoteStorage.defaultEndpoint,
        maximumFee: Int64 = 100_000
    ) throws -> RemoteWallet {
        let identityKey = try MnemonicRestore.identityKey(fromPhrase: phrase)
        let identityHex = identityKey.publicKey.compressedBytes
            .map { String(format: "%02x", $0) }.joined()
        let storage = try RemoteStorage.client(
            at: endpoint, wallet: ProtoWallet(rootKey: identityKey)
        )
        return RemoteWallet(
            storage: storage,
            identityKey: identityKey,
            auth: AuthID(identityKey: identityHex),
            maximumFee: maximumFee
        )
    }

    /// Reachable once storage has described itself.
    @discardableResult
    public func connect() async throws -> StorageSettings {
        try await storage.makeAvailable(auth)
    }

    /// The spendable balance of a basket, in satoshis.
    public func balance(basket: String = "default") async throws -> Int64 {
        let outputs = try await storage.listOutputs(
            auth, try WalletListOutputsRequest(basket: basket)
        )
        return outputs.outputs.reduce(0) { $0 + Int64($1.satoshis) }
    }

    /// The wallet's transaction history, most work left to the caller's request.
    public func history(
        _ request: WalletListActionsRequest? = nil
    ) async throws -> WalletListActionsResult {
        try await storage.listActions(auth, request ?? (try WalletListActionsRequest(labels: [])))
    }

    // MARK: - Receiving

    /// A receiving address, derived at the given index under the 1Sat deposit convention
    /// (`OneSatDeposit`) — the same derivation the live `@1sat/actions` uses, so any wallet
    /// binding this identity key derives the same default addresses. Index 0 is the primary
    /// address a wallet usually displays.
    public func receiveAddress(
        index: Int = 0, network: BitcoinNetwork = .mainnet
    ) throws -> String {
        try OneSatDeposit.address(identity: identityKey, index: index, network: network)
            .description
    }

    /// A run of receiving addresses, for scanning the chain or handing out fresh ones.
    public func receiveAddresses(
        startIndex: Int, count: Int, network: BitcoinNetwork = .mainnet
    ) throws -> [String] {
        try (startIndex..<startIndex + count).map {
            try receiveAddress(index: $0, network: network)
        }
    }

    /// Pays the given outputs and broadcasts.
    ///
    /// The order is the point. Storage funds the action and returns it; the signer re-checks the
    /// outputs and the fee before any key is used, re-derives change from this wallet's own key,
    /// and signs; the signed transaction goes back as Atomic BEEF for storage to record and send.
    /// A failure at any step leaves the reserved inputs to be released by `abort`, never a
    /// half-sent payment.
    @discardableResult
    public func pay(
        _ outputs: [WalletCreateActionOutput],
        description: String,
        labels: [String] = []
    ) async throws -> SentPayment {
        try await sign(outputs, description: description, labels: labels).sent
    }

    /// Pays a recipient — a native address or a paymail — for an amount.
    ///
    /// Resolution is the whole point of this method: whatever the user typed becomes output
    /// scripts, and from there the payment is the ordinary one. A native address is one P2PKH
    /// output. A paymail is resolved through its host, which returns the outputs to pay and a
    /// reference; after the transaction is signed and broadcast, the signed BEEF is delivered back
    /// to that host so the recipient recognises the payment.
    ///
    /// A paymail whose delivery fails after the money has moved throws `paymailDeliveryFailed`
    /// carrying the txid — the payment is on chain, but the recipient's host was not told, and the
    /// caller must know both facts.
    @discardableResult
    public func pay(
        to recipient: String,
        satoshis: UInt64,
        description: String,
        labels: [String] = [],
        paymail resolver: Paymail = Paymail()
    ) async throws -> SentPayment {
        if Paymail.isPaymail(recipient) {
            let destination = try await resolver.paymentDestination(
                paymail: recipient, satoshis: satoshis
            )
            let outputs = try destination.outputs.map { output in
                try WalletCreateActionOutput(
                    lockingScript: output.lockingScript,
                    satoshis: output.satoshis,
                    outputDescription: description
                )
            }
            let result = try await sign(outputs, description: description, labels: labels)
            do {
                try await resolver.deliver(
                    beef: try result.signed.atomicBEEF(),
                    to: recipient,
                    reference: destination.reference
                )
            } catch {
                throw WalletError.paymailDeliveryFailed(
                    txid: result.sent.transactionID.displayHex
                )
            }
            return result.sent
        }

        // A native address: one P2PKH output for the whole amount.
        let script = try Script.payToPublicKeyHash(
            try Address(recipient).publicKeyHash, maximumByteCount: 1 << 20
        )
        let output = try WalletCreateActionOutput(
            lockingScript: script.bytes, satoshis: satoshis, outputDescription: description
        )
        return try await pay([output], description: description, labels: labels)
    }

    /// Funds, signs and broadcasts the outputs, returning both the signed action (for a paymail
    /// BEEF delivery) and the receipt.
    private func sign(
        _ outputs: [WalletCreateActionOutput],
        description: String,
        labels: [String]
    ) async throws -> (signed: SignedAction, sent: SentPayment) {
        let request = try WalletCreateActionRequest(
            description: description, outputs: outputs, labels: labels
        )
        let funded = try await storage.createAction(auth, request)

        let transaction = try ActionSigner.sign(
            funded,
            requested: outputs,
            identityKey: identityKey,
            senderPublicKey: identityKey.publicKey,
            maximumFee: maximumFee
        )

        let signed = try SignedAction(funded: funded, transaction: transaction)
        let result = try await storage.processAction(auth, try signed.processRequest())

        return (
            signed,
            SentPayment(
                transactionID: signed.transactionID,
                reference: funded.reference,
                results: result.sendWithResults
            )
        )
    }

    /// Abandons a funded action, releasing its reserved inputs.
    ///
    /// `reference` is the opaque base64 string storage returned on the funded action. It is decoded
    /// back to bytes here so the request re-encodes to exactly that string.
    @discardableResult
    public func abort(reference: String) async throws -> Bool {
        guard let bytes = Data(base64Encoded: reference) else {
            throw WalletError.invalidReference
        }
        let request = try WalletAbortActionRequest(reference: try WalletBase64Data(Array(bytes)))
        return try await storage.abortAction(auth, request).aborted
    }
}

/// The outcome of a payment that reached storage.
public struct SentPayment: Sendable {
    public let transactionID: TransactionID
    public let reference: String
    public let results: [SendWithResult]

    public init(transactionID: TransactionID, reference: String, results: [SendWithResult]) {
        self.transactionID = transactionID
        self.reference = reference
        self.results = results
    }
}
