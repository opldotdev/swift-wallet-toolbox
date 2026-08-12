import Foundation
import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxActions
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

    /// Restores a wallet from its recovery phrase.
    ///
    /// The phrase is the whole backup: it produces the identity key, which both authenticates to
    /// storage and signs. The derivation matches Yours Wallet exactly (`MnemonicRestore`), so a
    /// phrase written down there restores the same wallet here — same addresses, same coins.
    ///
    /// `nothing reaches the network`; the handshake waits for the first call, like every other
    /// path into `RemoteWallet`.
    public static func restore(
        fromPhrase phrase: String,
        passphrase: String = "",
        endpoint: URL = RemoteStorage.defaultEndpoint,
        maximumFee: Int64 = 100_000
    ) throws -> RemoteWallet {
        let identityKey = try MnemonicRestore.identityKey(
            fromPhrase: phrase, passphrase: passphrase
        )
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

        return SentPayment(
            transactionID: signed.transactionID,
            reference: funded.reference,
            results: result.sendWithResults
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
