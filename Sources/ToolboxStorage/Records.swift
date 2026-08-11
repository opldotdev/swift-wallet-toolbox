import Foundation
import ToolboxCore

/// The records the storage protocol moves.
///
/// Names follow the wire, because these cross a boundary shared with the TypeScript and Go
/// implementations and a private spelling would help nobody. Shapes are Swift: a status is an enum
/// rather than a string, and a satoshi amount is `Int64` rather than a floating-point number.
///
/// This file is deliberately narrow. It carries what the v1 action lifecycle needs and stops
/// there; certificate and commission records arrive with the features that read them.

// MARK: - Settings and baskets

public struct StorageSettings: Equatable, Sendable {
    public let storageIdentityKey: String
    public let storageName: String
    public let chain: Chain

    public init(storageIdentityKey: String, storageName: String, chain: Chain) {
        self.storageIdentityKey = storageIdentityKey
        self.storageName = storageName
        self.chain = chain
    }
}

public enum Chain: String, Equatable, Sendable {
    case main
    case test
}

public struct StorageOutputBasket: Equatable, Sendable {
    public let basketID: Int
    public let name: String
    /// How many outputs the wallet keeps in this basket before it stops making more.
    public let numberOfDesiredUTXOs: Int
    public let minimumDesiredUTXOValue: Int64

    public init(basketID: Int, name: String, numberOfDesiredUTXOs: Int,
                minimumDesiredUTXOValue: Int64) {
        self.basketID = basketID
        self.name = name
        self.numberOfDesiredUTXOs = numberOfDesiredUTXOs
        self.minimumDesiredUTXOValue = minimumDesiredUTXOValue
    }
}

// MARK: - Outputs

public struct StorageOutput: Equatable, Sendable {
    public let outputID: Int
    public let transactionID: Int
    public let basketID: Int?
    public let spendable: Bool
    /// True when this output is the wallet's own change rather than a payment it received.
    public let change: Bool
    public let satoshis: Int64
    public let outputIndex: UInt32
    public let lockingScript: [UInt8]?
    /// BRC-29 derivation, stored per output because the key that unlocks it cannot be found
    /// without them.
    public let derivationPrefix: String?
    public let derivationSuffix: String?

    public init(outputID: Int, transactionID: Int, basketID: Int?, spendable: Bool, change: Bool,
                satoshis: Int64, outputIndex: UInt32, lockingScript: [UInt8]?,
                derivationPrefix: String?, derivationSuffix: String?) {
        self.outputID = outputID
        self.transactionID = transactionID
        self.basketID = basketID
        self.spendable = spendable
        self.change = change
        self.satoshis = satoshis
        self.outputIndex = outputIndex
        self.lockingScript = lockingScript
        self.derivationPrefix = derivationPrefix
        self.derivationSuffix = derivationSuffix
    }
}

// MARK: - Transactions

/// Where a transaction has reached. The wallet's own view, not the chain's.
public enum TransactionStatus: String, Equatable, Sendable {
    case unprocessed
    case unsigned
    case unproven
    case sending
    case completed
    case failed
    case nosend
}

// MARK: - Queries

public struct FindOutputsQuery: Equatable, Sendable {
    public let auth: AuthID
    public let basket: String?
    public let spendable: Bool?
    public let limit: Int?

    public init(auth: AuthID, basket: String? = nil, spendable: Bool? = nil, limit: Int? = nil) {
        self.auth = auth
        self.basket = basket
        self.spendable = spendable
        self.limit = limit
    }
}

public struct FindBasketsQuery: Equatable, Sendable {
    public let auth: AuthID
    public let name: String?

    public init(auth: AuthID, name: String? = nil) {
        self.auth = auth
        self.name = name
    }
}
