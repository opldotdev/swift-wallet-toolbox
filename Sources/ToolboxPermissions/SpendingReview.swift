import BSVTransaction
import BSVWallet

/// Authoritative amounts for a prepared, unsigned wallet action. Matches the
/// TypeScript permissions manager's requested outputs + fee - caller inputs,
/// plus any separately validated storage commission so approval covers the whole debit.
/// Wallet funding inputs and wallet change are not caller flows.
public struct SpendingReview: Equatable, Sendable {
    public enum ReviewError: Error, Equatable, Sendable {
        case missingTransaction
        case missingSourceOutput
        case duplicateInput
        case missingRequestedInput
        case missingRequestedOutput
        case amountOverflow
        case outputsExceedInputs
    }

    public let requestedOutputSatoshis: UInt64
    public let callerInputSatoshis: UInt64
    public let feeSatoshis: UInt64
    public let walletSpendSatoshis: UInt64
    public let storageCommissionSatoshis: UInt64

    public init(
        request: WalletCreateActionRequest,
        prepared: AtomicBEEF,
        limits: TransactionLimits,
        storageCommissionSatoshis: UInt64 = 0
    ) throws {
        guard let transaction = try prepared.beef.transaction(
            for: prepared.subjectTransactionID, limits: limits
        ) else { throw ReviewError.missingTransaction }
        var sources: [Outpoint: TransactionOutput] = [:]
        for input in transaction.inputs {
            guard let source = try prepared.beef.transaction(
                for: input.previousOutput.transactionID, limits: limits
            ), Int(input.previousOutput.outputIndex) < source.outputs.count else {
                throw ReviewError.missingSourceOutput
            }
            sources[input.previousOutput] = source.outputs[Int(input.previousOutput.outputIndex)]
        }
        try self.init(request: request, transaction: transaction, sourceOutputs: sources,
                      storageCommissionSatoshis: storageCommissionSatoshis)
    }

    /// Source amounts must come from the prepared transaction's verified BEEF,
    /// never an amount or description supplied by the calling application.
    public init(
        request: WalletCreateActionRequest,
        transaction: Transaction,
        sourceOutputs: [Outpoint: TransactionOutput],
        storageCommissionSatoshis: UInt64 = 0
    ) throws {
        func sum(_ values: [UInt64]) throws -> UInt64 {
            try values.reduce(0) { total, amount in
                let (next, overflow) = total.addingReportingOverflow(amount)
                guard !overflow else { throw ReviewError.amountOverflow }
                return next
            }
        }
        let actualInputs = transaction.inputs.map(\.previousOutput)
        let requestedInputs = (request.inputs ?? []).map(\.outpoint)
        guard Set(actualInputs).count == actualInputs.count,
              Set(requestedInputs).count == requestedInputs.count else {
            throw ReviewError.duplicateInput
        }
        guard Set(requestedInputs).isSubset(of: Set(actualInputs)) else {
            throw ReviewError.missingRequestedInput
        }
        // Consume matching outputs individually: one actual output cannot
        // satisfy two identical caller outputs.
        var remaining = transaction.outputs
        for output in request.outputs ?? [] {
            guard let index = remaining.firstIndex(where: {
                $0.satoshis == output.satoshis && $0.lockingScript.bytes == output.lockingScript
            }) else { throw ReviewError.missingRequestedOutput }
            remaining.remove(at: index)
        }
        let inputTotal = try sum(actualInputs.map {
            guard let output = sourceOutputs[$0] else { throw ReviewError.missingSourceOutput }
            return output.satoshis
        })
        let outputTotal = try sum(transaction.outputs.map(\.satoshis))
        guard outputTotal <= inputTotal else { throw ReviewError.outputsExceedInputs }
        feeSatoshis = inputTotal - outputTotal
        requestedOutputSatoshis = try sum((request.outputs ?? []).map(\.satoshis))
        callerInputSatoshis = try sum(requestedInputs.map {
            guard let output = sourceOutputs[$0] else { throw ReviewError.missingSourceOutput }
            return output.satoshis
        })
        self.storageCommissionSatoshis = storageCommissionSatoshis
        let outflow = try sum([requestedOutputSatoshis, feeSatoshis, storageCommissionSatoshis])
        walletSpendSatoshis = outflow > callerInputSatoshis ? outflow - callerInputSatoshis : 0
    }
}
