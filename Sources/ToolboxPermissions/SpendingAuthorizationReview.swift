import BSVTransaction
import BSVWallet

/// Authoritative amounts for a BRC-116 spend prompt. Construct only from a transaction whose
/// input source outputs have been resolved from verified BEEF, before signing or broadcasting.
public struct SpendingAuthorizationReview: Equatable, Sendable {
    public let requestedOutputSatoshis: UInt64
    public let suppliedInputSatoshis: UInt64
    public let networkFee: UInt64
    /// Zero when caller-supplied inputs cover the requested outputs and fee.
    public let authorizationSatoshis: UInt64

    public enum ValidationError: Error, Equatable, Sendable {
        case missingRequestedOutput(Int)
        case duplicateInput
        case outputsExceedInputs
        case amountOverflow
    }

    public init(transaction: Transaction, request: WalletCreateActionRequest) throws {
        // Each actual output can satisfy only one requested output. Storage may reorder outputs
        // or append change, but may not substitute recipients, alter amounts, or collapse copies.
        var available = Set(transaction.outputs.indices)
        var requestedTotal: UInt64 = 0
        for (index, output) in (request.outputs ?? []).enumerated() {
            guard let match = available.first(where: {
                transaction.outputs[$0].satoshis == output.satoshis
                    && transaction.outputs[$0].lockingScript.bytes == output.lockingScript
            }) else { throw ValidationError.missingRequestedOutput(index) }
            available.remove(match)
            requestedTotal = try Self.add(requestedTotal, output.satoshis)
        }

        let totalInputs = try transaction.totalInputSatoshis()
        let totalOutputs = try transaction.totalOutputSatoshis()
        guard totalInputs >= totalOutputs else { throw ValidationError.outputsExceedInputs }
        let fee = totalInputs - totalOutputs
        let supplied = Set((request.inputs ?? []).map(\.outpoint))
        var seen = Set<Outpoint>()
        var suppliedTotal: UInt64 = 0
        for input in transaction.inputs {
            guard seen.insert(input.previousOutput).inserted else {
                throw ValidationError.duplicateInput
            }
            if supplied.contains(input.previousOutput), let source = input.sourceOutput {
                suppliedTotal = try Self.add(suppliedTotal, source.satoshis)
            }
        }
        let outflow = try Self.add(requestedTotal, fee)
        requestedOutputSatoshis = requestedTotal
        suppliedInputSatoshis = suppliedTotal
        networkFee = fee
        authorizationSatoshis = outflow > suppliedTotal ? outflow - suppliedTotal : 0
    }

    private static func add(_ lhs: UInt64, _ rhs: UInt64) throws -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else { throw ValidationError.amountOverflow }
        return sum
    }
}
