import Foundation
import BSVCore
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// Raised by the action-batch client for a request it cannot plan or a batch it cannot continue.
public enum ActionBatchError: Error, Equatable, Sendable, LocalizedError {
    /// The reserved funding, plus whatever storage would add, does not cover the action.
    case insufficientFunds(moreSatoshisNeeded: UInt64)
    /// An input or `fundFrom` outpoint cannot be used as given.
    case invalidInput(String)
    /// The batch is in a state where the call makes no sense.
    case invalidOperation(String)
    /// The commit would exceed what storage accepts inline. Uploading blobs is not implemented.
    case manifestTooLarge(bytes: Int, limit: Int)

    public var errorDescription: String? {
        switch self {
        case .insufficientFunds(let more): "Action batch needs \(more) more satoshis."
        case .invalidInput(let reason): "Action batch input: \(reason)"
        case .invalidOperation(let reason): "Action batch: \(reason)"
        case .manifestTooLarge(let bytes, let limit):
            "Action batch commit of \(bytes) bytes exceeds the \(limit)-byte inline limit."
        }
    }
}

/// An output the planner may spend: reserved by storage, named explicitly, or staged by an
/// earlier member of the batch (`TableOutput` plus the planner's `basketName`).
struct PlannerOutput: Equatable, Sendable {
    var outputId: Int
    var txid: String
    var vout: UInt32
    var satoshis: UInt64
    var change: Bool
    var providedBy: String
    var purpose: String
    var type: String
    var basketName: String?
    var tags: [String]?
    var derivationPrefix: String?
    var derivationSuffix: String?
    var senderIdentityKey: String?
    var customInstructions: String?
    var lockingScript: [UInt8]?

    var outpoint: String { "\(txid).\(vout)" }

    init(
        outputId: Int, txid: String, vout: UInt32, satoshis: UInt64, change: Bool,
        providedBy: String, purpose: String, type: String, basketName: String? = nil,
        tags: [String]? = nil, derivationPrefix: String? = nil, derivationSuffix: String? = nil,
        senderIdentityKey: String? = nil, customInstructions: String? = nil,
        lockingScript: [UInt8]? = nil
    ) {
        self.outputId = outputId
        self.txid = txid
        self.vout = vout
        self.satoshis = satoshis
        self.change = change
        self.providedBy = providedBy
        self.purpose = purpose
        self.type = type
        self.basketName = basketName
        self.tags = tags
        self.derivationPrefix = derivationPrefix
        self.derivationSuffix = derivationSuffix
        self.senderIdentityKey = senderIdentityKey
        self.customInstructions = customInstructions
        self.lockingScript = lockingScript
    }

    /// `addPlannerOutputs`: a storage row, without its source transaction (that goes into the
    /// shared proof graph instead).
    init(_ row: ActionBatchFundingOutput, basketName: String?) {
        self.init(
            outputId: row.outputId, txid: row.txid, vout: row.vout, satoshis: row.satoshis,
            change: row.change, providedBy: row.providedBy, purpose: row.purpose, type: row.type,
            basketName: basketName, derivationPrefix: row.derivationPrefix,
            derivationSuffix: row.derivationSuffix, senderIdentityKey: row.senderIdentityKey,
            customInstructions: row.customInstructions, lockingScript: row.lockingScript
        )
    }
}

/// One planned input, in the reference's `StorageCreateTransactionSdkInput` shape.
struct PlannedInput: Equatable, Sendable {
    let vin: UInt32
    let sourceTxid: String
    let sourceVout: UInt32
    let sourceSatoshis: UInt64
    let sourceLockingScript: [UInt8]
    let unlockingScriptLength: UInt32
    let providedBy: String
    let type: String
    let spendingDescription: String?
    let derivationPrefix: String?
    let derivationSuffix: String?
    let senderIdentityKey: String?

    /// The plan's input as the manifest carries it. Format 2 leaves out `sourceLockingScript`
    /// and `sourceTransaction`, which storage derives from the proven source output.
    var compactJSON: OrderedJSON {
        .record([
            "vin": .int(vin),
            "sourceTxid": .string(sourceTxid),
            "sourceVout": .int(sourceVout),
            "sourceSatoshis": .int(sourceSatoshis),
            "unlockingScriptLength": .int(unlockingScriptLength),
            "providedBy": .string(providedBy),
            "type": .string(type),
            "spendingDescription": spendingDescription.map { .string($0) },
            "derivationPrefix": derivationPrefix.map { .string($0) },
            "derivationSuffix": derivationSuffix.map { .string($0) },
            "senderIdentityKey": senderIdentityKey.map { .string($0) },
        ])
    }

    var storageInput: StorageActionInput {
        StorageActionInput(
            sourceTXID: sourceTxid, sourceVout: sourceVout, sourceSatoshis: Int64(sourceSatoshis),
            sourceLockingScript: sourceLockingScript, unlockingScriptLength: unlockingScriptLength,
            derivationPrefix: derivationPrefix, derivationSuffix: derivationSuffix,
            senderIdentityKey: senderIdentityKey, vin: vin
        )
    }
}

/// One planned output (`StorageCreateTransactionSdkOutput`): a requested output, or change.
struct PlannedOutput: Equatable, Sendable {
    var vout: UInt32
    let satoshis: UInt64
    /// The caller's output, for a requested one; `nil` for change.
    let requested: WalletCreateActionOutput?
    let changeBasket: String
    let derivationSuffix: String?

    var isChange: Bool { requested == nil }

    /// `{ ...output, lockingScript: '' }` of the reference plan's output.
    func compactJSON() throws -> OrderedJSON {
        if let requested {
            return try ActionBatchWire.output(requested, lockingScript: "")
                .setting("vout", .int(vout))
                .setting("providedBy", .string("you"))
        }
        return .record([
            "vout": .int(vout),
            "satoshis": .int(satoshis),
            "lockingScript": .string(""),
            "providedBy": .string("storage"),
            "purpose": .string("change"),
            "basket": .string(changeBasket),
            "tags": .array([]),
            "outputDescription": .string(""),
            "derivationSuffix": derivationSuffix.map { .string($0) },
        ])
    }

    var storageOutput: StorageActionOutput {
        StorageActionOutput(
            vout: vout, satoshis: satoshis, lockingScript: requested?.lockingScript ?? [],
            providedBy: isChange ? .storage : .you, purpose: isChange ? .change : nil,
            derivationSuffix: derivationSuffix
        )
    }
}

/// A planned, not yet signed, member action.
struct PlannedAction: Sendable {
    let reference: String
    let version: UInt32
    let lockTime: UInt32
    let inputs: [PlannedInput]
    let outputs: [PlannedOutput]
    let derivationPrefix: String
    /// The request's `noSend`, the one source for both the plan's change vouts below and the
    /// manifest metadata's `isNoSend`, which storage requires to agree.
    let isNoSend: Bool
    /// The change vouts, present exactly when the action is `noSend`, as storage checks.
    let noSendChangeOutputVouts: [UInt32]?
    let request: WalletCreateActionRequest
    let consumedOutpoints: [String]
    let result: StorageCreateActionResult
}

/// The planner's view of the batch (`ActionBatchPlannerState`).
struct PlannerState: Sendable {
    let begin: ActionBatchBegin
    var sharedBeef: BEEF
    var reserved: [String: PlannerOutput] = [:]
    var explicit: [String: PlannerOutput] = [:]
    var staged: [String: PlannerOutput] = [:]
    var consumed: Set<String> = []

    static let beefLimits = WalletBEEFLimits.standard
    static let transactionLimits = WalletTransactionLimits.standard

    init(begin: ActionBatchBegin, firstActionBEEF: BEEF?) throws {
        self.begin = begin
        var beef = try BEEF(version: .v2, merklePaths: [], transactions: [], limits: Self.beefLimits)
        if let bytes = begin.inputBeef, !bytes.isEmpty {
            beef = try beef.merging(BEEF(bytes: bytes, limits: Self.beefLimits), limits: Self.beefLimits)
        }
        if let firstActionBEEF {
            beef = try beef.merging(firstActionBEEF, limits: Self.beefLimits)
        }
        sharedBeef = beef
        for row in begin.reservedOutputs + begin.explicitOutputs {
            if let raw = row.sourceTransaction { try mergeRawTransaction(raw) }
        }
        add(reserved: begin.reservedOutputs, explicit: begin.explicitOutputs)
    }

    mutating func add(reserved rows: [ActionBatchFundingOutput], explicit explicitRows: [ActionBatchFundingOutput]) {
        for row in rows {
            reserved[row.outpoint] = PlannerOutput(row, basketName: begin.changeBasket.name)
        }
        for row in explicitRows {
            explicit[row.outpoint] = PlannerOutput(row, basketName: nil)
        }
    }

    mutating func merge(_ beef: BEEF) throws {
        sharedBeef = try sharedBeef.merging(beef, limits: Self.beefLimits)
    }

    mutating func mergeRawTransaction(_ bytes: [UInt8]) throws {
        let transaction = try Transaction(bytes: bytes, limits: Self.transactionLimits)
        try merge(BEEF(version: .v2, merklePaths: [], transactions: [.raw(transaction)], limits: Self.beefLimits))
    }

    func transaction(_ txid: String) -> Transaction? {
        guard let id = try? TransactionID(displayHex: txid) else { return nil }
        return try? sharedBeef.transaction(for: id, limits: Self.transactionLimits)
    }

    /// `outputFromBeef`: an output known only from the proof graph, treated as the caller's.
    func outputFromBeef(_ outpoint: Outpoint) -> PlannerOutput? {
        let txid = outpoint.transactionID.displayHex
        guard let transaction = transaction(txid),
              transaction.outputs.indices.contains(Int(outpoint.outputIndex)) else { return nil }
        return PlannerOutput(
            outputId: -1, txid: txid, vout: outpoint.outputIndex,
            satoshis: transaction.outputs[Int(outpoint.outputIndex)].satoshis,
            change: false, providedBy: "you", purpose: "", type: "custom"
        )
    }

    /// `resolveInputOutput`: staged, then explicit, then reserved, then the proof graph.
    func resolve(_ outpoint: Outpoint) throws -> PlannerOutput {
        let key = outpoint.description
        if let output = staged[key] ?? explicit[key] ?? reserved[key] ?? outputFromBeef(outpoint) {
            return output
        }
        throw ActionBatchError.invalidInput("no proof data for \(key)")
    }

    /// `plannerOutputLockingScript`: the row's script, or the one in its transaction.
    func lockingScript(of output: PlannerOutput) throws -> [UInt8] {
        if let script = output.lockingScript { return script }
        guard let transaction = transaction(output.txid),
              transaction.outputs.indices.contains(Int(output.vout)) else {
            throw ActionBatchError.invalidOperation("output \(output.outpoint) is missing its script")
        }
        return transaction.outputs[Int(output.vout)].lockingScript.bytes
    }

    /// True when the outpoint is already known to the batch, so no extension is needed for it.
    func knows(_ outpoint: Outpoint) -> Bool {
        let key = outpoint.description
        return staged[key] != nil || explicit[key] != nil || reserved[key] != nil
            || transaction(outpoint.transactionID.displayHex) != nil
    }

    /// `stageTransactionOutputs`: a processed member's outputs become spendable by the next.
    mutating func stage(_ planned: PlannedAction, txid: String, transaction: Transaction) throws {
        for output in planned.outputs {
            let isChange = output.isChange
            let staged = PlannerOutput(
                outputId: -(self.staged.count + 1), txid: txid, vout: output.vout,
                satoshis: output.satoshis, change: isChange,
                providedBy: isChange ? "storage" : "you", purpose: isChange ? "change" : "",
                type: isChange ? "P2PKH" : "custom",
                basketName: isChange ? output.changeBasket : output.requested?.basket,
                tags: isChange ? [] : output.requested?.tags,
                derivationPrefix: isChange ? planned.derivationPrefix : nil,
                derivationSuffix: output.derivationSuffix,
                customInstructions: output.requested?.customInstructions
            )
            self.staged[staged.outpoint] = staged
        }
        try merge(BEEF(version: .v2, merklePaths: [], transactions: [.raw(transaction)], limits: Self.beefLimits))
    }
}

/// Plans one member action against the batch's reservations and staged outputs.
///
/// A port of `ActionBatchPlanner.planAction` with one deliberate simplification: funding is a
/// single change output, not `generateChangeSdk`'s pool shaping. Storage validates only the
/// properties this keeps — the fee is at least the fee model's minimum for the signed size, change
/// carries canonical metadata, and every requested output appears unchanged — so a shaped pool is
/// an optimisation the batch can do without. Surplus too small for a change output worth spending
/// goes to the fee, as it does in the reference's one-way fallback.
enum ActionBatchPlanner {
    /// `maxPossibleSatoshis`: an output asking for "everything else". Not planned here.
    static let maxPossibleSatoshis: UInt64 = 2_099_999_999_999_999
    static let changeLockingScriptLength = 25
    static let changeUnlockingScriptLength = 107

    static func plan(
        _ state: inout PlannerState, request: WalletCreateActionRequest, fundFrom: [Outpoint]
    ) throws -> PlannedAction {
        let requestedInputs = request.inputs ?? []
        let requestedOutputs = request.outputs ?? []
        let options = request.options
        let isNoSend = options?.noSend ?? false

        try validateOutpoints(state, requestedInputs.map(\.outpoint) + fundFrom)

        let explicit = try requestedInputs.map { try state.resolve($0.outpoint) }
        if explicit.contains(where: \.change) {
            throw ActionBatchError.invalidInput("unmanaged inputs; use fundFrom for managed change")
        }
        let managed = try fundFrom.map { outpoint -> PlannerOutput in
            let output = try state.resolve(outpoint)
            guard output.change, output.type == "P2PKH", output.providedBy == "storage",
                  output.purpose == "change", output.derivationPrefix != nil,
                  output.derivationSuffix != nil else {
                throw ActionBatchError.invalidInput("fundFrom \(outpoint) is not wallet-managed change")
            }
            return output
        }

        let funding = try fund(
            state, explicit: explicit, requestedInputs: requestedInputs,
            requestedOutputs: requestedOutputs, fundFrom: managed
        )

        let derivationPrefix = randomBase64(16)
        var outputs = requestedOutputs.enumerated().map { index, output in
            PlannedOutput(
                vout: UInt32(index), satoshis: output.satoshis, requested: output,
                changeBasket: state.begin.changeBasket.name, derivationSuffix: nil
            )
        }
        if let change = funding.change {
            outputs.append(PlannedOutput(
                vout: UInt32(outputs.count), satoshis: change, requested: nil,
                changeBasket: state.begin.changeBasket.name, derivationSuffix: randomBase64(16)
            ))
        }
        if options?.randomizeOutputs ?? true {
            randomizeVouts(&outputs)
        }

        var inputs: [PlannedInput] = []
        for (index, output) in explicit.enumerated() {
            let input = requestedInputs[index]
            inputs.append(PlannedInput(
                vin: UInt32(inputs.count), sourceTxid: output.txid, sourceVout: output.vout,
                sourceSatoshis: output.satoshis, sourceLockingScript: try state.lockingScript(of: output),
                unlockingScriptLength: unlockingLength(input.unlocking),
                providedBy: output.providedBy == "storage" ? "you-and-storage" : output.providedBy,
                type: output.type, spendingDescription: input.inputDescription,
                derivationPrefix: output.derivationPrefix, derivationSuffix: output.derivationSuffix,
                senderIdentityKey: output.senderIdentityKey
            ))
        }
        for output in funding.allocated {
            inputs.append(PlannedInput(
                vin: UInt32(inputs.count), sourceTxid: output.txid, sourceVout: output.vout,
                sourceSatoshis: output.satoshis, sourceLockingScript: try state.lockingScript(of: output),
                unlockingScriptLength: UInt32(changeUnlockingScriptLength), providedBy: "storage",
                type: "P2PKH", spendingDescription: nil, derivationPrefix: output.derivationPrefix,
                derivationSuffix: output.derivationSuffix, senderIdentityKey: output.senderIdentityKey
            ))
        }

        let consumed = funding.allocated.map(\.outpoint) + requestedInputs.map(\.outpoint.description)
        let reference = randomBase64(12)
        let inputBEEF = try trimmedInputBEEF(state, request: request, inputs: inputs)
        let result = StorageCreateActionResult(
            reference: reference,
            version: request.version ?? 1,
            lockTime: request.lockTime ?? 0,
            outputs: outputs.map(\.storageOutput),
            inputs: inputs.map(\.storageInput),
            inputBEEF: inputBEEF,
            derivationPrefix: derivationPrefix
        )
        // Only now, with nothing left to fail, does the plan touch the batch's state.
        state.consumed.formUnion(consumed)
        return PlannedAction(
            reference: reference,
            version: result.version,
            lockTime: result.lockTime,
            inputs: inputs,
            outputs: outputs,
            derivationPrefix: derivationPrefix,
            isNoSend: isNoSend,
            noSendChangeOutputVouts: isNoSend ? outputs.filter(\.isChange).map(\.vout) : nil,
            request: request,
            consumedOutpoints: consumed,
            result: result
        )
    }

    /// The description bounds of `validateCreateActionArgs` (`@bsv/sdk` `validateStringLength`
    /// with 5 and 2000 UTF-8 bytes) for the action, each input and each output, and its label,
    /// tag and basket bounds (`validateIdentifier`, 1 to 300 bytes after trimming).
    ///
    /// Storage runs that validator again over every member's metadata when the batch commits
    /// (`validateActionMetadata`), which is after the whole chain is staged. Checking here refuses
    /// such a request before anything is reserved. The errors are the validator's own.
    static func validateMetadata(_ request: WalletCreateActionRequest) throws {
        try validateDescription(request.description, name: "description")
        for input in request.inputs ?? [] {
            try validateDescription(input.inputDescription, name: "inputDescription")
        }
        for output in request.outputs ?? [] {
            try validateDescription(output.outputDescription, name: "outputDescription")
            if let basket = output.basket { try validateIdentifier(basket, name: "basket") }
            for tag in output.tags { try validateIdentifier(tag, name: "tag") }
        }
        for label in request.labels ?? [] { try validateIdentifier(label, name: "label") }
    }

    static let identifierBytes = ActionBatchWire.identifierBytes

    /// `validateIdentifier` for labels, tags and baskets: trimmed and lowercased, 1 to 300 UTF-8
    /// bytes.
    private static func validateIdentifier(_ text: String, name: String) throws {
        _ = try ActionBatchWire.identifier(text, name: name)
    }

    static let descriptionBytes = 5...2000

    private static func validateDescription(_ text: String, name: String) throws {
        let bytes = text.utf8.count
        if bytes < descriptionBytes.lowerBound {
            throw WireError.invalidParameter(name: name, message: "at least \(descriptionBytes.lowerBound) length.")
        }
        if bytes > descriptionBytes.upperBound {
            throw WireError.invalidParameter(name: name, message: "no more than \(descriptionBytes.upperBound) length.")
        }
    }

    /// `validateActionOutpoints`: no outpoint twice, none already spent within the batch.
    static func validateOutpoints(_ state: PlannerState, _ outpoints: [Outpoint]) throws {
        var seen = Set<String>()
        for outpoint in outpoints {
            let key = outpoint.description
            guard seen.insert(key).inserted else {
                throw ActionBatchError.invalidInput("\(key) is repeated")
            }
            guard !state.consumed.contains(key) else {
                throw ActionBatchError.invalidInput("\(key) is already consumed by this action batch")
            }
        }
    }

    struct Funding {
        var allocated: [PlannerOutput]
        var change: UInt64?
    }

    /// Chooses funding inputs and the change amount.
    ///
    /// `fundFrom` outputs are taken first, last one first as the reference pops its
    /// `noSendChange` list, then unconsumed reservations by the canonical exact / least-over /
    /// largest-under rule. Inputs are added until the action can pay its fee and a change output
    /// worth at least the dust floor; failing that, until it can pay its fee with no change.
    ///
    /// The no-change fallback is tried only once every `fundFrom` output and every unconsumed
    /// reservation has been allocated, so an action that ends there spends the batch's whole
    /// reserved pool, and its surplus (less than the dust floor plus a change output's fee) goes
    /// to the fee. A later member then has to extend the batch for its own funding. This is
    /// kept deliberately: it is reached only when the pool barely covers the action.
    static func fund(
        _ state: PlannerState, explicit: [PlannerOutput], requestedInputs: [WalletCreateActionInput],
        requestedOutputs: [WalletCreateActionOutput], fundFrom: [PlannerOutput]
    ) throws -> Funding {
        let rate = state.begin.feeModel.value
        let dust = dustFloor(rate: rate)
        let fixedInputSatoshis = explicit.reduce(UInt64(0)) { $0 + $1.satoshis }
        let fixedInputLengths = requestedInputs.map { Int(unlockingLength($0.unlocking)) }
        let outputSatoshis = requestedOutputs.reduce(UInt64(0)) { $0 + $1.satoshis }
        let outputLengths = requestedOutputs.map(\.lockingScript.count)
        var queue = fundFrom
        var allocated: [PlannerOutput] = []
        var candidates = state.reserved.values.filter { !state.consumed.contains($0.outpoint) }

        while true {
            let inputSatoshis = fixedInputSatoshis + allocated.reduce(UInt64(0)) { $0 + $1.satoshis }
            let inputLengths = fixedInputLengths
                + Array(repeating: changeUnlockingScriptLength, count: allocated.count)
            let feeWithChange = fee(
                size: transactionSize(inputLengths, outputLengths + [changeLockingScriptLength]), rate: rate
            )
            let neededWithChange = outputSatoshis + feeWithChange + dust
            if inputSatoshis >= neededWithChange {
                return Funding(allocated: allocated, change: inputSatoshis - outputSatoshis - feeWithChange)
            }
            let marginalInputFee = fee(
                size: transactionSize(inputLengths + [changeUnlockingScriptLength], outputLengths + [changeLockingScriptLength]),
                rate: rate
            ) - feeWithChange
            let shortfall = neededWithChange - inputSatoshis
            if let next = queue.popLast() ?? selectCanonical(candidates, target: shortfall + marginalInputFee) {
                allocated.append(next)
                candidates.removeAll { $0.outpoint == next.outpoint }
                continue
            }
            let feeWithoutChange = fee(size: transactionSize(inputLengths, outputLengths), rate: rate)
            if !requestedOutputs.isEmpty, inputSatoshis >= outputSatoshis + feeWithoutChange {
                return Funding(allocated: allocated, change: nil)
            }
            throw ActionBatchError.insufficientFunds(moreSatoshisNeeded: shortfall + marginalInputFee)
        }
    }

    /// `selectCanonicalChange` without an exact target: the smallest output at or above the
    /// target, else the largest below it; ties broken by `outputId`.
    static func selectCanonical(_ outputs: [PlannerOutput], target: UInt64) -> PlannerOutput? {
        let over = outputs.filter { $0.satoshis >= target }
            .min { ($0.satoshis, $0.outputId) < ($1.satoshis, $1.outputId) }
        if let over { return over }
        return outputs.filter { $0.satoshis < target }
            .max { ($0.satoshis, $0.outputId) < ($1.satoshis, $1.outputId) }
    }

    /// The fee for a transaction of `size` bytes. Storage checks `ceil(size * rate / 1000)` and
    /// the reference planner charges `ceil(size / 1000 * rate)`; the larger of the two is paid so
    /// floating-point rounding can never put a planned fee one satoshi under storage's minimum.
    static func fee(size: Int, rate: Double) -> UInt64 {
        let server = (Double(size) * rate / 1000).rounded(.up)
        let planner = (Double(size) / 1000 * rate).rounded(.up)
        return UInt64(max(0, max(server, planner)))
    }

    /// `generateChangeSdk`'s dust floor: twice the fee of the smallest spend of one change output.
    static func dustFloor(rate: Double) -> UInt64 {
        let size = transactionSize([changeUnlockingScriptLength], [changeLockingScriptLength])
        return max(1, UInt64((Double(size) / 1000 * rate).rounded(.up)) * 2)
    }

    /// `transactionSize` from `storage/methods/utils.js`.
    static func transactionSize(_ inputs: [Int], _ outputs: [Int]) -> Int {
        4 + varIntSize(inputs.count)
            + inputs.reduce(0) { $0 + 32 + 4 + varIntSize($1) + $1 + 4 }
            + varIntSize(outputs.count)
            + outputs.reduce(0) { $0 + varIntSize($1) + $1 + 8 }
            + 4
    }

    static func varIntSize(_ value: Int) -> Int {
        switch value {
        case ...0xfc: 1
        case ...0xffff: 3
        case ...0xffff_ffff: 5
        default: 9
        }
    }

    static func unlockingLength(_ unlocking: WalletInputUnlocking) -> UInt32 {
        switch unlocking {
        case .script(let bytes): UInt32(bytes.count)
        case .scriptLength(let length): length
        }
    }

    /// `randomizeOutputVouts`: a Fisher-Yates shuffle of the vouts, outputs kept in array order.
    static func randomizeVouts(_ outputs: inout [PlannedOutput]) {
        var vouts = Array(0..<outputs.count)
        var current = vouts.count
        while current > 0 {
            let randomIndex = Int.random(in: 0..<current)
            vouts.swapAt(current - 1, randomIndex)
            current -= 1
        }
        for index in outputs.indices {
            outputs[index].vout = UInt32(vouts[index])
        }
    }

    /// `trimInputBeef`: the proof graph the signer needs for exactly these inputs.
    ///
    /// The reference also merges the caller's whole `inputBEEF` back in. Here it was merged into
    /// the shared graph when planning began, and the result is cut to the inputs' ancestry, because
    /// `SignedAction` builds BRC-95 Atomic BEEF from it and refuses any unrelated record.
    static func trimmedInputBEEF(
        _ state: PlannerState, request: WalletCreateActionRequest, inputs: [PlannedInput]
    ) throws -> [UInt8]? {
        if request.options?.returnTransactionIDOnly == true { return nil }
        let txids = try inputs.map { try TransactionID(displayHex: $0.sourceTxid) }
        let known = Set(request.options?.knownTransactionIDs ?? [])
        return try ActionBatchBEEF.subgraph(state.sharedBeef, txids: txids, known: known)
            .serialized(limits: PlannerState.beefLimits)
    }

    static func randomBase64(_ count: Int) -> String {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
        return Data(bytes).base64EncodedString()
    }
}

/// `beefForTxids`: the part of a proof graph that proves the given transactions.
enum ActionBatchBEEF {
    /// The given transactions and their unproven ancestry, walked until each line reaches a
    /// transaction with a merkle path. A transaction in `known` is kept as a transaction-ID-only
    /// record and not walked past, so the result is an exact graph `AtomicBEEF` accepts; the
    /// reference instead marks it ID-only and keeps the ancestry below it.
    static func subgraph(_ source: BEEF, txids: [TransactionID], known: Set<TransactionID> = []) throws -> BEEF {
        let limits = PlannerState.beefLimits
        var entries: [TransactionID: BEEFTransaction] = [:]
        for entry in source.transactions {
            entries[try entry.transactionID(limits: limits.transactionLimits)] = entry
        }
        var selected: [TransactionID: BEEFTransaction] = [:]
        var stack = txids
        while let txid = stack.popLast() {
            guard selected[txid] == nil, let entry = entries[txid] else { continue }
            if known.contains(txid), entry.transaction != nil {
                selected[txid] = .transactionID(txid)
                continue
            }
            selected[txid] = entry
            let proven = entry.merklePathIndex != nil || source.merklePath(for: txid) != nil
            guard !proven, let transaction = entry.transaction else { continue }
            for input in transaction.inputs where selected[input.previousOutput.transactionID] == nil {
                stack.append(input.previousOutput.transactionID)
            }
        }

        var pathIndexes = Set<Int>()
        for (txid, entry) in selected {
            if let index = entry.merklePathIndex {
                pathIndexes.insert(index)
            } else if entry.transaction != nil, let path = source.merklePath(for: txid),
                      let index = source.merklePaths.firstIndex(of: path) {
                pathIndexes.insert(index)
            }
        }
        var remap: [Int: Int] = [:]
        var paths: [MerklePath] = []
        for (index, path) in source.merklePaths.enumerated() where pathIndexes.contains(index) {
            remap[index] = paths.count
            paths.append(path)
        }
        var transactions: [BEEFTransaction] = []
        for entry in source.transactions {
            let txid = try entry.transactionID(limits: limits.transactionLimits)
            guard let chosen = selected[txid] else { continue }
            if case .rawWithMerklePath(let transaction, let index) = chosen, let mapped = remap[index] {
                transactions.append(.rawWithMerklePath(transaction: transaction, merklePathIndex: mapped))
            } else {
                transactions.append(chosen)
            }
        }
        let hasIDOnly = transactions.contains { $0.format == .transactionIDOnly }
        return try BEEF(
            version: hasIDOnly ? .v2 : source.version,
            merklePaths: paths,
            transactions: transactions,
            limits: limits
        )
    }
}
