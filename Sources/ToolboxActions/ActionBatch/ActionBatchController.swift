import Foundation
import BSVCore
import BSVTransaction
import BSVWallet
import ToolboxCore
import ToolboxStorage

/// Plans a chain of actions on the client and commits them to storage in one batch.
///
/// A port of `ActionBatchController` and `ActionBatchWorkspace` from `@bsv/wallet-toolbox`
/// 2.15.3 (`signer/actionBatch/`), narrowed to what a wallet that signs its own actions needs.
///
/// The case it exists for is a `noSend` action whose change funds the action after it: a SIGMA
/// anchor and the publish that spends it, from a wallet with a single unspent output. Ordinary
/// `createAction` cannot fund the second, because storage funds only from change whose
/// transaction is completed, unproven or sending. Here the first `noSend` action begins a batch;
/// storage reserves funding for it; the action is planned locally, signed, and staged in memory
/// without any storage call; the second action is planned from the first's outputs and change;
/// and the second's `process` commits both at once, with `sendWith` naming both.
///
/// Every call returns `nil` to mean "this request is not for the batch, use the ordinary call".
/// That is decided before anything is reserved, so a caller can always fall back:
///
///     let funded = try await batch.plan(auth, request) ?? storage.createAction(auth, request)
///     ...
///     let result = try await batch.process(auth, signed, sendWith: ..., isNoSend: ..., isDelayed: ...)
///         ?? storage.processAction(auth, signed.processRequest(...))
///
/// and on any failure after a batch-owned plan, `abort(_:)` releases the reservations.
///
/// Deliberate differences from the reference, each because the batch here only has to carry a
/// short chain of small actions:
/// - Funding makes one change output (`ActionBatchPlanner`); no pool shaping, no proactive
///   runway extension (the reference's EWMA), and commission-charging storage is not batched.
/// - Only format-2 manifests with every blob inline; a larger commit throws
///   `ActionBatchError.manifestTooLarge` instead of uploading. Storage that does not advertise
///   `manifestVersion: 2` is not batched.
/// - No `resume`: an expired lease is left to commit, which reacquires the inputs in storage as
///   it does for version-1 providers in the reference.
/// - `abort` releases the whole batch; there is no per-action `abortAction` rebuild.
/// - `listActions` and `listOutputs` do not see staged actions.
/// - BRC-177 expiry-labelled requests and "max satoshis" outputs are not batched.
/// - `fundFrom` stands in for `noSendChange` on a member that is not `noSend`, because the SDK's
///   createAction options refuse that combination while the reference planner accepts it.
public actor ActionBatchController {
    /// The reference begins a batch only for a first action with at most this many inputs.
    public static let maximumFirstActionInputs = 8

    private let storage: any ActionBatchStorage
    private let now: @Sendable () -> Date
    private var negotiated: ActionBatchCapabilities??
    private var workspace: ActionBatchWorkspace?
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init(storage: any ActionBatchStorage, now: @escaping @Sendable () -> Date = { Date() }) {
        self.storage = storage
        self.now = now
    }

    /// True while a batch holds reservations in storage.
    public var isActive: Bool { workspace != nil }

    /// The batch id storage knows this batch by, while one is active.
    public var batchId: String? { workspace?.batchId }

    /// True when `reference` names an action this batch planned or staged.
    public func owns(reference: String) -> Bool {
        workspace?.owns(reference) ?? false
    }

    // MARK: - Plan

    /// Funds `request` inside the batch, or returns `nil` for the ordinary `createAction`.
    ///
    /// With no batch active, a new `noSend` action with at most eight inputs begins one, when
    /// storage supports it. With a batch active, a request joins it only when it spends a staged
    /// output (an input or a `fundFrom` outpoint) or names a staged transaction in `sendWith`;
    /// unrelated work stays on the ordinary path.
    ///
    /// `fundFrom` is wallet-managed change to spend first, typically the `noSendChange` the
    /// previous member returned; it is added to any `noSendChange` in the request's options. It is
    /// ignored when the result is `nil`.
    ///
    /// The result is an ordinary funded action: assemble it with `ActionAssembler.assemble`, sign
    /// it, and wrap it with `SignedAction(funded:transaction:)`.
    public func plan(
        _ auth: AuthID, _ request: WalletCreateActionRequest, fundFrom: [Outpoint] = []
    ) async throws -> StorageCreateActionResult? {
        try await exclusive {
            try await self.planExclusive(auth, request, fundFrom: fundFrom)
        }
    }

    private func planExclusive(
        _ auth: AuthID, _ request: WalletCreateActionRequest, fundFrom extra: [Outpoint]
    ) async throws -> StorageCreateActionResult? {
        // A noSend request may name its managed change in options, as the reference does.
        var fundFrom: [Outpoint] = []
        for outpoint in (request.options?.noSendChange ?? []) + extra where !fundFrom.contains(outpoint) {
            fundFrom.append(outpoint)
        }
        let inputs = request.inputs ?? []
        let outputs = request.outputs ?? []
        guard !inputs.isEmpty || !outputs.isEmpty else { return nil }
        // A BRC-177 protected action is a different client protocol with its own storage calls.
        guard !(request.labels ?? []).contains(where: { $0.hasPrefix(NoSendExpiry.labelPrefix) }) else {
            return nil
        }
        guard !outputs.contains(where: { $0.satoshis == ActionBatchPlanner.maxPossibleSatoshis }) else {
            return nil
        }

        if let workspace {
            guard workspace.references(inputs.map(\.outpoint) + fundFrom, sendWith: request.options?.sendWith ?? []) else {
                return nil
            }
            do {
                return try await planInWorkspace(workspace, auth, request, fundFrom: fundFrom)
            } catch {
                throw await recovered(error, workspace)
            }
        }

        guard request.options?.noSend == true, inputs.count <= Self.maximumFirstActionInputs else {
            return nil
        }
        let begun: ActionBatchWorkspace
        do {
            guard let started = try await begin(auth, request) else { return nil }
            begun = started
        } catch {
            // The reservation ceiling bounds the optimisation, not createAction: a first action
            // that cannot fit keeps the ordinary path.
            if Self.isCapacityError(error) { return nil }
            throw error
        }
        // Storage commission would have to be paid by every member and validated at commit.
        // That is not ported, so such storage keeps the ordinary path.
        guard begun.state.begin.commissionSatoshis == 0 else {
            await retire(begun)
            return nil
        }
        do {
            return try await planInWorkspace(begun, auth, request, fundFrom: fundFrom)
        } catch {
            await retire(begun)
            if Self.isCapacityError(error) { return nil }
            throw error
        }
    }

    private func begin(_ auth: AuthID, _ request: WalletCreateActionRequest) async throws -> ActionBatchWorkspace? {
        guard let capabilities = await negotiate() else { return nil }
        let begin = try await storage.beginActionBatch(auth, ActionBatchBeginRequest(
            batchId: ActionBatchPlanner.randomBase64(24),
            firstAction: request,
            compact: capabilities.compactBegin
        ))
        let state = try PlannerState(begin: begin, firstActionBEEF: request.inputBEEF)
        let workspace = ActionBatchWorkspace(auth: auth, capabilities: capabilities, state: state)
        self.workspace = workspace
        return workspace
    }

    /// `getCapabilities` once per controller. A failure there is "no batch", not an error.
    private func negotiate() async -> ActionBatchCapabilities? {
        if let negotiated { return negotiated }
        let read: ActionBatchCapabilities?
        do {
            read = try await storage.actionBatchCapabilities()
        } catch {
            read = nil
        }
        // Format-1 manifests are not built here, so only storage that takes format 2 is batched.
        let usable = read.flatMap { $0.version == 1 && $0.manifestVersion == 2 ? $0 : nil }
        negotiated = .some(usable)
        return usable
    }

    private func planInWorkspace(
        _ workspace: ActionBatchWorkspace, _ auth: AuthID, _ request: WalletCreateActionRequest, fundFrom: [Outpoint]
    ) async throws -> StorageCreateActionResult {
        guard !workspace.committed else {
            throw ActionBatchError.invalidOperation("action batch is already committed")
        }
        try await renewIfNeeded(workspace, auth)
        if let beef = request.inputBEEF {
            try workspace.state.merge(beef)
        }
        let missing = ((request.inputs ?? []).map(\.outpoint) + fundFrom).filter { !workspace.state.knows($0) }
        if !missing.isEmpty {
            _ = try await extend(workspace, auth, target: 1, outputs: 1, explicit: missing)
        }
        var requestedOutputs = 8
        while true {
            do {
                let planned = try ActionBatchPlanner.plan(&workspace.state, request: request, fundFrom: fundFrom)
                workspace.planned[planned.reference] = planned
                return planned.result
            } catch ActionBatchError.insufficientFunds(let more) {
                // Only the reported shortfall is additional: the reserved pool was already
                // counted, and asking for the whole amount would double-count it.
                let added = try await extend(workspace, auth, target: more, outputs: requestedOutputs, explicit: [])
                if added.count == 0 || added.satoshis == 0 {
                    throw ActionBatchError.insufficientFunds(moreSatoshisNeeded: more)
                }
                requestedOutputs = min(requestedOutputs * 2, Int(Int32.max))
            }
        }
    }

    // MARK: - Process

    /// Stages a signed member, and commits the batch when the member is to be broadcast.
    ///
    /// Returns `nil` when `signed` was not planned by this batch. A `noSend` member that names no
    /// staged transaction in `sendWith` is staged only, with no storage call, and returns an empty
    /// result. Any other member commits every staged action in one manifest, with `sendWith`
    /// extended by this member's own txid when it is not `noSend`; the batch is then finished.
    public func process(
        _ auth: AuthID, _ signed: SignedAction, sendWith: [String] = [],
        isNoSend: Bool = false, isDelayed: Bool = false
    ) async throws -> StorageProcessActionResult? {
        try await exclusive {
            try await self.processExclusive(auth, signed, sendWith: sendWith, isNoSend: isNoSend, isDelayed: isDelayed)
        }
    }

    /// `process` with the flags read from createAction options, with the reference client's
    /// defaults (`noSend` false, `acceptDelayedBroadcast` true), as `SignedAction.processRequest`.
    public func process(
        _ auth: AuthID, _ signed: SignedAction, options: WalletCreateActionOptions?
    ) async throws -> StorageProcessActionResult? {
        try await process(
            auth, signed,
            sendWith: (options?.sendWith ?? []).map(\.displayHex),
            isNoSend: options?.noSend ?? false,
            isDelayed: options?.acceptDelayedBroadcast ?? true
        )
    }

    /// A broadcast-only call (`createAction` with no inputs or outputs and `sendWith` set).
    ///
    /// Returns `nil` unless `sendWith` names a staged transaction; otherwise commits the batch
    /// with exactly that `sendWith`, so staged `noSend` actions can be sent after the fact.
    public func send(
        _ auth: AuthID, sendWith: [String], isDelayed: Bool = false
    ) async throws -> StorageProcessActionResult? {
        try await exclusive {
            try await self.processExclusive(auth, nil, sendWith: sendWith, isNoSend: false, isDelayed: isDelayed)
        }
    }

    /// `ActionBatchController.process`; `signed` is the reference's `prior`.
    private func processExclusive(
        _ auth: AuthID, _ signed: SignedAction?, sendWith: [String], isNoSend: Bool, isDelayed: Bool
    ) async throws -> StorageProcessActionResult? {
        guard let workspace else { return nil }
        if let signed {
            guard workspace.owns(signed.reference) else { return nil }
        } else {
            guard sendWith.contains(where: { workspace.ownsTransaction($0) }) else { return nil }
        }
        if let signed {
            try workspace.stage(signed, isNoSend: isNoSend, isDelayed: isDelayed)
        }

        let referencesWorkspace = sendWith.contains { workspace.ownsTransaction($0) }
        if signed != nil, isNoSend, !sendWith.isEmpty, !referencesWorkspace {
            // The member belongs to the batch but its sendWith list does not. Keep it staged and
            // fulfil the unrelated broadcast the ordinary way rather than dropping it.
            return try await storage.processAction(auth, StorageProcessActionRequest(
                reference: "", isNewTx: false, isSendWith: true, rawTX: nil,
                sendWith: sendWith, isNoSend: false, isDelayed: isDelayed
            ))
        }
        guard referencesWorkspace || (signed != nil && !isNoSend) else {
            return StorageProcessActionResult(sendWithResults: [])
        }
        var commitSendWith = sendWith
        if let signed, !isNoSend {
            let txid = signed.transactionID.displayHex
            if !commitSendWith.contains(txid) { commitSendWith.append(txid) }
        }
        let result: ActionBatchCommitResult
        do {
            result = try await commit(workspace, auth, sendWith: commitSendWith, isDelayed: isDelayed)
        } catch {
            throw await recovered(error, workspace)
        }
        self.workspace = nil
        return StorageProcessActionResult(sendWithResults: result.sendWithResults)
    }

    private func commit(
        _ workspace: ActionBatchWorkspace, _ auth: AuthID, sendWith: [String], isDelayed: Bool
    ) async throws -> ActionBatchCommitResult {
        try await renewIfNeeded(workspace, auth)
        guard workspace.planned.isEmpty else {
            throw ActionBatchError.invalidOperation("all actions must be signed before batch commit")
        }
        let manifest = try ActionBatchManifestBuilder.build(
            batchId: workspace.batchId,
            actions: workspace.actions,
            sharedBeef: workspace.state.sharedBeef,
            sendWith: sendWith,
            isDelayed: isDelayed,
            maxInlineBytes: workspace.capabilities.maxInlineBytes
        )
        let result = try await storage.commitActionBatch(auth, manifest)
        workspace.committed = true
        return result
    }

    // MARK: - Abort

    /// Releases the batch's reservations in storage and forgets it. Does nothing when no batch is
    /// active or it has already committed. Best effort: storage also releases an abandoned batch
    /// when its lease runs out.
    @discardableResult
    public func abort(_ auth: AuthID) async -> Bool {
        await exclusive {
            guard let workspace = self.workspace else { return false }
            await self.retire(workspace, auth)
            return true
        }
    }

    private func retire(_ workspace: ActionBatchWorkspace, _ auth: AuthID? = nil) async {
        if !workspace.committed {
            _ = try? await storage.abortActionBatch(auth ?? workspace.auth, batchId: workspace.batchId)
        }
        if self.workspace === workspace { self.workspace = nil }
    }

    // MARK: - Lease

    /// Renews at 80% of the lease. An already lapsed lease is left alone: commit reacquires it.
    private func renewIfNeeded(_ workspace: ActionBatchWorkspace, _ auth: AuthID) async throws {
        let current = now()
        if current >= workspace.expiresAt { return }
        let renewAt = workspace.expiresAt.addingTimeInterval(
            -Double(workspace.capabilities.leaseMs) * 0.2 / 1000
        )
        if current < renewAt { return }
        do {
            workspace.expiresAt = try await storage.renewActionBatch(auth, batchId: workspace.batchId)
        } catch let WireError.actionBatchState(state, _, _) where state == "expired" {
            // Commit's reacquisition path still applies; a renewal race is not a dead batch.
            return
        }
    }

    private func extend(
        _ workspace: ActionBatchWorkspace, _ auth: AuthID, target: UInt64, outputs: Int, explicit: [Outpoint]
    ) async throws -> (count: Int, satoshis: UInt64) {
        let extension_ = try await storage.extendActionBatch(auth, ActionBatchExtendRequest(
            batchId: workspace.batchId,
            targetSatoshis: max(1, target),
            requestedOutputs: max(1, outputs),
            explicitOutpoints: explicit,
            includeSourceTransactions: true
        ))
        for row in extension_.reservedOutputs + extension_.explicitOutputs {
            if let raw = row.sourceTransaction { try workspace.state.mergeRawTransaction(raw) }
        }
        workspace.state.add(reserved: extension_.reservedOutputs, explicit: extension_.explicitOutputs)
        if let bytes = extension_.inputBeef, !bytes.isEmpty {
            try workspace.state.merge(BEEF(bytes: bytes, limits: PlannerState.beefLimits))
        }
        workspace.expiresAt = extension_.expiresAt
        return (
            extension_.reservedOutputs.count,
            extension_.reservedOutputs.reduce(UInt64(0)) { $0 + $1.satoshis }
        )
    }

    /// Terminal lifecycle errors retire the batch; a soft expiry does not, because commit can
    /// still reacquire it (`ActionBatchController.recover`).
    private func recovered(_ error: Error, _ workspace: ActionBatchWorkspace) async -> Error {
        if case WireError.actionBatchState(let state, _, _) = error, state != "expired" {
            await retire(workspace)
        }
        return error
    }

    static func isCapacityError(_ error: Error) -> Bool {
        switch error {
        case WireError.invalidParameter(let name, _):
            return name == "firstAction"
        case WireError.invalidOperation(let message):
            return message.contains("action batch")
                && (message.contains("maximum") || message.contains("reserve"))
        default:
            return false
        }
    }

    // MARK: - Serial access

    /// Runs one public operation at a time, as the reference's `runExclusive` does. An actor alone
    /// is not enough: each operation awaits storage, and another call would interleave there.
    private func exclusive<T: Sendable>(_ operation: () async throws -> T) async rethrows -> T {
        while busy {
            await withCheckedContinuation { waiters.append($0) }
        }
        busy = true
        defer {
            busy = false
            if !waiters.isEmpty { waiters.removeFirst().resume() }
        }
        return try await operation()
    }
}

/// One batch: its reservations, planned members and staged members, as in the reference.
final class ActionBatchWorkspace {
    let auth: AuthID
    let capabilities: ActionBatchCapabilities
    let batchId: String
    var state: PlannerState
    var planned: [String: PlannedAction] = [:]
    var actions: [StagedAction] = []
    var expiresAt: Date
    var committed = false

    init(auth: AuthID, capabilities: ActionBatchCapabilities, state: PlannerState) {
        self.auth = auth
        self.capabilities = capabilities
        self.batchId = state.begin.batchId
        self.state = state
        self.expiresAt = state.begin.expiresAt
    }

    func owns(_ reference: String) -> Bool {
        planned[reference] != nil || actions.contains { $0.reference == reference || $0.txid == reference }
    }

    func ownsTransaction(_ txid: String) -> Bool {
        actions.contains { $0.txid == txid }
    }

    /// Membership is an explicit transaction-graph relationship, never adjacency in time.
    func references(_ outpoints: [Outpoint], sendWith: [TransactionID]) -> Bool {
        outpoints.contains { state.staged[$0.description] != nil }
            || sendWith.contains { ownsTransaction($0.displayHex) }
    }

    func stage(_ signed: SignedAction, isNoSend: Bool, isDelayed: Bool) throws {
        if actions.contains(where: { $0.reference == signed.reference }) { return }
        guard let planned = planned[signed.reference] else {
            throw ActionBatchError.invalidOperation("signed action does not belong to the action batch")
        }
        let action = try StagedAction(
            planned: planned, transaction: signed.transaction, isNoSend: isNoSend, isDelayed: isDelayed
        )
        try state.stage(planned, txid: action.txid, transaction: signed.transaction)
        actions.append(action)
        self.planned[signed.reference] = nil
    }
}
