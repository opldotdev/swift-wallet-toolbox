# How `go-wallet-toolbox` ports `wallet-toolbox` (TypeScript) to Go

Source repos read locally:
- Go port: `~/code/go-wallet-toolbox` (module `github.com/bsv-blockchain/go-wallet-toolbox`, `go.mod:1-3`)
- TypeScript original: `~/code/wallet-toolbox` (single package, `src/`)
- TypeScript monorepo (broader stack, for context only): `~/code/ts-stack`

This report is written for a team building `swift-wallet-toolbox`. It documents what the Go port actually did, not what it should have done. Where the report infers rather than reads, it says so.

---

## 1. Scope decisions

**This is the most important section.** The Go port is not a full 1:1 port of `wallet-toolbox`. It implements the transaction/output/storage core solidly, and leaves the BRC-100 *identity and certificate* surface as explicit stubs.

### 1.1 What the Go port implemented

- The full storage data model and CRUD/query surface: users, transactions, outputs, output baskets, tags, labels, certificates (storage-level), commissions, known-tx, sync state. See `pkg/wdk/wallet_storage_interface.go` and the GORM models migrated in `pkg/internal/storage/repo/migrator.go:20-38`.
- The core wallet action lifecycle: `CreateAction`, `SignAction`, `AbortAction`, `ListActions`, `InternalizeAction`, `ListOutputs`, `RelinquishOutput` — all implemented in `pkg/wallet/wallet.go:214-356`.
- `GetPublicKey`, `Encrypt`, `Decrypt`, `CreateHMAC`, `VerifyHMAC`, `CreateSignature`, `VerifySignature` — delegated to a `ProtoWallet` from `go-sdk` (`pkg/wallet/wallet.go:145-212`).
- `IsAuthenticated`, `WaitForAuthentication`, `GetHeight`, `GetHeaderForHeight`, `GetNetwork`, `GetVersion` (`pkg/wallet/wallet.go:410-497`).
- A three-way SQL storage backend (SQLite, PostgreSQL, MySQL) through GORM, a JSON-RPC storage server/client pair for remote storage providers, a background monitor daemon with distributed cron locking, and a services layer aggregating ARC, WhatsOnChain, Bitails, and a Block Header Service (BHS).
- BRC-29 payment-template address derivation as its own package (`pkg/brc29`).

### 1.2 What the Go port deliberately did NOT implement (stubbed)

The clearest, most concrete evidence: eight of the BRC-100 `wallet.Interface` methods are implemented as bare `panic("implement me")` in `pkg/wallet/wallet.go`:

| Method | Location |
|---|---|
| `RevealCounterpartyKeyLinkage` | `pkg/wallet/wallet.go:358-363` |
| `RevealSpecificKeyLinkage` | `pkg/wallet/wallet.go:365-370` |
| `AcquireCertificate` | `pkg/wallet/wallet.go:372-376` |
| `ListCertificates` (wallet-level) | `pkg/wallet/wallet.go:378-382` |
| `ProveCertificate` | `pkg/wallet/wallet.go:384-388` |
| `RelinquishCertificate` (wallet-level) | `pkg/wallet/wallet.go:390-395` |
| `DiscoverByIdentityKey` | `pkg/wallet/wallet.go:397-401` |
| `DiscoverByAttributes` | `pkg/wallet/wallet.go:403-408` |

In other words: every method belonging to `CertificatesManagement` (part of `wallet.Interface`, defined in the `go-sdk` dependency, `go-sdk@v1.2.9/wallet/interfaces.go:51`) is unimplemented at the wallet layer. Note this is *not* the same as "certificates aren't supported anywhere" — `ListCertificates`, `InsertCertificateAuth`, and `RelinquishCertificate` **are** implemented at the storage layer (`pkg/wdk/storage.interface.go:52-58`); they are just never wired up to the BRC-100-facing `Wallet` struct. Read literally: the storage plumbing for certificates exists, the identity/verifier-facing operations on top of it do not.

A second, explicit and repeated stub: privileged-key support. Six of the seven proto-wallet-delegated methods carry the identical comment:
```
// TODO: support for privileged key manager (https://github.com/bitcoin-sv/wallet-toolbox/blob/master/src/sdk/PrivilegedKeyManager.ts)
```
(`pkg/wallet/wallet.go:146,156,166,176,186,196,206`). `PrivilegedKeyManager` — a TS class that lets a wallet use a second, higher-trust key for privileged operations — has no Go equivalent at all.

A third stub, in the RPC storage server: mutual authentication on the wire protocol. `pkg/storage/internal/server/rpc_server.go:39-40` registers a `/.well-known/auth` handler whose body is:
```go
s.logger.Warn("Auth requests are still not handled properly, this is a workaround to pass the client to the next step, it will be handled by the auth middleware")
```
The comment explicitly labels this a **fixme workaround**, not a design decision — BRC-103/104-style mutual auth for the storage RPC channel is not implemented.

Fourth: `New()` in `pkg/wallet/wallet.go:90-93` carries:
```go
// TODO: add support for optional parameters (like services, wallet storage manager, etc.) as it is in the Typescript version.
```
i.e. the TS constructor's fuller options surface (passing in a pre-built `WalletStorageManager`, `WalletSigner`, etc. directly) is narrower in Go — the Go `New()` takes a key source and a single active storage provider and builds the manager internally.

Fifth: batch/queued sync details are explicitly deferred, e.g. `pkg/internal/storage/repo/syncrepo/sync_knowntx.go:198` (`Batch: nil, // TODO: For now batch broadcasting is not supported, will be added later`) and `:219` (`Index: 0, // TODO: JS version also contains an index, it could be done in separate task later`).

53 `TODO` comments exist across the non-test Go source (grep count), concentrated in: sync-chunk processing (`pkg/storage/internal/sync/chunk_processor.go` — tag backup, `ReservedByID` provenance, user-ID translation across storages all explicitly deferred), the storage manager (locking around active-storage swaps, `pkg/storage/storage_manager.go:32,56,69,81,99,104`), and mapping edge cases.

### 1.3 What the Go port added that TypeScript does not have

- **A generated three-tier interface split from one annotated interface.** `pkg/wdk/storage.interface.go` defines a single `WalletStorageProvider` interface with `// @Read` / `// @Write` method annotations and three `go:generate` directives (`pkg/wdk/storage.interface.go:8-11`) that derive: a client (`pkg/storage/client_gen.go`), a narrower `WalletStorageBasic` (`pkg/wdk/wallet_storage_interface_gen.go`, sync methods stripped), and a storage-manager surface (`pkg/storage/storage_manager_gen.go`). TypeScript has no equivalent generation step — it hand-maintains its several storage interfaces (`WalletStorageWriter`, `WalletStorageSync`, `WalletStorageProvider`, ...) directly. This is a Go-specific answer to the lack of structural typing: **section 3** goes into more depth.
- **A first-class JSON-RPC storage server/client** (`pkg/storage/internal/server`, `pkg/storage/server.go`, `pkg/storage/client.go`) built on `github.com/filecoin-project/go-jsonrpc`. The TS `wallet-toolbox` has client/server storage separation in concept (`StorageClient`, `StorageServer` classes exist in TS too) but the Go port's is a dedicated code-generated RPC layer, not carried over line-for-line.
- **`github.com/bsv-blockchain/universal-test-vectors`** — a separate, dedicated Go module of JSON test vectors (transactions, users, BRC-100 wire frames) generated from Go definitions and checked into a JSON `generated/` directory (module README, `universal-test-vectors@v0.6.1/README.md`). This does not exist in the TypeScript stack in any form. See **section 7**.
- **A distributed cron lock for the monitor daemon** via `go-co-op/gocron-gorm-lock`, so multiple deployed instances of the same wallet-storage service coordinate background task execution through a DB-backed lock table (`pkg/monitor/monitor.go:42-59`). The TS `Monitor` class does not have this — it assumes a single running instance.
- **A `cmd/infra` / `infra-config.example.yaml` deployable server binary and a config-generation tool** (`cmd/infra_config_gen`), i.e. the Go port ships an actual runnable service binary as part of the same module, not just a library.
- **A `tools/client-gen` code generator** (see 1.3 above and section 3) as a first-party tool in the repo, with its own README (`tools/client-gen/README.md`).

**Takeaway for a v1 Swift port:** the Go team's implicit prioritization was *"transaction, output, and storage core must be complete and correct; identity/certificate BRC-100 surface and privileged keys can wait."* That is a defensible, load-bearing signal — the certificate/identity surface is exactly the part of BRC-100 that has the fewest concrete consumers in typical wallet apps versus `createAction`/`listOutputs`/`internalizeAction`, which every wallet needs on day one.

---

## 2. Package structure

Go layout (from `find ~/code/go-wallet-toolbox -maxdepth 4 -type d`):

```
cmd/                      # runnable binaries: infra server, infra_config_gen
examples/                 # runnable usage examples, one folder per operation
internal/config/          # module-private app config
manual_tests/             # human-run smoke tests + a TUI
pkg/
  brc29/                  # BRC-29 payment template address derivation
  defs/                   # shared enums/constants/config structs (network, db type, fee model, ...)
  entity/                 # plain domain entities (User, Transaction, Output, Commission, ...)
  errors/                 # typed wallet-action errors (TransactionError, CreateActionError, ProcessActionError)
  infra/                  # wiring for the deployable server
  internal/                # PRIVATE: assembler, satoshi math, storage repo impl, validate, mocks, test fixtures
  monitor/                # background task daemon (public interface) + internal/tasks (private)
  randomizer/             # crypto-random helper (ID/nonce generation)
  services/               # 3rd-party service aggregator (public) + internal/{arc,bhs,bitails,whatsonchain,httpx,servicequeue}
  storage/                # public storage provider/manager/server/client + internal/{actions,sync,server,service,managed,commission,integrationtests}
  wallet/                 # public BRC-100 Wallet implementation + internal/{actions,mapping,wallet_opts} and public pending/ subpackage
  wdk/                     # "Wallet Development Kit" — the shared interface & type vocabulary (public) + primitives/ subpackage
tools/client-gen/          # code-generation tool (interface -> client/manager) used via go:generate
```

TypeScript layout (`~/code/wallet-toolbox/src`):
```
src/
  sdk/           # interfaces + WalletError + WalletStorage.interfaces.ts, WalletServices.interfaces.ts, WalletSigner.interfaces.ts
  storage/       # WalletStorageManager, StorageProvider implementations (Knex-based)
  services/      # 3rd-party service integrations
  signer/        # the wallet signer (creates/signs actions) — analogous to Go's pkg/wallet
  monitor/       # background task runner
  utility/       # helpers
  wab-client/    # wallet-authentication-backend client (not ported to Go at all — see below)
```

Key structural differences:

1. **`wdk` replaces `sdk` as the interface-vocabulary package.** TS's `src/sdk/` (interfaces + error + certain shared types) maps roughly to Go's `pkg/wdk/` (interfaces + entity args/results + primitives), but Go's `wdk` is narrower — it holds no error taxonomy (see section 4) and no wallet implementation logic, purely the wire/storage vocabulary and the two top-level interfaces (`WalletStorage`, `WalletStorageProvider`, `Services`).
2. **TS's `signer/` becomes Go's `wallet/`.** The class that actually assembles and signs transactions (TS: `Signer`/`WalletSigner`) is where Go's `pkg/wallet.Wallet` and `pkg/wallet/internal/actions` live.
3. **No Go equivalent of `wab-client/`.** The Wallet Authentication Backend client (used in TS to talk to an external auth/2FA backend for wallet provisioning) was not ported. This is consistent with the certificate/identity stubbing noted in section 1 — it's the same "auth backend" surface being deferred.
4. **Heavy use of Go's `internal/` convention to enforce a public/private boundary that TS cannot express.** Every `pkg/X` public package that has implementation detail keeps it in `pkg/X/internal/...`. Examples: `pkg/wallet/internal/actions` (the actual `CreateAction`/`SignAction` logic), `pkg/wallet/internal/mapping` (BRC-100 args ↔ wdk args translation), `pkg/storage/internal/actions` and `pkg/storage/internal/sync` (the real CRUD/sync engine — `pkg/storage/provider.go` is a thin public façade over these), `pkg/services/internal/{arc,bhs,bitails,whatsonchain}` (concrete service clients — only the aggregating `WalletServices` type and the `Services` interface are public). Anything under `pkg/internal/` at the repo root (`assembler`, `satoshi`, `storage/{database,entity,repo,...}`, `validate`, `mocks`, all `testabilities`/`fixtures`) is invisible to any external module entirely — the compiler enforces it, whereas TS relies on `index.ts` export lists and convention (which do not stop a consumer from `import`-ing a deep path). **This is the single biggest structural lesson for Swift**: Swift's `internal` access level (module-private, not file- or directory-scoped like Go) is the nearest primitive, but achieving the same "one implementation package per public package" boundary needs the same discipline of a public target re-exporting a narrower surface, since Swift doesn't have Go's path-based `internal/` convention — it would need multiple SwiftPM targets/modules if the same hard boundary is wanted.
5. **One package, `pkg/wdk`, is the seam every other package depends on** (storage, services, wallet, monitor, errors, entity all import it) — it plays the role TS's `src/sdk/` plays, but is more strictly a leaf/vocabulary package with no behavior.

---

## 3. Interface design

Go has no structural typing and no TS-style unions, so every place TS relied on either was resolved with one of two mechanisms: (a) hand-written narrow interfaces plus explicit adapter structs, or (b) code generation from one annotated interface.

### 3.1 BRC-100 wallet interface

**Not defined in this repository at all.** It is imported from the sibling `go-sdk` module:
```go
sdk "github.com/bsv-blockchain/go-sdk/wallet"
var _ sdk.Interface = (*Wallet)(nil)   // pkg/wallet/wallet.go:22
```
The interface itself, `go-sdk@v1.2.9/wallet/interfaces.go:50-70`:
```go
type Interface interface {
	KeyOperations
	CertificatesManagement
	CreateAction(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error)
	SignAction(ctx context.Context, args SignActionArgs, originator string) (*SignActionResult, error)
	AbortAction(ctx context.Context, args AbortActionArgs, originator string) (*AbortActionResult, error)
	ListActions(ctx context.Context, args ListActionsArgs, originator string) (*ListActionsResult, error)
	InternalizeAction(ctx context.Context, args InternalizeActionArgs, originator string) (*InternalizeActionResult, error)
	ListOutputs(ctx context.Context, args ListOutputsArgs, originator string) (*ListOutputsResult, error)
	RelinquishOutput(ctx context.Context, args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error)
	RevealCounterpartyKeyLinkage(...)
	RevealSpecificKeyLinkage(...)
	DiscoverByIdentityKey(...)
	DiscoverByAttributes(...)
	IsAuthenticated(...)
	WaitForAuthentication(...)
	GetHeight(...)
	GetHeaderForHeight(...)
	GetNetwork(...)
	GetVersion(...)
}
```
It is **one large interface** (18 top-level methods plus everything pulled in by the embedded `KeyOperations` and `CertificatesManagement` interfaces), assembled by embedding two smaller interfaces (`KeyOperations`, `CertificatesManagement`) rather than being split at the toolbox layer. `pkg/wallet.Wallet` implements the whole thing in one struct; unimplemented methods `panic`, so the interface is satisfied at compile time but not at runtime for the certificate methods (section 1.2).

Every method carries a trailing `originator string` parameter (the BRC-100 calling-application identity) — this is present on almost every exported method in the interface and validated per-call in `pkg/wallet/wallet.go` via `validate.Originator(originator)` (e.g. lines 247, 267, 293, 313, 338, 411, 423, 438, 458, 477, 489). This is the Go equivalent of a cross-cutting TS decorator/middleware — there's no decorator mechanism in Go, so each method repeats the validation call explicitly. Note the inconsistency: `GetPublicKey`/`Encrypt`/`Decrypt`/`CreateHMAC`/`VerifyHMAC`/`CreateSignature`/`VerifySignature` (delegated straight to `ProtoWallet`, lines 145-212) do **not** call `validate.Originator` themselves — only the storage-backed and network-backed methods do. Worth flagging as a possible gap, not a deliberate split.

### 3.2 Storage provider interface

This is where the generation strategy is concentrated. One interface is hand-written and annotated; three more are generated from it.

Hand-written source of truth, `pkg/wdk/storage.interface.go:15-77` (`WalletStorageProvider`) — every method tagged `// @Read` or `// @Write`, e.g.:
```go
// CreateAction creates a new transaction ready to be signed and processed later.
// @Write
CreateAction(ctx context.Context, auth AuthID, args ValidCreateActionArgs) (*StorageCreateActionResult, error)
```
Three `go:generate` directives sit right above it (`pkg/wdk/storage.interface.go:8-11`):
```go
//go:generate go run -tags gen ../../tools/client-gen/main.go -out ../storage/client_gen.go
//go:generate go run -tags gen ../../tools/client-gen/main.go -out wallet_storage_interface_gen.go -skip-methods "GetSyncChunk,FindOrInsertSyncStateAuth,ProcessSyncChunk" -tmpl wallet_storage.tpl
//go:generate go run -tags gen ../../tools/client-gen/main.go -out ../storage/storage_manager_gen.go -skip-methods "MakeAvailable,GetSyncChunk,FindOrInsertSyncStateAuth,ProcessSyncChunk" -tmpl manager.tpl
```
This produces:
- `WalletStorageBasic` (`pkg/wdk/wallet_storage_interface_gen.go`) — same methods, `auth AuthID` parameter dropped (because callers of this narrower interface already operate within an authenticated session), sync-internal methods stripped.
- `WalletStorage` (hand-written, `pkg/wdk/wallet_storage_interface.go:6-9`) — `WalletStorageBasic` plus `GetAuth(ctx) (AuthID, error)`.
- A generated RPC client (`pkg/storage/client_gen.go`) and a generated storage-manager surface (`pkg/storage/storage_manager_gen.go`, which additionally drops `MakeAvailable`).

So Go's answer to "TS structurally derives several related interface shapes from one another (`Pick<>`/`Omit<>`)" is: **one authoritative interface with method-level annotations, and a purpose-built code generator (`tools/client-gen`) that emits the derived shapes at `go generate` time.** This is a direct, reusable idea for Swift — Swift has no structural-typing shortcut either, and a small generator (even a Swift script using SourceKit, or a simpler annotation/codegen step) that derives narrower protocol conformances from one annotated protocol is the same shape of solution.

Interface **size**: one large `WalletStorageProvider` (13 methods), not split into many small ones — this mirrors the TS `WalletStorageProvider` shape rather than decomposing further. It groups by "everything a storage backend must implement," not by capability.

### 3.3 Services / provider interfaces

`pkg/wdk/services.interface.go:10-18` — again one interface, assembled by embedding two smaller ones plus six direct methods:
```go
type Services interface {
	BlockHeaderLoader
	chaintracker.ChainTracker   // from go-sdk
	PostBEEF(ctx context.Context, beef *transaction.Beef, txids []string) (PostBeefResult, error)
	MerklePath(ctx context.Context, txid string) (*MerklePathResult, error)
	FindChainTipHeader(ctx context.Context) (*ChainBlockHeader, error)
	RawTx(ctx context.Context, txID string) (RawTxResult, error)
	GetBEEF(ctx context.Context, txID string, knownTxIDs []string) (*transaction.Beef, error)
	NLockTimeIsFinal(ctx context.Context, txOrLockTime any) (bool, error)
}
```
Two genuinely small, single-method interfaces exist alongside it for narrower consumers: `HeightProvider` (`services.interface.go:21-23`) and `BlockHeaderLoader` (`services.interface.go:26-28`) — used where a caller (e.g. the monitor) only needs current-height or header lookups, not the full services surface. So the pattern here is: **one broad interface for the concrete `WalletServices` aggregator to implement, plus a handful of single-method interfaces for narrow consumers to depend on** — an approximation of Go's "accept interfaces, return structs" idiom, applied selectively rather than uniformly.

Under the hood, `pkg/services/` fans this single interface out to four internal concrete clients (`internal/arc`, `internal/bhs`, `internal/bitails`, `internal/whatsonchain`), aggregated and raced/queued via `internal/servicequeue` (multiple providers competing for the same call, first success wins — inferred from `ErrEmptyResult`/`ErrNoServicesRegistered` sentinels in `pkg/services/internal/servicequeue/queues.go:19-20`).

---

## 4. Error handling

This is a **complete taxonomy break from TypeScript**, not a port.

TS `wallet-toolbox` (`src/sdk/WalletError.ts:19-30`) has one central `WalletError` class, string-coded (`WERR_*` prefixed `name`/`code`), with a `fromUnknown()` static recovery method that inspects arbitrary caught values and normalizes them into a `WalletError`. Errors flow as **runtime string codes** (`err.code === 'WERR_INVALID_PARAMETER'`), which is idiomatic in a dynamically-typed-at-the-boundary language and lets errors cross serialization boundaries (HTTP/JSON-RPC) by code string.

Go **does not have this pattern at all**: `grep -rn "WERR_" --include=*.go` across the entire repo returns **zero** matches. Instead:

- **Sentinel errors** (package-level `var`s compared with `errors.Is`), scattered per-package rather than centralized:
  - `wdk.NotFoundError` (`pkg/wdk/errors.go:6`)
  - `wdk.ErrNotAbortableAction` (`pkg/wdk/storage_abort_action_args.go:22`)
  - `storage.ErrAuthorization` (`pkg/storage/provider.go:27`)
  - `servicequeue.ErrEmptyResult`, `servicequeue.ErrNoServicesRegistered` (`pkg/services/internal/servicequeue/queues.go:19-20`)
  - `errfunder.NotEnoughFunds` (`pkg/internal/storage/funder/errfunder/errfunder.go:5`)
- **Typed structured errors** implementing the standard `error`, `Unwrap() error`, and `Is(target error) bool` methods, in `pkg/errors/action_error.go`:
  - `TransactionError` (line 18) — carries `TxID chainhash.Hash`, `Cause error`, `WrongHash bool`.
  - `CreateActionError` (line 81) — carries `Reference string`, `Cause error`.
  - `ProcessActionError` (line 132) — carries `SendWithResults []wdk.SendWithResult`, `ReviewResults []wdk.ReviewActionResult`, `Cause error`, and builds a **human-readable summary** in `Error()` (counts of succeeded/sending/failed transactions) rather than a bare message.

  Each type implements the fluent `Wrap(err error) *T` builder pattern (e.g. `pkg/errors/action_error.go:52-55`) plus a hand-rolled `Is()` that both matches the concrete type and delegates to the wrapped `Cause` via `errors.Is` — this is the idiomatic Go way of getting TS's "is this a WalletError, and if so which subtype" pattern, but it requires writing `Unwrap`/`Is` by hand for every error type since Go has no exception-class hierarchy to walk.

**No error taxonomy mirrors the TS one.** There is no Go `WERR_*` constant set, no central error registry, and no JSON-serializable error-code convention visible in `pkg/wdk` or `pkg/errors`. Given the RPC storage server exists and needs to convey failures across the wire (`pkg/storage/internal/server`), this is either an intentional simplification (Go's richer static error types don't need string codes) or a gap depending on whether the RPC layer has its own separate error-code mapping — this report did not find one, so treat it as **unverified**: it wasn't found, not confirmed absent everywhere.

**For Swift:** the direct analogue of the sentinel + typed-struct-with-`Unwrap` pattern is Swift's `Error` protocol plus `enum` cases with associated values (closer to Rust/Go's tagged unions than to TS's class hierarchy), or a small number of `struct`-based error types conforming to `LocalizedError`/`CustomNSError`. The Go port's decision to drop the centralized `WERR_*` string-code registry entirely, rather than port it, is worth a deliberate yes/no decision for Swift rather than a default carry-over — string error codes matter more when errors cross a wire boundary (JSON-RPC/HTTP), less when they stay in-process.

---

## 5. Concurrency

Go's concurrency primitives (goroutines, channels, `context.Context` cancellation, `sync.Mutex`) replace TS's single-threaded event loop + `async`/`await` + external locking. Findings:

- **`context.Context` is threaded through essentially every public method** in `wdk`, `storage`, `wallet`, `monitor`, and `services` — every interface method signature in section 3 takes `ctx context.Context` as its first argument. This is the mechanical equivalent of propagating cancellation/deadline/tracing through the whole call graph; TS has no equivalent primitive (it relies on `AbortSignal`, used far less pervasively in the TS codebase).
- **The monitor daemon (`pkg/monitor/monitor.go`) is the one place genuine concurrency-safety is engineered, not just plumbed:**
  - `Daemon.startLock sync.Mutex` (`monitor.go:31`) guards a `started bool` flag so `Start`/`Stop` are safe to call concurrently (start-once semantics).
  - **Cross-process** (not just cross-goroutine) safety: `NewDaemonWithGORMLocker` (`monitor.go:44-59`) wraps the `gocron/v2` scheduler with `gocron-gorm-lock`, a **database-row-based distributed lock**. This means when a wallet-storage service is deployed as multiple replicas (the typical production topology), only one replica actually executes a given scheduled task (proof-checking, waiting-tx sending, abandoned-tx failing) at a time — coordinated through a lock table migrated alongside the app schema (`gormlock.CronJobLock{}`, `monitor.go:45`). Each worker gets a random 12-byte base64 name (`monitor.go:50-53`) used both as the lock identity and as a logging field.
  - Per-task **timeout contexts** derived from the next scheduled run time with a 0.95 safety margin (`const safetyMargin = 0.95`, `monitor.go:19`, used in `contextWithTimeout`, `monitor.go:212`) — a task is given a deadline just short of its next scheduled invocation, so a stuck task can't overlap its own next run.
  - TS's `Monitor` class has no equivalent distributed lock — it assumes single-instance deployment. **This is a genuine addition, not a port** (also listed in section 1.3).
- **What is documented as safe for concurrent use vs. not**: the report did not find explicit doc comments asserting goroutine-safety on `Wallet`, `WalletStorageManager`, or the GORM-backed storage provider — safety appears to be *structural* (each request builds fresh short-lived action structs, e.g. `pkg/wallet/wallet.go:216-221` constructs a new `actions.CreateAction` per call) rather than *documented*. A `pkg/storage/storage_manager.go` `TODO` at line 81 (`// TODO: add locking mechanism to ensure that the active storage is not being modified while syncing`) and line 99/104 (same) is explicit evidence that **concurrent-safety of active-storage swapping during sync is a known, unresolved gap**, not a designed guarantee.
- No use of goroutines for fan-out/parallel request handling was found in the core action/storage path (`grep "go func"` across `pkg/wallet`, `pkg/storage` core turned up nothing) — the services layer's multi-provider racing (`servicequeue`) is the most likely place goroutines are used for fan-out, but this report did not read that package's internals in depth; flagged as **inferred, not verified**, and worth a targeted follow-up read of `pkg/services/internal/servicequeue/queues.go` before assuming a pattern for Swift's `TaskGroup` usage.

**For Swift**, the direct translation targets are: `context.Context` cancellation → structured concurrency's task cancellation (`Task` cancellation checks, no explicit context object needed); the GORM distributed-lock pattern → an actor-isolated scheduler is *not* enough by itself for multi-*process* deployments — Swift would need the same kind of DB-row-based lock if multi-instance deployment is a goal, since Swift's actor isolation only solves in-process concurrency, not cross-process/cross-replica coordination.

---

## 6. Storage

**Backends implemented:** SQLite, PostgreSQL, MySQL — all through one ORM (GORM), selected by a dialector map:
```go
// pkg/internal/storage/database/dialectors.go:14-19
type dialectorMaker func(cfg defs.Database) gorm.Dialector
var ... = map[defs.DBType]dialectorMaker{
    defs.DBTypeSQLite:   sqliteDialector,
    defs.DBTypePostgres: postgresDialector,
    defs.DBTypeMySQL:    mysqlDialector,
}
```
This is a **single SQL abstraction layer** (GORM) rather than TS's Knex-based query builder — conceptually the same role (schema-portable ORM/query builder over multiple SQL engines), different library, same "one interface, pick a dialect" strategy. `pkg/internal/storage/database/database.go:64-65` centralizes connection creation (`gorm.Open(dialector, ...)`), including MySQL-specific timezone normalization (`database.go:121-122`, converting `/` to `%2F` in timezone strings — a documented driver quirk workaround, cited with a link).

**Schema/migrations:** GORM's `AutoMigrate` — no separate up/down migration files. `pkg/internal/storage/repo/migrator.go:19-38` lists every model to migrate in one call:
```go
models.Setting{}, models.User{}, models.OutputBasket{}, models.CertificateField{}, models.Certificate{},
models.UserUTXO{}, models.Transaction{}, models.Output{}, models.KnownTx{}, models.Label{},
models.TransactionLabel{}, models.NumericIDLookup{}, models.SyncState{}, models.KeyValue{}, models.Tag{},
models.OutputTag{}, models.Commission{}, models.TxNote{}
```
plus two explicit join-table setups (`Transaction`↔`Labels`, `Output`↔`Tags`, `migrator.go:40-48`). This is schema-as-code with no migration history/versioning artifact checked into the repo (no `migrations/0001_*.sql`-style directory was found) — GORM diffs the struct tags against the live schema at startup. That is a materially different operational model from TS `wallet-toolbox`, which uses Knex migration files with explicit up/down steps and a migration history table. **This is a real trade-off to flag for Swift**: `AutoMigrate`-style schema-from-struct is fast to develop against but has no rollback story and can silently apply additive changes on every boot; a Swift port using (for example) GRDB or SQLite.swift would need to choose deliberately between an equivalent "migrate from model" approach and versioned migration files — the Go port chose convenience over auditability here, which may or may not be the right call for a mobile wallet where schema changes ship inside app updates rather than a continuously-deployed server.

**Table/model naming maps closely to TS's `Table*` interfaces** — `pkg/wdk/table_*.go` files (`table_user.go`, `table_transaction.go`, `table_output.go`, `table_certificate.go`, `table_proven_tx.go`, `table_proven_tx_req.go`, `table_sync_state.go`, `table_commission.go`, `table_output_basket.go`, `table_tx_label.go`, `table_output_tag.go`, ...) are the wire/domain-level structs; `pkg/internal/storage/database/models` (not read in depth, but referenced from `migrator.go`) holds the GORM-tagged persistence structs — i.e. **the port keeps TS's separation between a storage-agnostic domain type and a driver-specific persisted type**, just expressed as two parallel Go struct sets connected by a mapping layer (`pkg/internal/storage/entity`, `pkg/storage/mappings.go`) instead of TS's single interface with optional Knex row-mapping.

**Local storage server topology:** `pkg/storage/server.go` + `pkg/storage/internal/server/rpc_server.go` expose the storage provider over JSON-RPC (`github.com/filecoin-project/go-jsonrpc`), registered on a single `POST /` HTTP handler plus the not-yet-functional `/.well-known/auth` (section 1.2). `pkg/storage/client.go` / `client_gen.go` is the generated RPC client counterpart.

---

## 7. Testing strategy

**Volume:** 693 total `.go` files in the module, 131 of them `_test.go` files (grep count) — roughly a 1:4.3 test-to-total file ratio, concentrated per-package rather than in one top-level test tree (Go convention: `foo.go` next to `foo_test.go`).

**Style:** Given-When-Then structure is a written team standard, not just an observed pattern — `CODE_STANDARDS.md` (repo root) codifies it explicitly with a code sample (`//given` / `//when` / `//then` comment sections) and states table-driven tests are preferred "when possible," with an explicit rule to **avoid branching inside a test** and split differing scenarios into separate test cases instead. Random test data is explicitly disallowed unless seeded, for reproducibility. Testing private functions through their public entry points is the default; direct testing of unexported functions is the stated exception, reserved for genuinely complex algorithms.

**Mocking:** `go.uber.org/mock` (the official `gomock` successor) is a declared build tool in `go.mod` (`tool go.uber.org/mock/mockgen`), and mocks are generated via `go:generate` directly from the `WalletStorageProvider` interface: `//go:generate go tool mockgen -destination=../internal/mocks/mock_wallet_storage_writer.go -package=mocks github.com/bsv-blockchain/go-wallet-toolbox/pkg/wdk WalletStorageProvider` (`pkg/wdk/storage.interface.go:11`).

**Integration tests:** exist but are notably thin — only one file was found under `pkg/storage/internal/integrationtests/` (`internalize_create_process_test.go`), covering the internalize→create→process action lifecycle end-to-end against a real (likely SQLite, in-process) storage backend. No `testcontainers` dependency exists in `go.mod` and no `testcontainers` usage was found by grep — so **Postgres/MySQL are not exercised by an automated container-based integration suite** in this repo as currently checked out; SQLite (file or in-memory) appears to be the workhorse for anything beyond unit tests, based on the available evidence (this report did not exhaustively trace every test's DB setup, so treat "Postgres/MySQL are untested" as a likely-but-not-fully-confirmed gap rather than a certainty).

**Cross-implementation test vectors — yes, this exists, and it directly answers the brief's question.** `github.com/bsv-blockchain/universal-test-vectors` (`go.mod` require, v0.6.1) is a **separate, dedicated repository** whose entire purpose is cross-language test vectors: BSV transactions (with/without OP_RETURN), users with keypairs, and **BRC-100 wire frames** (currently just `createAction`), defined once in Go (`vectors/`, `brc100frames/`) and exported as plain JSON (`generated/`) specifically so "the implementation in various programming languages" (its own README's words) can consume the same fixtures. It is used pervasively inside `go-wallet-toolbox` — 20 files reference it directly, spanning `pkg/internal/testabilities`, `pkg/storage` (provider create/process/internalize/get-beef tests), `pkg/services` (rawtx/beef/merkle-path tests), and `pkg/wdk`.

Two caveats, both load-bearing for planning a Swift port:
1. **The TS `wallet-toolbox` and `ts-stack` repos checked out locally do not reference `universal-test-vectors` by that name** (`grep` for the string across both `package.json` trees and `wallet-toolbox/src` returned nothing). So as of what's on disk here, the vector set is **consumed by Go only** — it was *built* to be cross-language (JSON, language-agnostic, explicitly documented as such) but there's no confirmed evidence the TS side actually consumes it yet. This may simply be a repo-currency issue (the local TS checkout may predate adoption) rather than a permanent fact — worth confirming with the BSV Blockchain org directly before assuming TS never adopted it.
2. There is also a `pkg/internal/testabilities/tsgenerated/` directory inside `go-wallet-toolbox` itself (`create_action_result.go`, `create_action_result.json`, `signed_transaction.go`, `beef_to_internalize.go`) — hand-copied-looking fixtures with "tsgenerated" naming, distinct from `universal-test-vectors`, suggesting a *second*, ad hoc channel where specific TS-produced outputs were captured and replayed as Go test fixtures. This is weaker evidence of active TS↔Go parity testing (a handful of captured fixtures vs. a maintained generator), but it confirms the intent to cross-check against real TS output existed at some point.

**Recommendation embedded in the finding, not a separate speculation:** `universal-test-vectors`, if it is genuinely still maintained by the BSV Blockchain org, is the strongest asset for a Swift port to plug into directly — it's already JSON, already schema-documented, and explicitly built for exactly this multi-language-parity problem. Verify its current maintenance status and TS-side adoption before committing to it, since local evidence is Go-only.

---

## 8. Naming and API conventions

| TypeScript (`wallet-toolbox`) | Go (`go-wallet-toolbox`) | Note |
|---|---|---|
| `WalletError` (class, `src/sdk/WalletError.ts`) | *(no direct equivalent)* — sentinel `var`s + typed structs | Taxonomy dropped, not renamed (section 4) |
| `WERR_INVALID_PARAMETER` etc. (string codes) | *(none found)* | — |
| `WalletStorageManager` (`src/storage/WalletStorageManager.ts`) | `storage.WalletStorageManager` (`pkg/storage/storage_manager.go`) | Same name, package-qualified instead of import-qualified |
| `WalletStorage.interfaces.ts` (`WalletStorageWriter`, `WalletStorageSync`, `WalletStorageProvider`, ...) | `wdk.WalletStorageProvider` (hand-written) → generates `wdk.WalletStorageBasic`, `wdk.WalletStorage`, `storage` client/manager | Several hand-maintained interfaces → one annotated interface + codegen (section 3.2) |
| `Signer` / the class doing `createAction`/`signAction` | `pkg/wallet.Wallet` + `pkg/wallet/internal/actions.{CreateAction,SignAction}` | TS's "signer" concept renamed to match the BRC-100 term "wallet" |
| `CreateActionArgs`, `SignActionArgs`, etc. (TS interfaces, camelCase fields) | `sdk.CreateActionArgs` etc. (from `go-sdk`, PascalCase fields) — plus `wdk.ValidCreateActionArgs` as the internally-validated variant | Go **adds a `Valid*` prefix convention** for post-validation types not present in TS |
| optional fields (`foo?: string`) | pointer fields (`Foo *string`) or a documented zero-value convention | Standard Go idiom, no TS analogue needed |
| string literal unions (e.g. a `status` field with a fixed set of string values) | typed string constants, e.g. `wdk.SyncStatus` with `SyncStatusUpdated SyncStatus = "updated"` (`pkg/wdk/sync_status.go:11`) and `wdk.SendWithResultStatusUnproven`/`...Failed`/`...Sending` (referenced in `pkg/errors/action_error.go:157-165`) | Go's nearest equivalent to a TS string-literal union: a named string type + exported constants, not a real closed enum |
| `Monitor` (class) | `monitor.Daemon` | Renamed to reflect what it actually is (a scheduled background process), not a literal transliteration |
| camelCase methods/fields throughout | PascalCase for exported, camelCase for unexported | Mechanical Go convention, applied consistently |
| `index.ts` barrel exports controlling public surface | `internal/` directories controlling public surface | Convention → compiler-enforced (section 2) |
| TS optional constructor-options object (`new Wallet({ storage, services, ... })`) | Go functional options: `wallet.New(chain, keySource, storage, wallet.WithServices(...), wallet.WithLogger(...), ...)` (`pkg/wallet/wallet.go:39-88`, `93`) | Standard idiomatic-Go translation of TS's options-object constructor pattern |
| `WalletStorage.interfaces.ts` method taking no explicit context/cancellation | every Go interface method's first parameter is `ctx context.Context` | Mechanical addition Go requires structurally (section 5) |

General naming pattern observed: **types and interfaces keep their TS name almost verbatim** (`CreateActionArgs`, `ListOutputsResult`, `TableCertificate`, `SyncStatus`) since these are largely BRC-100/BRC-8 wire-protocol names that are language-agnostic by design; it is the **surrounding machinery** (errors, options, generics-adjacent patterns, module boundaries) that gets substantially rewritten in idiomatic Go rather than transliterated.

---

## 9. Build, CI, release

- **Module layout:** single Go module (`go.mod:1`, `module github.com/bsv-blockchain/go-wallet-toolbox`), Go 1.24.3 (`go.mod:3`). No multi-module workspace (`go.work`) was found — everything (library, `cmd/` binaries, `tools/client-gen`, `examples/`) lives in one module.
- **Versioning:** no `CHANGELOG.md` was found at the repo root (unlike TS `wallet-toolbox`, which has one); `ROADMAP.md` explicitly defers versioning/roadmap details ("Until version 1.0 of this library is released, the roadmap is being managed internally by the development team"). `.github/workflows/autotag.yaml` and `.github/release.yaml` + `.github/workflows/release.yaml` exist, implying automated tag/release on some trigger, but this report did not read their bodies in depth.
- **CI:** `.github/workflows/check_branch.yaml` runs on every push to a non-main/master branch and simply delegates to a **shared reusable workflow** hosted in a separate org repo: `uses: bactions/workflows/.github/workflows/on-push-go.yml@main`. The actual lint/test steps are therefore centrally maintained outside this repo (standard BSV Blockchain org practice, inferred from the `bactions/workflows` naming) — this repo's own CI file carries no inline `go test`/`golangci-lint` invocation to read.
- **Linting:** two separate golangci-lint config files — `.golangci-lint.yml` (rules) and `.golangci-style.yml` (style-specific, presumably a stricter/separate pass) — both referenced from `CODE_STANDARDS.md`'s Effective-Go/Go-Code-Review-Comments/Uber-Style-Guide citation list.
- **Code generation:** two independent generation systems, both invoked via `go:generate` and checked into version control as generated output (not generated at build time):
  1. `tools/client-gen` — interface → client/manager/basic-interface generation (section 3.2), templates in `tools/client-gen/generator/templates/*.tpl`.
  2. `gorm.io/gen` (a `go.mod` dependency) — likely used for type-safe GORM query code generation, though this report did not trace its output files directly; flagged as **inferred from the dependency list, not verified by reading generated output**.
  3. `go.uber.org/mock/mockgen` as a declared Go tool (`go.mod` `tool` directive) for interface mocks (section 7).
- **Contribution workflow** (`CONTRIBUTING.md`, summarized from README): fork → `go mod tidy` → branch → `go test ./...` → PR, with branch-naming and issue-number conventions documented in `CODE_STANDARDS.md` sections 3.3+.
- **No Dockerfile was confirmed read** in this pass, though `cmd/infra` plus `infra-config.example.yaml` strongly imply a deployable server artifact exists; worth a follow-up read of `cmd/infra` before assuming a specific deployment shape.

---

## Summary for Swift planning (not elaborated further — another agent owns Swift specifics)

The single highest-value takeaway: the Go port's v1 scope line is **"complete transaction/output/storage core; certificate/identity BRC-100 surface stubbed with explicit panics; privileged-key manager not ported at all; RPC-layer mutual auth explicitly marked as a workaround."** That is a real, load-bearing prioritization decision made by a team that already had the TS spec in hand and still chose to defer identity/certificates — strong signal for what a Swift v1 can also defer.
