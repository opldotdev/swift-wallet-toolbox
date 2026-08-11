# TypeScript BSV Wallet Toolbox — Architecture Map

Scope: maps the public surface and internal architecture of the authoritative TypeScript
wallet toolbox, read from two local repos:

- `~/code/ts-stack` — current monorepo (core SDK + wallet toolbox + network/overlay/messaging/middleware), package `@bsv/wallet-toolbox` v2.4.0, path `packages/wallet/wallet-toolbox`
- `~/code/wallet-toolbox` — older standalone toolbox repo, `@bsv/wallet-toolbox` v1.7.18

All file:line references below are relative to these two repo roots. Where a claim is inferred
rather than directly read, it is marked "(inferred)".

---

## 1. Monorepo layout

`ts-stack` is a pnpm workspace (`pnpm-workspace.yaml`) with packages under `packages/**`,
`conformance/**`, `apps/**`, and `docs-site`. Node ≥22, pnpm ≥9, TypeScript 6.

### Package groups (`packages/`)

| Group | Members | Purpose |
|---|---|---|
| `sdk` | `@bsv/sdk` (v2.1.6) | Core primitives: keys, `KeyDeriver`/`CachedKeyDeriver` (BRC-42/43), transaction building, `Beef`, `AuthFetch`, `LookupResolver`, `ProtoWallet`, `WalletInterface` type, script templates. This is the layer the Swift SDK already covers. |
| `verifast` | `@bsv/verifast` (0.2.0) | Optional C++/WASM (BDK) script-verification backend for `@bsv/sdk`. Performance-only; not required for correctness. |
| `wallet` | `@bsv/wallet-toolbox`, `@bsv/wallet-toolbox-client`, `@bsv/wallet-toolbox-mobile` (build targets of one source tree, see §1.2), `@bsv/btms`, `@bsv/btms-permission-module`, `@bsv/wallet-relay` (`ts-wallet-relay`), `@bsv/wallet-toolbox-examples` | THE toolbox — BRC-100 wallet, storage, actions, signing orchestration. This report covers `wallet-toolbox` in depth (§2–§8). `btms` = Basic Token Management System (UTXO token bookkeeping); `wallet-relay` = mobile pairing/relay server; `wallet-toolbox-examples` = usage samples. |
| `helpers` | `@bsv/wallet-helper`, `@bsv/did`, `@bsv/did-client`, `@bsv/templates` (ts-templates), `@bsv/simple`, `@bsv/fund-wallet`, `@bsv/amountinator` | Small standalone utility libraries (DID/SD-JWT, script templates, currency conversion, faucet funding). Not core toolbox dependencies. |
| `messaging` | `@bsv/message-box-client`, `@bsv/authsocket`, `@bsv/authsocket-client`, `@bsv/paymail` (ts-paymail) | P2P messaging, mutually-authenticated WebSockets, Paymail. `message-box-client` is used by BRC-100 wallets for out-of-band payment delivery; not imported by wallet-toolbox itself (loosely coupled). |
| `middleware` | `@bsv/auth` (signed/expiry-bound auth proofs), `@bsv/auth-express-middleware`, `@bsv/payment-express-middleware`, `@bsv/402-pay` | Express middleware implementing BRC-103 mutual auth and BRC-41/121 HTTP micropayments. `wallet-toolbox`'s `StorageServer` depends directly on `@bsv/auth-express-middleware` and `@bsv/payment-express-middleware` (`storage/remoting/StorageServer.ts:9-10`). |
| `network` | `@bsv/teranode-listener` (ts-p2p) | Subscribes to Teranode P2P topics; used by the live-block-header ingestor (`LiveIngestorTeranodeP2P.ts`, see §6). |
| `overlays` | `@bsv/overlay` (Overlay Services Engine), `@bsv/overlay-express`, `@bsv/overlay-topics`, `@bsv/overlay-discovery-services`, `@bsv/gasp` (Graph Aware Sync Protocol), `@bsv/btms-backend` | Overlay network infrastructure. The wallet toolbox consumes overlays only as a *client*, via `LookupResolver` (from `@bsv/sdk`) for identity certificate discovery (`Wallet.ts` `discoverByIdentityKey`/`discoverByAttributes`, §2) — it does not embed an overlay node. |

### Dependency edges (toolbox-relevant)

```
@bsv/wallet-toolbox
 ├─ @bsv/sdk               (peer dep; KeyDeriverApi, WalletInterface, Beef, AuthFetch, LookupResolver, ProtoWallet, Transaction, script templates)
 ├─ @bsv/auth-express-middleware     (StorageServer only, Node build)
 ├─ @bsv/payment-express-middleware  (StorageServer only, Node build)
 ├─ knex, better-sqlite3, mysql2     (StorageKnex, Node build only)
 ├─ idb                              (StorageIdb, client/mobile-omitted-differently, see §8)
 ├─ hash-wasm                        (PBKDF2 fallback when WebCrypto unavailable)
 ├─ express, ws                      (StorageServer / SSE clients)
```

`@bsv/btms-permission-module` and `@bsv/wallet-relay` depend on `@bsv/wallet-toolbox` but are
optional add-ons (token permission gating, mobile pairing relay) — not required for a baseline
BRC-100 wallet port.

### Build tooling & versioning

- Build: `tsc --build` per package (`wallet-toolbox/package.json:26` `"build": "tsc --build"`).
- Docs: `ts2md` generates markdown API docs from TSDoc comments (`"doc": "ts2md"`).
- Root scripts (`ts-stack/package.json`): `pnpm -r --filter '!@bsv/ts-stack' run {build,test,lint,clean}` fan out to every workspace package.
- **Version sync**: `scripts/sync-versions.mjs` walks all workspace `package.json` files via `pnpm -r ls --json --depth 0`, builds a name→version map, and rewrites every cross-package `dependencies`/`devDependencies`/`peerDependencies` reference to the current workspace version — including `infra/*` packages that are *not* in the pnpm workspace (auto patch-bumps them so `infra-release` CI rebuilds). `scripts/check-versions.mjs` is the CI-gating dry-run (exit 1 on stale refs).
- CI workflows present: `ci.yml`, `codegen.yml`, `conformance.yml`, `docs-deploy.yml`, `infra-release.yaml`, `release.yaml` (`.github/workflows/`).
- Each package still carries its own `prepublish` script chaining build → doc → `sync-versions` (e.g. `wallet-toolbox/package.json:27`).
- `pnpm.overrides` in the root `package.json` pins `@bsv/sdk`, `knex`, `better-sqlite3`, `mysql2`, `typescript` versions workspace-wide, plus several security-patched transitive deps (`tar`, `qs`, `ws`, `xml2js`, etc.).

---

## 2. The Wallet class

`Wallet` (`wallet-toolbox/src/Wallet.ts:206`) is the concrete `implements WalletInterface, ProtoWallet` class — the BRC-100 wallet.

### Constructor dependencies (`Wallet.ts:206-262`)

```ts
constructor(
  argsOrSigner: WalletArgs | WalletSigner,
  services?: WalletServices,
  monitor?: Monitor,
  privilegedKeyManager?: PrivilegedKeyManager,
  makeLogger?: MakeWalletLogger
)
```

`WalletArgs` composes:
- `chain: Chain` (`'main' | 'test'`)
- `keyDeriver: KeyDeriverApi` — from `@bsv/sdk`; BRC-42/43 derivation, source of `identityKey`
- `storage: WalletStorageManager` — the storage layer (§3)
- `services?: WalletServices` — chain-facing layer (§5)
- `monitor?: Monitor` — background tasks (§6)
- `privilegedKeyManager?: PrivilegedKeyManager` — separately-secured key ops (certificates, HMAC/signature over privileged keys)
- `lookupResolver?: LookupResolver` — defaults to a new one scoped to the chain, used for overlay identity queries
- `contactSource?: ContactSource` — optional local-contacts short-circuit before hitting the overlay for identity discovery (`Wallet.ts:118-131`)
- `settingsManager?: WalletSettingsManager`
- `makeLogger?: MakeWalletLogger`

Constructor **requires** `storage._authId.identityKey === keyDeriver.identityKey` (`Wallet.ts:224-229`) — storage and signer must already be authenticated as the same identity before the `Wallet` will accept them. It also creates a `BeefParty` (`this.beef`, `Wallet.ts:218`) seeded with `this.userParty` — a `Beef` subclass that accumulates and tracks provenance of every transaction/proof that passes through the wallet, enabling "txid-only" proof compression on repeat sends to a party (storage or the user) that already has the data.

### BRC-100 methods implemented, grouped

All at `Wallet.ts`, line numbers of `async` method declarations:

- **Action/transaction**: `createAction` (899), `signAction` (943), `internalizeAction` (962), `abortAction` (978), `listActions` (475), `relinquishOutput` (989), `listOutputs` (497), `listNoSendActions` (1189, non-BRC-100 helper), `listFailedActions` (1203, non-BRC-100 helper)
- **Key/crypto**: `getPublicKey` (329), `revealCounterpartyKeyLinkage` (342), `revealSpecificKeyLinkage` (355), `encrypt` (368), `decrypt` (378), `createHmac` (388), `verifyHmac` (398), `createSignature` (408), `verifySignature` (421)
- **Certificate**: `listCertificates` (514), `acquireCertificate` (528), `relinquishCertificate` (691), `proveCertificate` (701), `discoverByIdentityKey` (720), `discoverByAttributes` (778)
- **Output/basket**: covered by `listOutputs`/`relinquishOutput` above; basket semantics live in storage (§3)
- **Identity**: `getIdentityKey` (325), `discoverByIdentityKey`/`discoverByAttributes` (above)
- **Misc / lifecycle**: `destroy` (312), `isAuthenticated` (999), `waitForAuthentication` (1007), `getHeight` (1015), `getHeaderForHeight` (1021), `getNetwork` (1030), `getVersion` (1035), `sweepTo` (1045, non-BRC-100 helper to sweep funds into another wallet), `balanceAndUtxos`/`balance` (1107/1132, helpers), `reviewSpendableOutputs` (1152), `setWalletChangeParams` (1175)

`discoverByIdentityKey`/`discoverByAttributes` first check `contactSource` (fast local lookup), then fall back to `queryOverlay` (`utility/identityUtils.ts`) against the `LookupResolver`, then run `transformVerifiableCertificatesWithTrust` to attach `TrustSelf` scoring.

---

## 3. Storage layer

This is the largest subsystem. Class hierarchy (all in `wallet-toolbox/src/storage/`):

```
StorageReader (abstract)             storage/StorageReader.ts:35
  └─ StorageReaderWriter (abstract)  storage/StorageReaderWriter.ts:32
       └─ StorageProvider (abstract) storage/StorageProvider.ts:73
            ├─ StorageKnex           storage/StorageKnex.ts:70   (SQL: SQLite/MySQL via knex)
            └─ StorageIdb            storage/StorageIdb.ts:114   (browser IndexedDB via `idb`)

WalletStorageManager                 storage/WalletStorageManager.ts:57
  (implements sdk.WalletStorage — wraps N StorageProvider-or-remote instances)

StorageClientBase (abstract)         storage/remoting/StorageClientBase.ts:44
  ├─ StorageClient                   storage/remoting/StorageClient.ts:23   (full/Node — logger-aware)
  └─ StorageMobile (class StorageClient) storage/remoting/StorageMobile.ts:16 (mobile/browser-lean — no logger passthrough)

StorageServer                        storage/remoting/StorageServer.ts:29  (Express JSON-RPC server wrapping a StorageProvider)
```

### 3.1 `WalletStorageManager` — active/backup topology

`WalletStorageManager` (`storage/WalletStorageManager.ts:57`) implements `sdk.WalletStorage` and
manages a list of `WalletStorageProvider` instances (`_stores`), each wrapped in an internal
`ManagedStorage {storage, settings?, user?, isAvailable, isStorageProvider}` (`WalletStorageManager.ts:29-38`).

**Authority resolution** happens in `makeAvailable()` (`WalletStorageManager.ts:167-198`), driven by
`selectActiveFromStore` (`WalletStorageManager.ts:151-165`):

1. Every configured store's `TableSettings`/`TableUser` records are fetched via `ensureStoreAvailable` (calls `store.storage.makeAvailable()` then `findOrInsertUser(identityKey)`).
2. The **first store added is the tentative default active**. For every store thereafter, if that store's own `TableUser.activeStorage` (the *user's* selected active storage identity key) equals that store's own `TableSettings.storageIdentityKey` (i.e., the store believes itself to be the user's chosen active), it swaps in as active and the previous active is demoted to backups.
3. After the pass, stores are partitioned into `_backups` (agree with the winning active's `storageIdentityKey`) vs. `_conflictingActives` (disagree — i.e. multiple stores each think *they* are the user's active storage; e.g., during unresolved multi-device conflicts).
4. `isActiveEnabled` (`WalletStorageManager.ts:110-116`) is only `true` when the active store's own settings match the active user record's `activeStorage` field **and** there are zero conflicting actives. This lets a wallet be constructed with *read-only* access to storage that isn't (or can't yet be confirmed as) the user's chosen active store.

So authority is not decided by which store was passed in first structurally — it is decided by **each store's own persisted `TableUser.activeStorage` value**, i.e. the storage layer is self-describing about which physical store is canonical, and `WalletStorageManager` reconciles agreement across all configured stores.

**Concurrency**: `WalletStorageManager` implements a manual 4-tier promise-queue lock ladder — reader lock → writer lock (also takes reader) → sync lock (also takes writer+reader) → storage-provider lock (also takes sync+writer+reader) (`WalletStorageManager.ts:257-330`). All storage access goes through `runAsReader`/`runAsWriter`/`runAsSync`/`runAsStorageProvider`, which acquire/release the appropriate lock tier around `getActive()`. This means only one write (and no reads) can proceed at a time against the active store, but this is an in-process lock — it does **not** protect against a genuinely concurrent second writer to a remote SQL store; that is handled by DB-level locking in `StorageKnex`/`StorageServer`.

**`setActive`** (`WalletStorageManager.ts:799+`) is invoked to promote a backup to active: it first calls `updateBackups` to push a full sync to all backups, then flips `TableUser.activeStorage` on the chosen store.

### 3.2 Storage provider interfaces

Defined in `sdk/WalletStorage.interfaces.ts` (616 lines). Interface hierarchy (narrowest → widest):

- **`WalletStorageReader`** (`sdk/WalletStorage.interfaces.ts:165-179`): `isAvailable`, `getServices`, `getSettings`, `findCertificatesAuth`, `findOutputBasketsAuth`, `findOutputsAuth`, `findProvenTxReqs`, `listActions`, `listCertificates`, `listOutputs` — all `auth`-scoped (caller passes an already-resolved `AuthId`).
- **`WalletStorageWriter extends WalletStorageReader`** (`:141-156`): adds `makeAvailable`, `migrate`, `destroy`, `findOrInsertUser`, `abortAction`, `createAction`, `processAction`, `internalizeAction`, `insertCertificateAuth`, `relinquishCertificate`, `relinquishOutput`.
- **`WalletStorageSync extends WalletStorageWriter`** (`:118-133`): adds `findOrInsertSyncStateAuth`, `setActive`, `getSyncChunk`, `processSyncChunk` — the replication protocol (§3.6).
- **`WalletStorageProvider extends WalletStorageSync`** (`:107-113`): adds `isStorageProvider()` and `setServices`. This is the interface every store — local or remote — must satisfy to be added to a `WalletStorageManager`.
- **`WalletStorage`** (`:41-83`, non-`auth`-scoped variant implemented by `WalletStorageManager` itself, since it resolves `auth` internally from its own `_authId`): `isStorageProvider`, `isAvailable`, `makeAvailable`, `migrate`, `destroy`, `setServices`, `getServices`, `getSettings`, `getAuth`, `findOrInsertUser`, `abortAction`, `createAction`, `processAction`, `internalizeAction`, `findCertificates`, `findOutputBaskets`, `findOutputs`, `findProvenTxReqs`, `listActions`, `listCertificates`, `listOutputs`, `insertCertificate`, `relinquishCertificate`, `relinquishOutput`, `getStores`.

Lower still, `StorageReader` (abstract, `storage/StorageReader.ts:35`) declares the raw CRUD surface every concrete engine must implement: `transaction`, `readSettings`, `find*` for every table (`findCertificateFields`, `findCertificates`, `findCommissions`, `findMonitorEvents`, `findOutputBaskets`, `findOutputs`, `findOutputTags`, `findSyncStates`, `findTransactions`, `findTxLabels`, `findUsers`), a matching `count*` for each, and per-user paged variants `getProvenTxsForUser`, `getProvenTxReqsForUser`, `getTxLabelMapsForUser`, `getOutputTagMapsForUser`. `StorageReaderWriter` (abstract, `storage/StorageReaderWriter.ts:32`) adds `insert*`/`update*` for every table plus `dropAllData`, `migrate`, `findOutputTagMaps`, `findProvenTxReqs`, `findProvenTxs`, `findTxLabelMaps`, `findStaleMerkleRoots`, and a large set of `findOrInsert*` convenience helpers implemented once at this level (shared by all concrete engines). `StorageProvider` (abstract, `storage/StorageProvider.ts:73`) adds the actual business logic on top of raw CRUD: `createAction`, `processAction`, `internalizeAction`, `abortAction`, `listCertificates`, `relinquishCertificate`, `relinquishOutput`, `getValidBeefForTxid`/`getValidBeefForKnownTxid`/`getBeefForTransaction`, `updateTransactionStatus`, `updateProvenTxReqWithNewProvenTx`, `confirmSpendableOutputs`, `processSyncChunk`.

### 3.3 Concrete implementations

| Class | File | Backing | Depends on |
|---|---|---|---|
| `StorageKnex` | `storage/StorageKnex.ts:70` (1646 lines) | SQLite (via `better-sqlite3`) or MySQL (via `mysql2`) | `knex` query builder; Node-only |
| `StorageIdb` | `storage/StorageIdb.ts:114` (1965 lines) | Browser IndexedDB | `idb` npm package; browser-only (also usable under a Node `fake-indexeddb` shim, used in tests) |
| `StorageClient` | `storage/remoting/StorageClient.ts:23` | Remote HTTP JSON-RPC | full/Node build; logger-passthrough support |
| `StorageMobile`'s `StorageClient` | `storage/remoting/StorageMobile.ts:16` | Remote HTTP JSON-RPC | mobile/browser-lean build; same wire protocol, no logger merge |
| `MockChainStorage` | `mockchain/MockChainStorage.ts` | In-memory/sqlite simulated chain | test-only, not a `WalletStorageProvider` |

Both `StorageKnex` and `StorageIdb` extend `StorageProvider` and implement `WalletStorageProvider` —
i.e. they are full local engines capable of running `createAction`'s input-selection and
change-generation logic themselves (§4). `StorageClient`/`StorageMobile` implement only the
narrower `WalletStorageProvider` surface by forwarding every call over the wire to a remote
`StorageServer`-fronted `StorageProvider` — they do **not** implement `isStorageProvider()==true`,
so a `WalletStorageManager` backed only by a `StorageClient` cannot be used with
`runAsStorageProvider` (some admin/sync operations require a real local engine).

### 3.4 `StorageClient` — remote JSON-RPC client

- **Transport**: HTTP POST, single endpoint URL, JSON-RPC 2.0 envelope: `{jsonrpc: '2.0', method, params, id}` request, `{result}` or `{error}` response (`storage/remoting/StorageClient.ts:41-58`). Errors are rehydrated via `WalletErrorFromJson` into typed `WalletError` subclasses client-side.
- **Auth**: `AuthFetch` from `@bsv/sdk`, constructed with a `WalletInterface` (`StorageClientBase.ts:56` `this.authClient = new AuthFetch(wallet)`) — this is BRC-103 mutual authentication, where the calling wallet's own identity key signs/authenticates each request. Every RPC call's first parameter is an `AuthId {identityKey, userId?, isActive?}` which the server cross-checks against the `AuthFetch`-established identity.
- **Method names over the wire** (all pass-through 1:1 to `StorageProvider`/`WalletStorageWriter`/`WalletStorageSync` methods): `makeAvailable`, `destroy`, `migrate`, `internalizeAction`, `createAction`, `processAction`, `abortAction`, `findOrInsertUser`, `findOrInsertSyncStateAuth`, `insertCertificateAuth`, `listActions`, `listOutputs`, `listCertificates`, `findCertificatesAuth`, `findOutputBaskets`, `findOutputsAuth`, `findProvenTxReqs`, `relinquishCertificate`, `relinquishOutput`, `processSyncChunk`, `getSyncChunk`, `updateProvenTxReqWithNewProvenTx`, `setActive` (see `StorageClientBase.ts:110-455` for the full pass-through list; every method's wire name matches the interface method name).
- **Server side**: `StorageServer` (`storage/remoting/StorageServer.ts:29`) wraps a `StorageProvider` behind Express, applies `createAuthMiddleware` (from `@bsv/auth-express-middleware`, BRC-103) and optionally `createPaymentMiddleware` (from `@bsv/payment-express-middleware`, BRC-41-style monetization per request, `monetize`/`calculateRequestPrice` options), enforces CORS, and dispatches the JSON-RPC `method` string to the matching `StorageProvider` method (`StorageServer.ts:95+`, method table not fully enumerated here but mirrors the client's method list exactly).
- Response validation on the client side runs every entity through `validateEntity`/`validateEntities`/`validateSyncChunkEntities` (`storage/remoting/entityValidationHelpers.ts`) to coerce date fields (`created_at`/`updated_at`/`when`) that arrive as JSON strings back into `Date` objects, and to reject any `null` field values (storage engines must return `undefined`, never `null` — `getSyncChunk.ts:281-286` `checkEntityValues` enforces the same rule server-side before responding).
- **Security note** (`signer/methods/buildSignableTransaction.ts:24-40`, tagged `GHSA-36f9-7rg5-cpf8`): because the default mobile/browser configuration is `StorageClient` talking to a possibly-untrusted remote storage operator, the signer independently re-verifies that every output the caller actually requested in `createAction`/`signAction` args is echoed back unchanged by storage's response, and checks storage hasn't injected extra attacker-paying outputs funded by shrinking change — **before** anything is signed. This is a wallet-side trust boundary that a Swift port must reproduce exactly if it uses a remote storage backend.

### 3.5 Storage schema

All table row interfaces are in `storage/schema/tables/*.ts`. Every table extends `sdk.EntityTimeStamp` (`created_at: Date; updated_at: Date`).

| Table (interface) | Key columns |
|---|---|
| `TableUser` | `userId` (PK), `identityKey` (unique per-user identity), `activeStorage` (identity key of the store this user currently considers active — drives §3.1's resolution) |
| `TableSettings` | `storageIdentityKey`, `storageName`, `chain`, `dbtype: 'SQLite'\|'MySQL'\|'IndexedDB'`, `maxOutputScript` — singleton row per store describing the store itself |
| `TableTransaction` | `transactionId` (PK), `userId`, `provenTxId?`, `status: TransactionStatus`, `reference` (base64, correlates create/sign/internalize round-trips), `isOutgoing`, `satoshis`, `description`, `version?`, `lockTime?`, `txid?`, `inputBEEF?: number[]`, `rawTx?: number[]` |
| `TableOutput` | `outputId` (PK), `userId`, `transactionId`, `basketId?`, `spendable`, `change`, `vout`, `satoshis`, `providedBy: 'you'\|'storage'\|'you-and-storage'`, `purpose`, `type`, `txid?`, `senderIdentityKey?`, `derivationPrefix?`/`derivationSuffix?` (BRC-29 key derivation material), `customInstructions?`, `spentBy?`, `lockingScript?` (separately-stored to avoid loading big blobs — `outputColumnsWithoutLockingScript` const lists the lean projection) |
| `TableOutputBasket` | `basketId` (PK), `userId`, `name`, `numberOfDesiredUTXOs`, `minimumDesiredUTXOValue`, `isDeleted` |
| `TableOutputTag` / `TableOutputTagMap` | `outputTagId`/`(outputTagId, outputId)` — many-to-many tagging of outputs |
| `TableTxLabel` / `TableTxLabelMap` | `txLabelId`/`(txLabelId, transactionId)` — many-to-many labeling of transactions |
| `TableCertificate` | `certificateId` (PK), `userId`, `type`, `serialNumber`, `certifier`, `subject`, `verifier?`, `revocationOutpoint`, `signature`, `isDeleted` |
| `TableCertificateField` | `(userId, certificateId, fieldName)`, `fieldValue`, `masterKey` (encrypted field value + wrapped key) |
| `TableCommission` | `commissionId` (PK), `transactionId`, `satoshis`, `keyOffset`, `isRedeemed`, `lockingScript` — storage-operator monetization output tracking |
| `TableProvenTx` | `provenTxId` (PK), `txid`, `height`, `index`, `merklePath: number[]` (serialized BUMP), `rawTx`, `blockHash`, `merkleRoot` — a **confirmed** transaction with proof |
| `TableProvenTxReq` | `provenTxReqId` (PK), `provenTxId?` (set once proven), `status: ProvenTxReqStatus`, `attempts`, `notified`, `txid`, `batch?`, `history` (JSON `ProvenTxReqHistoryApi`), `notify` (JSON `ProvenTxReqNotifyApi`), `rawTx`, `inputBEEF?`, `wasBroadcast?`, `rebroadcastAttempts?` — an **outstanding proof request** driving the monitor tasks (§6); `wasBroadcast`/`rebroadcastAttempts` are new-since-1.7.18 fields (added by a 2026-04-30 migration) backing a rebroadcast circuit-breaker |
| `TableSyncState` | `syncStateId` (PK), `userId`, `storageIdentityKey`, `storageName`, `status: SyncStatus`, `init`, `refNum`, `syncMap` (JSON per-table offset cursor, see §3.6), `when?`, `satoshis?`, `errorLocal?`, `errorOther?` |
| `TableMonitorEvent` | `id` (PK), `event`, `details?` — audit log of monitor task runs |

### 3.6 Sync — `getSyncChunk` / replication

Push-based replication: the active store pushes chunks of changed rows to each backup
(`updateBackups`, `WalletStorageManager.ts:779`; `syncFromReader`/`syncToWriter`,
`WalletStorageManager.ts:695/738`).

`getSyncChunk` (`storage/methods/getSyncChunk.ts:24`) is engine-agnostic (`storage: StorageReader`) and works over an ordered list of **chunkers**, one per table, each with a `name`, `maxDivider` (relative share of the byte/item budget), `findItems`, and `addItem`. Tables are synced in dependency order: `provenTx → outputBasket → outputTag → txLabel → transaction → output → txLabelMap → outputTagMap → certificate → certificateField → commission → provenTxReq`. The caller supplies `RequestSyncChunkArgs {offsets: {name, offset}[], since?, maxItems, maxRoughSize}` — an explicit per-table cursor array plus a global item-count and byte-size budget; `getSyncChunk` walks each table's rows `since` a timestamp, paginating with `offset`, until either budget is exhausted, returning a `SyncChunk` with only the tables that produced rows this round (each field like `r.provenTxs` is only set if that chunker fired). The caller (receiving side, `processSyncChunk` in `StorageProvider.ts:770`) applies the chunk, then requests the next chunk with updated offsets, repeating until a chunk comes back empty for every table (full catch-up). Every row is validated with `checkEntityValues` (dates must be real `Date` instances, no `null` field values permitted) before being added to a chunk.

`findOrInsertSyncStateAuth` establishes/reuses a `TableSyncState` row per (user, remote store) pair
to persist the sync cursor (`syncMap`) across sessions.

---

## 4. Actions / transaction building

Two-layer split: **storage-side** input selection/change generation (server-authoritative, works even against a fully-remote `StorageClient`) and **signer-side** transaction assembly/signing (client-side, holds the private keys).

### `createAction` end-to-end

1. **`Wallet.createAction`** (`Wallet.ts:899`) → **`signer/methods/createAction.ts:33`** `createAction(wallet, auth, vargs)`.
2. If `vargs.isNewTx`, calls `createNewTx` (`createAction.ts:79`):
   - `wallet.storage.createAction(storageArgs)` → **`storage/methods/createAction.ts:54`**, running against whichever engine is active (`StorageKnex`/`StorageIdb` directly, or `StorageClient` forwarding to a remote `StorageProvider`). This method: verifies all supplied inputs either carry proof in `inputBEEF` or are already known-valid to storage (`trustSelf === 'known'`); creates a `TableTransaction` row (`status: 'unsigned'`) as an anchor; creates label rows; adds an optional commission output; **funds the transaction** by calling `generateChangeSdk` (§4.1) to allocate/lock change inputs and create new change outputs; creates output/basket/tag rows; optionally assembles a result `Beef` with full proofs for every input used; returns a `StorageCreateActionResult {inputs, outputs, reference, ...}`.
   - **`buildSignableTransaction`** (`signer/methods/buildSignableTransaction.ts:12`) turns that result into an actual `bsv-sdk` `Transaction` object: builds `TransactionInput`/`TransactionOutput` from the storage-returned `StorageCreateTransactionSdkInput`/`Output` rows, attaches `ScriptTemplateBRC29` for BRC-29 P2PKH change outputs derived via `wallet.getClientChangeKeyPair()`, and — critically — runs `verifyRequestedOutputsUnchanged` (the GHSA-36f9-7rg5-cpf8 mitigation, §3.4) before anything is signed.
3. If the caller asked for `isSignAction` (deferred signing — caller wants to countersign custom inputs), a `SignableTransaction` is returned to the caller now (`makeSignableTransactionResult`) and the flow pauses; the caller later calls **`Wallet.signAction`** (`Wallet.ts:943`) → `signer/methods/signAction.ts`, which supplies the missing unlocking scripts and resumes at step 4 via `completeSignedTransaction`.
4. Otherwise, `completeSignedTransaction` (`signer/methods/completeSignedTransaction.ts:8`) inserts any caller-provided unlocking scripts, then signs every wallet-owned input using derived BRC-29 keys and `ScriptTemplateBRC29.unlock`, producing a fully-signed `Transaction`.
5. The wallet merges the completed tx (+ any `inputBeef`) into a `Beef`, calls `verifyUnlockScripts` to confirm every input actually validates, computes `txid`, and — unless `options.returnTXIDOnly` — serializes to `AtomicBEEF` (`beef.toBinaryAtomic(txid)`, BRC-95) as `r.tx`.
6. **`processAction`** (`signer/methods/*` → `wallet.storage.processAction`, storage-side `storage/methods/processAction.ts`) is called with the completed transaction to finalize storage-side records: updates the `TableTransaction` status, creates a `TableProvenTxReq` (unless the caller flagged the tx as "no send"), and — unless `options.noSend`/deferred — attempts to broadcast via `attemptToPostReqsToNetwork.ts` which calls into `WalletServices.postBeef` (§5). Returns `sendWithResults`/`notDelayedResults` used to populate the final `CreateActionResult`.

`internalizeAction` (`Wallet.ts:962` → `signer/methods/internalizeAction.ts` → `storage/methods/internalizeAction.ts`, 759 lines) is the inverse: a wallet ingests a transaction (and BEEF) it did not create — e.g. an incoming payment — validating the BEEF, re-deriving output ownership via BRC-29, and inserting the relevant `TableOutput`/`TableTransaction` rows.

### 4.1 Fee model, change, input selection — `generateChangeSdk`

`storage/methods/generateChange.ts:113` `generateChangeSdk(params, allocateChangeInput, releaseChangeInput, logger)`.

- **Fee model**: only `satsPerKb` is supported ("Simplifications: only support one change type with fixed length scripts. only support satsPerKb fee model.", `generateChange.ts:103-105`). `StorageFeeModel` is validated by `validateStorageFeeModel` (`StorageProvider.ts`).
- **Dust floor**: computed from the minimum viable spend-tx size (`transactionSize` helper, one change input + one change output) at the configured `satsPerKb`; a change output must be worth at least 2× that fee to be created (`generateChange.ts:141-146`).
- **Input selection**: allocation is driven by injected callbacks `allocateChangeInput(targetSatoshis, exactSatoshis?)`/`releaseChangeInput(outputId)` supplied by the caller (storage engine) — `generateChangeSdk` itself is engine-agnostic and only orchestrates the *algorithm*; each engine (`StorageKnex`, `StorageIdb`) implements the actual row-locking allocate/release against its own table. This is a clean seam for a Swift port: reimplement `generateChangeSdk`'s pure logic once, then supply an engine-specific allocator.
- Randomness for output-count/ordering decisions is injectable (`params.randomVals`) for repeatable testing — production draws from `Random(4)` (`@bsv/sdk`, CSPRNG).
- `removeChurnPairs`/`distributeExcessFees`/`removeDustOutputs` (`generateChange.ts:46-101`) post-process the candidate change set to avoid pointless input/output pairs, redistribute leftover fee remainder into the largest change output, and merge/drop sub-dust outputs.
- `maxChangeOutputsPerTransaction` defaults limit how many new change UTXOs one transaction creates (grows the UTXO pool gradually rather than in one large batch); `params.maxChangeOutputs` can override per-call (e.g. consolidation transactions).

### 4.2 BEEF / BRC-95 handling

- `Wallet.beef: BeefParty` (`@bsv/sdk`, `Wallet.ts:218`) — a `Beef` subclass tracking, per known "party" (storage or the counterparty user), which transactions/proofs they already have, so subsequent sends can omit already-known data ("txid-only" entries) instead of re-sending full proofs.
- `AtomicBEEF` serialization (`beef.toBinaryAtomic(txid)`) is what `createAction`/`signAction` return as `tx` — this is the BRC-95 wire format (single-topic atomic BEEF anchored to one txid).
- Merkle proof validation: proofs arrive as `MerklePath` (BUMP format, from `@bsv/sdk`) and are stored as serialized `number[]` in `TableProvenTx.merklePath`; `utility/tscProofToMerklePath.ts` converts legacy TSC-format proofs. `verifyKnownValidTransaction`/`getValidBeefForKnownTxid`/`getValidBeefForTxid` (`StorageProvider.ts:616/635/693`) assemble and validate BEEF for a given txid against known proven/pending state.
- `mockchain/merkleTree.ts` (`computeMerkleRoot`/`computeMerklePath`) is a test-only local merkle implementation used by the simulated chain (§ testing), not production proof validation (that's `@bsv/sdk`'s `MerklePath.verify` against a `ChainTracker`).

---

## 5. Services (chain-facing layer)

`Services` (`services/Services.ts:41`) `implements WalletServices` (interface at `sdk/WalletServices.interfaces.ts:19`, ~200 lines). Composes a set of provider instances and `ServiceCollection<T>` fallback chains (`services/ServiceCollection.ts`) that cycle through configured providers on failure.

| Provider | File | Role |
|---|---|---|
| `WhatsOnChain` | `services/providers/WhatsOnChain.ts` | UTXO/status lookups, raw tx fetch, script-hash history; default general-purpose block-explorer API client |
| `ARC` (used twice: `arcTaal`, optional `arcGorillaPool`) | `services/providers/ARC.ts` | Transaction broadcaster (Bitcoin Association's ARC protocol) |
| `Arcade` (optional, `options.arcadeUrl`) | `services/providers/Arcade.ts` + `ArcSSEClient.ts` | Newer primary broadcaster (`bsv-blockchain/arcade`); supports Server-Sent-Events push status updates (feeds `TaskArcSSE`, §6) |
| `Bitails` (optional) | `services/providers/Bitails.ts` | Alternate UTXO/tx-status provider |
| exchange rates | `services/providers/exchangeRates.ts` (`updateChaintracksFiatExchangeRates`, `updateExchangeratesapi`) | Fiat/BSV rate feeds |
| `getBeefForTxid` | `services/providers/getBeefForTxid.ts` | Standalone BEEF-assembly helper reused by `Services.getBeefForTxid` |
| Chaintracker | `services/chaintracker/ChaintracksChainTracker.ts` (implements `@bsv/sdk`'s `ChainTracker`) wrapping `services/chaintracker/chaintracks/*` (§6.1) | Block-header/merkle-root source of truth for proof verification |

`WalletServices` interface surface (`sdk/WalletServices.interfaces.ts`): `chain`, `getChainTracker()`, `getHeaderForHeight(height)`, `getHeight()`, `getBsvExchangeRate()`, `getFiatExchangeRate(currency, base?)`, `getFiatExchangeRates(targets)`, `getStatusForTxids(txids, useNext?)`, `isUtxo(output)`, `getUtxoStatus(...)`, `getScriptHashHistory(...)`, `postBeef(beef, txids, logger?)`, `getRawTx(txid, useNext?)`, `getMerklePath(txid, useNext?, logger?)`, `updateFiatExchangeRates(...)`, `nLockTimeIsFinal(...)`, `getBeefForTxid(txid)`. `Services.getStatusForTxidsBatchLimit = 20` caps batch lookup size.

Each provider category (`getMerklePathServices`, `getRawTxServices`, `postBeefServices`, `getUtxoStatusServices`, `getStatusForTxidsServices`, etc., `Services.ts:53-58`) is a `ServiceCollection` — an ordered, cyclable list — so a `postBeef` call, for instance, tries `arcTaal`, falls through to `arcGorillaPool`/`arcade`, and so on, per configured priority, returning an array of `PostBeefResult` (one per provider attempted, not just the first success) so the caller can see which providers accepted the broadcast.

---

## 6. Monitor / background tasks

`Monitor` (`monitor/Monitor.ts:97`), constructed with `{chain, services, storage: WalletStorageManager, chaintracks: ChaintracksClientApi, chaintracksWithEvents?, startupTaskMode, msecsWaitPerMerkleProofServiceReq, taskRunWaitMsecs, abandonedMsecs, unprovenAttemptsLimitTest/Main, ...}` (`Monitor.ts:34-96`). Runs a set of `WalletMonitorTask` subclasses (`monitor/tasks/WalletMonitorTask.ts`) either on a schedule (`runOnce`/`startTasks`, `Monitor.ts:321/380`) or triggered by name (`runTask`, `Monitor.ts:310`).

| Task | File | What it does |
|---|---|---|
| `TaskClock` | `TaskClock.ts` | Heartbeat driving the periodic scheduler |
| `TaskNewHeader` | `TaskNewHeader.ts` | Polls for new block headers; a new block is the trigger point to (a) check for proofs of recently-broadcast txs and (b) bound which proofs are accepted by height, to avoid accepting a proof that gets re-orged out almost immediately |
| `TaskCheckForProofs` | `TaskCheckForProofs.ts` | Fetches merkle proofs for transactions awaiting confirmation; normally triggered by the new-header event |
| `TaskCheckNoSends` | `TaskCheckNoSends.ts` | Checks proofs for "nosend" transactions — fully valid txs the wallet built but did not itself broadcast (may have been shared externally by the app) |
| `TaskSendWaiting` | `TaskSendWaiting.ts` | Broadcasts transactions still waiting to be sent |
| `TaskFailAbandoned` | `TaskFailAbandoned.ts` | Transactions stuck in a non-terminal status past `abandonedMsecs` are set to `failed`; releases their inputs back to spendable and verifies no double-spend actually landed |
| `TaskReorg` | `TaskReorg.ts` | Reacts to `monitor.deactivatedHeaders`; re-checks `ProvenTx` records anchored to orphaned headers and updates/invalidates their proofs |
| `TaskReviewStatus` | `TaskReviewStatus.ts` | Notifies `TableTransaction` rows of `TableProvenTxReq` status changes they may have missed (aged transactions with a proven req not yet marked completed) |
| `TaskUnFail` | `TaskUnFail.ts` | Recovery: for reqs marked `invalid`, retries a merkle-path lookup; on success flips back through `unmined` → updates matching outputs' `spentBy`/`spendable` |
| `TaskReviewDoubleSpends` | `TaskReviewDoubleSpends.ts` | Reviews reqs terminally marked `doubleSpend`; moves false positives back to `unfail` for reprocessing (new since v1.7.18) |
| `TaskReviewProvenTxs` | `TaskReviewProvenTxs.ts` | (new since v1.7.18; no header docstring found — reconciles `TableProvenTx` records, inferred from name/placement alongside the other review tasks) |
| `TaskReviewUtxos` | `TaskReviewUtxos.ts` | Manual/on-demand review of a specific user's UTXOs by identity key (`reviewByIdentityKey`); disabled by default, not scheduled |
| `TaskPurge` | `TaskPurge.ts` | Deletes transient data (defines the tiers of what must be preserved — UTXOs, in-use metadata — vs. what's safe to purge) |
| `TaskMonitorCallHistory` | `TaskMonitorCallHistory.ts` | Records `ServicesCallHistory` telemetry (no docstring found; inferred from name) |
| `TaskArcSSE` (`TaskArcadeSSE`) | `TaskArcSSE.ts` | Subscribes to Arcade's SSE stream for real-time tx status pushes, including fetching merkle proofs directly from Arcade when a tx reports MINED (new since v1.7.18) |
| `TaskMineBlock` | `TaskMineBlock.ts` | Test/mockchain-only: mines a block on the simulated chain (no docstring; paired with `mockchain/MockMiner.ts`) |
| `TaskSyncWhenIdle` | `TaskSyncWhenIdle.ts` | Triggers `WalletStorageManager` backup sync during idle periods (no docstring found; inferred from name/placement) |

`Monitor.logEvent`/`fetchSSEEvents` (`Monitor.ts:401/487`) write to `TableMonitorEvent` for observability.

### 6.1 Chaintracks (block-header ingestion, sub-layer of Services)

`services/chaintracker/chaintracks/` is a self-contained header-tracking subsystem with its own storage and ingestor abstraction:

- **Storage backends**: `ChaintracksStorageKnex`, `ChaintracksStorageIdb`, `ChaintracksStorageMemory`, `ChaintracksStorageNoDb` (`Storage/*.ts`) — same Node/browser/memory split as the wallet's own storage layer.
- **Bulk ingestors** (historical header backfill): `BulkIngestorCDN`, `BulkIngestorCDNBabbage`, `BulkIngestorWhatsOnChainCdn`, `BulkIngestorWhatsOnChainWs` (`Ingest/*.ts`).
- **Live ingestors** (new-block streaming): `LiveIngestorChaintracksSSE`, `LiveIngestorTeranodeP2P` (uses `@bsv/teranode-listener`), `LiveIngestorWhatsOnChainPoll`, `LiveIngestorWhatsOnChainWs` (`Ingest/*.ts`).
- Factory functions `createIdbChaintracks`, `createKnexChaintracks`, `createNoDbChaintracks` (root of `chaintracks/`) wire a storage backend + ingestor set into a runnable `Chaintracks` instance; `ChaintracksServiceClient`/`GoChaintracksServiceClient` are remote clients against a standalone Chaintracks service (including a Go-implemented one).

---

## 7. Key derivation

**BRC-42/43 key derivation itself is not implemented in the toolbox** — it lives in the core SDK: `packages/sdk/src/wallet/KeyDeriver.ts` and `packages/sdk/src/wallet/CachedKeyDeriver.ts`. The toolbox only *consumes* `KeyDeriverApi` (constructor-injected into `Wallet`, `WalletSigner`, etc.) — this is already covered by the existing Swift SDK layer per the task framing.

**BRC-29 deposit-address derivation** is implemented in the toolbox: `utility/ScriptTemplateBRC29.ts`. `brc29ProtocolID: WalletProtocol = [2, '3241645161d8']` (security-level 2, the fixed BRC-29 protocol string). `ScriptTemplateBRC29 implements ScriptTemplate` (the `@bsv/sdk` locking/unlocking template interface):
- `getKeyID()` → `` `${derivationPrefix} ${derivationSuffix}` `` (the BRC-29 key ID is the space-joined prefix+suffix pair, both required — constructor asserts both are truthy).
- `lock(lockerPrivKey, unlockerPubKey)` → derives a public key via `keyDeriver.derivePublicKey(brc29ProtocolID, keyID, unlockerPubKey, false)`, converts to a P2PKH address, locks with `P2PKH.lock`.
- `unlock(unlockerPrivKey, lockerPubKey, ...)` → derives the matching private key via `keyDeriver.derivePrivateKey(brc29ProtocolID, keyID, lockerPubKey)`, unlocks with `P2PKH.unlock`. Fixed `unlockLength = 108` (P2PKH signature+pubkey unlock is constant-length).
- `getKeyDeriver` lazily wraps a raw private key in a fresh `CachedKeyDeriver` if it doesn't match the instance's configured `keyDeriver.rootKey` — supporting one-off derivation from an arbitrary key (e.g. change-key derivation using the wallet's separate `getClientChangeKeyPair()`).

`derivationPrefix`/`derivationSuffix` are persisted per-output in `TableOutput` (§3.5) so a later spend can reconstruct the exact key ID used to lock that output.

---

## 8. What depends on a browser or Node — platform-abstraction points for a Swift port

The toolbox already ships **three build targets from one source tree** (`index.all.ts` / `index.client.ts` / `index.mobile.ts`, each re-exporting a different subset — see `Wallet.ts`'s sibling index files and `storage/index.{all,client,mobile}.ts`), which is itself a map of every platform seam:

| Platform-bound piece | Node/full (`index.all`) | Browser (`index.client`) | Mobile/RN (`index.mobile`) | Swift-port substitute needed |
|---|---|---|---|---|
| **SQL storage** (`StorageKnex`) | ✅ (`knex` + `better-sqlite3`/`mysql2`, native bindings) | ❌ excluded | ❌ excluded | SQLite via a native Swift driver (e.g. GRDB/SQLite.swift) implementing the same `StorageReaderWriter`/`StorageProvider` abstract contract |
| **IndexedDB storage** (`StorageIdb`) | ✅ (bundled, though moot on a server) | ✅ (`idb` npm package, real browser IndexedDB) | ❌ **excluded** — `index.mobile.ts` does *not* export `StorageIdb` at all | **No existing local-storage engine to port for mobile** — the TS mobile build ships with *zero* local persistence; it relies entirely on `StorageMobile`'s remote `StorageClient`. A Swift port targeting on-device persistence has no TS mobile precedent to copy; either mirror `StorageKnex`'s logic against SQLite, or accept remote-only storage like the TS mobile build does |
| **Remote storage client** (`StorageClient`/`StorageMobile`) | ✅ (logger-aware) | ✅ (via client build) | ✅ (lean variant, `StorageMobile.ts`) | Straightforward: URLSession + JSON-RPC + BRC-103 `AuthFetch`-equivalent (already exists in Swift SDK per framing, or needs porting from `@bsv/sdk`'s `AuthFetch`) |
| **Express server** (`StorageServer`) | ✅ | n/a (never shipped client-side) | n/a | Not needed for a wallet client port — only relevant if the Swift project also needs to *host* a storage server |
| **WebCrypto** (PBKDF2 in `CWIStyleWalletManager.ts`) | Falls back to `hash-wasm` if WebCrypto unavailable (`CWIStyleWalletManager.ts:135-142`) | Uses native WebCrypto | (inferred: same fallback pattern) | CryptoKit / CommonCrypto PBKDF2 on iOS; Argon2id (UMP v3 KDF) needs a Swift Argon2 implementation |
| **`fetch`** (all remote calls: `StorageClient`, `ARC`, `Arcade`, `WhatsOnChain`, `Bitails`, `ChaintracksFetch`) | Node global `fetch` (Node ≥18) | browser `fetch` | RN `fetch` polyfill (assumed) | URLSession-based networking layer |
| **Server-Sent Events** (`ArcSSEClient.ts`, `LiveIngestorChaintracksSSE.ts`, `TaskArcSSE.ts`) | via `ws`/EventSource-equivalent | browser `EventSource` (inferred) | (inferred; needs verification) | Needs an SSE client — iOS has no built-in EventSource; requires a URLSession streaming-response implementation |
| **WebSockets** (`LiveIngestorWhatsOnChainWs.ts`, `authsocket`) | `ws` package | browser native `WebSocket` | (inferred) | URLSessionWebSocketTask |
| **Web Workers** | Not found in the toolbox source (no `Worker`/`postMessage` usage located in `wallet-toolbox/src`) — none to substitute | | | n/a |
| **Node filesystem** (`ChaintracksFsApi`/`ChaintracksFs.ts`, bulk header file storage) | ✅ (reads/writes header bulk files to disk) | ❌ (browser build uses CDN/idb-backed bulk storage instead) | (inferred: excluded, same reasoning as `StorageIdb`) | FileManager-based bulk header cache, or skip bulk-file ingestion and always live-sync from a service if header-file distribution isn't needed |
| **`better-sqlite3` native binding** | ✅ | ❌ | ❌ | n/a — only relevant to a server-side Swift port, not a client wallet |
| **P2P networking** (`LiveIngestorTeranodeP2P.ts`, `@bsv/teranode-listener`) | ✅ (Node TCP/DHT) | ❌ (excluded from client/mobile ingestor configs — inferred from `createDefaultIdbChaintracksOptions.ts`/`createDefaultNoDbChaintracksOptions.ts` naming, not directly confirmed) | ❌ (same, inferred) | Out of scope for a wallet client; this is a specialized low-latency listener, not required for BRC-100 wallet correctness |

**Bottom line for the port**: the single biggest platform decision the TS toolbox has already made — and a Swift port must explicitly decide, rather than inherit — is that **mobile has no on-device storage engine**. `StorageIdb` (the only non-SQL, non-remote local engine) is deliberately excluded from `index.mobile.ts`. Every existing TS mobile deployment is therefore either (a) remote-storage-only via `StorageClient`, or (b) something downstream built its own storage engine outside this repo. If the Swift wallet wants genuine offline/local persistence on iOS, there is no TS precedent to port — it requires reproducing `StorageProvider`'s abstract contract (§3.2) against a new SQLite-backed engine modeled on `StorageKnex`'s *behavior* (not its knex-specific code), a real do-we-want-this design decision, not a naming or research question — this is the kind of decision this map exists to surface for the design agent handling the Swift side, not one to resolve here.

---

## Appendix: version drift, `ts-stack` (2.4.0) vs standalone `wallet-toolbox` (1.7.18)

Confirmed absent in the 1.7.18 tree (`~/code/wallet-toolbox/src`), present in 2.4.0:

- `entropy/EntropyCollector.ts` — mouse-movement entropy mixing for key generation (new)
- `mockchain/*` — simulated chain test harness: `MockChainStorage`, `MockChainTracker`, `MockMiner`, `MockServices`, `merkleTree.ts` (new)
- `ShamirWalletManager.ts` — Shamir Secret Sharing key recovery, alternative to `CWIStyleWalletManager`'s password+UMP-token recovery (new)
- `services/providers/Arcade.ts` + `services/providers/ArcSSEClient.ts` — new primary broadcaster with SSE push (new)
- `monitor/tasks/TaskArcSSE.ts`, `TaskReviewDoubleSpends.ts`, `TaskReviewProvenTxs.ts`, `TaskReviewUtxos.ts` — new monitor tasks (old tree has 12 tasks; new tree has 17)
- `TableProvenTxReq.wasBroadcast` / `.rebroadcastAttempts` — rebroadcast circuit-breaker fields, added by a named 2026-04-30 migration
- `Wallet.ts`'s `ContactSource` interface (local-contacts short-circuit for identity discovery) — confirmed absent from the 1.7.18 `Wallet.ts`. (`BeefParty` itself is *not* new — it was already present in 1.7.18's `Wallet.ts:8/145-154/227`.)

This is a partial diff (targeted at what's structurally new/absent), not an exhaustive line-by-line comparison of shared files.
