# swift-wallet-toolbox: gap analysis against TS/Go toolboxes and the mobile app

Scope: what is still missing for functional parity with `ts-stack/packages/wallet/wallet-toolbox`
and `go-wallet-toolbox`, filtered by what `1sat-wallet-mobile` actually needs. Everything DESIGN.md
§4 already lists as built is out of scope here. Method: read the three reference trees plus the
consuming app, not assumption.

## Priority summary

| # | Gap | Rating | Build order |
|---|---|---|---|
| 1 | `usdPerBSV` provider in `ToolboxServices` | MUST-HAVE | first |
| 2 | `RemoteWallet` crypto ops (`getPublicKey`/`createSignature`/`encrypt`/`decrypt`/HMAC) | IMPORTANT | second |
| 3 | Broadcast/status fallback path (`postBEEF`, `statusForTXIDs`, `isUTXO`) | IMPORTANT | third |
| 4 | Monitor tasks (`SendWaiting`, `CheckForProofs`, `FailAbandoned`) | LATER | — |
| 5 | Formal `WalletStorageProvider` conformance on `StorageClient` | LATER | — |
| 6 | Certificates / identity discovery / `acquireCertificate` | LATER | — |
| 7 | Output basket management (`findOutputBaskets` exposed on `RemoteWallet`) | LATER | — |
| — | `merklePath` / SPV proof verification | NOT NEEDED YET | — |

The app was read directly (`~/code/1sat-wallet-mobile/OneSatWallet`), not inferred. Two findings
drove the ranking: the app already hand-rolls a WhatsOnChain exchange-rate client that duplicates
protocol surface the toolbox already declares but never implements, and two "Connect" affordances
(`DiscoverAppsView.swift`, `SessionWire.Method.connect`) are UI-complete but explicitly marked
`"Mocked: Connect buttons do not open a BRC-100 session yet."`

## 1. `usdPerBSV` provider — MUST-HAVE

`ToolboxServices/ChainServices.swift:45` declares `func usdPerBSV() async throws -> Double` on
`WalletServices`, matching Go's `BsvExchangeRateFunc` in
`go-wallet-toolbox/pkg/services/services_definition.go:44` and TS's
`services/providers/exchangeRates.ts`. No provider exists.

The app already needs this rate — `ExchangeRateRow.swift`, `SendView.swift`, `CardViews.swift`, and
four other files consume it — and gets it from
`1sat-wallet-mobile/OneSatWallet/Services/ExchangeRate.swift`, a standalone 85-line client that
calls `https://api.whatsonchain.com/v1/bsv/main/exchangerate` directly, with its own caching and
staleness logic, entirely outside the toolbox.

This is not a hypothetical need; it is duplicated code today. `swift-sdk`'s `BSVNetwork` module
already has the HTTP transport and WhatsOnChain wiring patterns to copy
(`BSVNetwork/WhatsOnChain/WhatsOnChainBroadcaster.swift`,
`BSVNetwork/WhatsOnChain/WhatsOnChainChainTracker.swift` — same transport, same host, same request
policy shape), just no exchange-rate endpoint yet. Writing a `WhatsOnChainRates` provider that
implements `usdPerBSV()` and adapting `ExchangeRate.swift` to call through `WalletServices` removes
one hand-maintained network client from the app and gives it the caching/staleness policy for free
if `ServiceQueue` retry/fallback semantics are used.

**Build first** because it is small (one endpoint, one decode), has zero dependency on anything
else in this table, and deletes real duplicate code rather than adding speculative surface.

## 2. `RemoteWallet` crypto ops — IMPORTANT

`ToolboxWallet.RemoteWallet` exposes `connect`, `balance`, `history`, `receiveAddress`, `pay`,
`abort` — nothing from the BRC-100 crypto surface (`getPublicKey`, `createSignature`,
`verifySignature`, `encrypt`, `decrypt`, `createHMAC`, `verifyHMAC`).

The gap is not that these are hard: `swift-sdk`'s `ProtoWallet`
(`BSVWallet/Crypto/ProtoWallet.swift`) already implements every one of them completely, correctly,
and with tests — TS's mirror is `Wallet.ts:329-431`, which forwards the same seven calls to
`this.proto` when no privileged key manager is configured, exactly the shape `RemoteWallet` should
copy. Wiring is a few lines: hold a `ProtoWallet` alongside the `identityKey` and forward.

The gap matters because of what it blocks, not because it is difficult. `1sat-wallet-mobile`'s
BRC-100 handoff (`Services/Session/BRC100Session.swift`, `SessionCodec.swift`) already reserves
`SessionWire.Method.connect` as a wire value, and `DiscoverAppsView.swift` ships a full "Discover
Apps" screen with Connect buttons on every card — footnoted `"Mocked: Connect buttons do not open a
BRC-100 session yet."` `ResultSigner.swift` signs every result "for anyone" today and says explicitly
in its own doc comment: *"Once the connect phase lands and the caller's identity key is known, this
becomes a signature for that key."* Connect is the next BRC-100 milestone this app has already
built UI for, and connect needs `getPublicKey` (to hand the dApp an identity key) and
`createSignature`/`verifySignature` (to authenticate the session) at minimum.

Rated IMPORTANT rather than MUST-HAVE only because Connect itself has not started — this is a
enabler, not something blocking a shipped flow today. It should be built in the same PR that starts
Connect, not before. Note `ProtoWallet.requireStandardAccess` throws for anything but
`.access == .standard` — there is no permission-grant system in Swift (TS's
`WalletPermissionsManager` is out of scope per DESIGN.md), so `RemoteWallet`'s wrapper should
hard-code standard access rather than pretend to support a policy tier that does not exist.

## 3. Broadcast/status fallback path — IMPORTANT

`postBEEF`, `statusForTXIDs`, and `isUTXO` are declared on `WalletServices` with no provider.
`swift-sdk` ships both `ARCClient` (`BSVNetwork/ARC/ARCClient.swift`, `submit`/`broadcast`/`status`)
and `WhatsOnChainBroadcaster`/`WhatsOnChainChainTracker` ready to adapt — this is the least new code
of anything in this report, mostly protocol conformance over existing clients.

The send path already broadcasts via storage's `processAction` (DESIGN.md's stated reason for
deferring this), and today's app has zero client-side transaction-status polling —
`TransactionDetailView.swift` shows nothing derived from status, and `listActions` already returns
status per the wire schema. So this is not blocking a UI today the way item 1 is.

It still ranks above "later": `processAction`'s broadcast result is opaque past the initial
response — if the storage server's own broadcast silently fails after returning success, the wallet
has no independent way to notice, and a resilience-minded wallet (which is what "IMPORTANT" is
tracking here, not a named screen) wants a second path. Building it after item 2, not before,
because item 2 unlocks a feature the app has already committed UI to and this does not yet.

## 4. Monitor tasks — LATER

Go's actual runtime default (`go-wallet-toolbox/pkg/monitor/all_tasks.go`) is three tasks —
`CheckForProofs`, `SendWaiting`, `FailAbandoned` — not seventeen; TS's `Monitor.ts:225-238` runs the
full seventeen only because a TS deployment owns its own storage engine and needs reorg handling,
UTXO review, double-spend review, and purge on top of the three Go keeps. Swift's `MonitorTask`
protocol doc comment already states "two" (`SendWaiting`+`CheckForProofs`); Go's own production
default disagrees by one — `FailAbandoned` also ships in every real Go deployment and should be in
the same "minimum" list when it is built.

The reason this is LATER and not IMPORTANT: `1sat-wallet-mobile` talks to `wallet.1sat.app`, a
storage server that is itself backed by a toolbox (TS or Go) already running its *own* Monitor
daemon server-side. A client-side `SendWaiting`/`CheckForProofs`/`FailAbandoned` trio duplicates
work the storage operator already does for every account on that server. It earns its keep the day
a storage backend ships that does *not* run its own monitor — which is not today's backend — so
build it when that backend exists, not preemptively.

## 5. Formal `WalletStorageProvider` conformance — LATER

`StorageClient` implements every method of `WalletStorageReader`/`WalletStorageWriter` but is not
declared to conform to `WalletStorageProvider`, which additionally requires `getSyncChunk`,
`processSyncChunk`, and `isStorageProvider`.

Checked whether any consumer needs the formal conformance today: none does.
`StorageProviderView.swift` in the app is a picker between "1Sat Cloud" and "On this iPhone",
explicitly footnoted `"Mocked: changing this picker does not move wallet data."` — on-device storage
is UI-only, matching DESIGN.md's deferral. The conformance exists purely to let two stores
reconcile via `getSyncChunk`/`processSyncChunk`, which needs a second store to reconcile with, which
does not exist. Build this the day on-device storage or a second remote is started, not before —
it's a protocol-conformance annotation plus two new methods, cheap to add exactly when needed.

## 6. Certificates, identity discovery, `acquireCertificate` — LATER

Checked the app's one certificate-adjacent-sounding feature, "Passes"
(`Features/Passes/PassDetailView.swift`, `PassActionSheets.swift`, `PassInformationView.swift`,
`ArchivedPassesView.swift`): it is a 1Sat Ordinals NFT collection viewer — transfer, list, hide,
remove — with no reference to BRC-100 certificates, `discoverByIdentityKey`, or
`acquireCertificate` anywhere in the four files. The one match for "identity key" in that whole
feature is a free-text field asking the user to paste a recipient's paymail or identity key for a
transfer, unrelated to certificate issuance or verification.

This confirms DESIGN.md's existing call: no Swift consumer, Go ships without it too
(`panic("implement me")` for the whole certificate/identity surface). Nothing found in this pass
changes that.

## 7. Output basket management — LATER

`RemoteWallet.balance(basket: String = "default")` takes a basket name but there is no way to list
baskets (`findOutputBaskets` exists on `WalletStorageReader` but nothing above it surfaces it) or
see per-basket balances. The app shows one aggregate balance today with no basket-aware UI anywhere
in `Features/Home` or `Features/Accounts`. Build when a basket-aware feature (e.g. per-app coin
separation for BRC-100 grants) is scoped, not before.

## Not needed yet: `merklePath` / SPV

`merklePath(txid:)` is declared on `WalletServices` with no provider and no consumer — grepped the
whole app for `merklePath`/`MerkleProof`/`SPV` and the only hits are in the Yours-backup import/export
code and the BRC-100 session file, none of which do proof verification. The app takes storage's word
for transaction state today. This stays off the build order entirely until an SPV-verifying feature
is actually scoped — it is the one item in this report with truly zero pull from any direction.

## Recommended build order

1. `usdPerBSV` (WhatsOnChain) — deletes real duplicate code in the app today.
2. `RemoteWallet` crypto-op wrapper over `ProtoWallet` — build together with the app's Connect
   feature when that work starts; the wiring is trivial, the value is entirely about timing.
3. Broadcast/status fallback (`postBEEF`, `statusForTXIDs`, `isUTXO`) via `ARCClient` and
   `WhatsOnChainBroadcaster`/`ChainTracker` — resilience work, do after Connect ships.
4. Monitor tasks, `WalletStorageProvider` conformance, certificates, basket management, SPV — build
   each the day its actual trigger (a non-monitored storage backend, on-device storage, a
   certificate-consuming feature, a basket-aware feature, an SPV feature) is scoped, not before.
