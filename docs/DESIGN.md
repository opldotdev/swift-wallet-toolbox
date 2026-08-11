# Design

This document records what the library is, what v1 covers, and why each boundary sits where it
does. It is written from a survey of the three existing implementations: the TypeScript toolbox
(`bsv-blockchain/ts-stack`), the Go toolbox (`bsv-blockchain/go-wallet-toolbox`), and the Swift SDK
this library sits on (`opldotdev/swift-sdk`).

## 1. What this library is

`swift-sdk` already carries the BRC-100 **contract**: `WalletActionOperations`,
`WalletOutputOperations`, `WalletCertificateOperations` and their siblings, plus BEEF, SPV proof
verification, BRC-42/43 derivation, certificates and the BRC-103 protocol types.

It carries no **implementation**. Its own `WalletInterface` documentation says conformance "does
not imply persistence, transport, permission prompting, or successful behavior". There is no
storage of any kind.

This library is that implementation. The split mirrors TypeScript exactly:

| TypeScript | Swift |
|---|---|
| `@bsv/sdk` — primitives and interfaces | `swift-sdk` |
| `@bsv/wallet-toolbox` — storage, actions, services | `swift-wallet-toolbox` |

We do not define `WalletInterface`. We conform to the one that exists.

## 2. Modules

Go enforces its internal boundaries with `pkg/X/internal/`, which the compiler checks. Swift has no
path-based equivalent, so a separate target is the only way to make a boundary real. Each module
below is a boundary we intend to keep.

| Module | Responsibility |
|---|---|
| `ToolboxCore` | Shared vocabulary: the wire error taxonomy, decode limits |
| `ToolboxAuth` | BRC-103 mutual authentication over HTTP |
| `ToolboxStorage` | The storage contract and its record types — no implementation |
| `ToolboxStorageClient` | Remote storage over JSON-RPC |
| `ToolboxServices` | Broadcast, output status, block headers, exchange rate |
| `ToolboxActions` | Building, funding and signing transactions; BRC-29 |
| `ToolboxWallet` | The concrete BRC-100 wallet |
| `ToolboxMonitor` | Scheduled background work |
| `WalletToolbox` | Umbrella, re-exporting all of the above |

## 3. Conventions

Inherited from `swift-sdk` without exception, because a consumer imports both and a library that
disagreed with its own foundation would be worse than one with mediocre conventions applied evenly.

- **Swift 6 language mode**, strict concurrency, from the first commit.
- **`[UInt8]` at API boundaries**, not `Data`. `Data` appears only where a system framework demands
  it.
- **Typed error enums per concern.** No `LocalizedError` — the SDK has none across roughly sixty
  error enums, and message text belongs to the application that shows it.
- **Value types.** Structs and enums; a class only where reference identity is genuinely required.
- **Parsing throws, never returns `nil`.** No failable initialisers.
- **Explicit limits on every decoder.** The SDK has no unbounded decode path, and this library
  parses untrusted server responses, so it will not introduce the first one.
- **Secret-bearing types redact `description`, `debugDescription` and `customMirror`,** so
  interpolation and reflection cannot leak a key.
- **`Sendable` declared explicitly,** not inherited by synthesis.

Two places where this library must differ from `swift-sdk`, both stated so they are not mistaken
for drift:

1. **It has state.** The SDK is pure value types with no actors. Storage sessions, in-flight
   actions and scheduled tasks are mutable and shared, so actors will appear here. They are the
   exception, justified per use, not the default.
2. **It performs I/O.** Every storage and service call is `async throws` because it crosses a
   network.

## 4. Scope of v1

The Go port is the precedent, and it is more aggressive than expected: it ships with eight BRC-100
methods as `panic("implement me")` — the entire certificate and identity surface — while
implementing the storage and action core completely. Our own consumer analysis independently
reached the same cut, with certificates rated as having no Swift consumer today.

### In v1

- BRC-103 authenticated HTTP transport
- Remote storage client over JSON-RPC
- The action lifecycle: `createAction`, `signAction`, `internalizeAction`, `abortAction`,
  `listActions`, `listOutputs`, `relinquishOutput`
- Change generation and input selection
- BRC-29 deposit-address derivation and script template
- Broadcast and output status, with ordered provider fallback
- The crypto operations the SDK's offline wallet kernel already answers

### Deferred, with reasons

| Deferred | Why |
|---|---|
| Certificates, key linkage, identity discovery | No consumer; Go ships without them |
| Privileged key manager | No Go equivalent exists at all |
| On-device storage engine | See §5 — no implementation has one on mobile |
| Monitor beyond rebroadcast and proof collection | The remaining tasks serve a server deployment |
| Multi-store sync and backup topology | One store cannot disagree with itself |
| UMP and Argon2 key derivation | Key custody is the platform Keychain |

Deferred methods **throw** `.notImplemented`. They do not crash. Go's `panic` is a language habit,
not a design decision worth copying into a wallet on somebody's phone.

## 5. Why storage is remote-first

This is the decision most likely to be questioned, so the evidence is recorded in full.

The TypeScript toolbox builds three targets from one source tree. `index.mobile.ts` exports
`StorageMobile`, the remote JSON-RPC client, and **does not export `StorageIdb`** — the mobile build
has no on-device storage engine at all.

Yours Wallet, a shipping wallet and our closest functional model, defaults every new account to a
single remote: `activeRemote` and the sole entry of `remotes[]` are both `https://wallet.1sat.app`.
Its local IndexedDB holds permission grants and task state, never wallet records.

So remote-first is not a shortcut. It is the only shape with precedent on this platform, and it
removes the largest and least portable subsystem — a SQL engine with a schema and migrations —
from the critical path. An on-device engine can be added later against the same
`WalletStorageProvider` contract; it would be new work in any case, since no implementation has one
to port.

## 6. Security requirements

**Storage cannot be trusted with output values.** Before signing, the signer re-verifies that
storage echoed back the caller's exact requested outputs. Without this check a storage operator can
alter an output and have the wallet sign it — advisory GHSA-36f9-7rg5-cpf8 in the TypeScript
toolbox. Remote-first storage makes this mandatory rather than defensive, and it lives inside
`ToolboxActions` so no caller can skip it.

**The wire error taxonomy is decoded, not flattened.** Fourteen error names cross the JSON-RPC
boundary. A client keeping only the message turns "insufficient funds" into text no application can
branch on.

**Every decoder is bounded.** Server responses are untrusted input.

## 7. Correctness strategy

`swift-sdk` proves itself against a pinned Go oracle: a process speaking a `bsv-conformance/1` JSON
protocol, checked out at a commit recorded in `go-sdk.lock.json`, exercising roughly twenty-five
operations. A round trip through our own encoder would prove only that we agree with ourselves.

This library adopts the same pattern against `go-wallet-toolbox`, extended to the operations that
matter here: change generation, transaction assembly, BRC-29 derivation, and the JSON-RPC envelope.

`bsv-blockchain/universal-test-vectors` was considered and not adopted as the primary mechanism. It
is built to be cross-language, but a search of the TypeScript checkouts found no reference to it —
it is consumed by Go alone today. It remains useful as a supplementary fixture source.

## 8. Bootstrap order

`StorageClient` authenticates with BRC-103 using a wallet's identity, and the wallet needs storage.
TypeScript resolves this inside a factory function; the cycle is real and Swift's initialisation
rules will not permit papering over it.

Construction is therefore two-phase:

1. Build the offline key operations from the identity key. This needs no storage.
2. Build the authenticated transport from those key operations, then the storage client, then the
   full wallet around both.

The reference implementation also treats the wallet as usable before synchronisation finishes:
address and message sync are started and not awaited. A Swift consumer should not block its
interface on sync either.
