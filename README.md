<div align="center">

# BSV Blockchain | Swift Wallet Toolbox

**Storage, actions and services for a BRC-100 wallet in Swift.**

<a href="https://www.swift.org/"><img src="https://img.shields.io/badge/Swift-6.1%2B-F05138?style=flat-square&logo=swift&logoColor=white" alt="Swift 6.1 or later"></a>
<a href="Package.swift"><img src="https://img.shields.io/badge/platforms-Apple%20%7C%20Linux-lightgrey?style=flat-square" alt="Apple and Linux platforms"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT License"></a>

</div>

## What this is

[`swift-sdk`](https://github.com/opldotdev/swift-sdk) carries the BRC-100 **contract** — the wallet
interface, BEEF, SPV proof verification, BRC-42/43 key derivation, certificates. It carries no
implementation, and no storage of any kind.

This library is that implementation. The split mirrors the TypeScript one exactly:

| TypeScript | Swift |
|---|---|
| `@bsv/sdk` — primitives and interfaces | `swift-sdk` |
| `@bsv/wallet-toolbox` — storage, actions, services | `swift-wallet-toolbox` |

It follows the TypeScript toolbox in [`bsv-blockchain/ts-stack`](https://github.com/bsv-blockchain/ts-stack)
and the Go toolbox in [`bsv-blockchain/go-wallet-toolbox`](https://github.com/bsv-blockchain/go-wallet-toolbox).

## Status

The send path works end to end against a real BRC-103 storage server: authenticated handshake,
JSON-RPC transport, `makeAvailable` / `listOutputs` / `createAction` / `processAction`, BRC-29 key
derivation (cross-checked against the Go toolbox's vectors), transaction assembly, signing, and
Atomic BEEF packaging. An adversarial review of 2026-08-11 raised 20 findings; all are resolved —
see [`docs/reviews/2026-08-11-adversarial.md`](docs/reviews/2026-08-11-adversarial.md).

`RemoteWallet` composes the whole wallet: `restore(fromPhrase:)`, `connect`, `balance`,
`history`, `receiveAddress`, `pay`, `abort`, and the `createAction` / `signAction` lifecycle. Recovery-phrase restore matches Yours Wallet; receive-address
derivation matches the live @1sat deposit convention's paths, checked against vectors from the reference libraries.

Not yet built: the `Services` provider chains and the monitor tasks. See
[`docs/DESIGN.md`](docs/DESIGN.md) §4.

See [`docs/DESIGN.md`](docs/DESIGN.md) for what v1 covers, what it defers, and why.

### Transaction approval integration

Permission-aware hosts call `createAction` with `signAndProcess: false`, obtain authoritative
amounts with `reviewAction(reference:)`, and call `signAction` only after consent. Prepared
actions retain no keys and signing references are consumed once. Caller inputs, source amounts,
recipient outputs, wallet change, fees, and unlocking scripts are checked before finalization.
`abortAction` invalidates the pending reference. Pending actions are local to the wallet instance;
they are not restored across restart. Hosts must additionally bind consent to their authenticated
originator, account, and session (as the desktop app does).

`noSend` is preserved. Batch-only actions and nonempty `sendWith` are explicitly rejected by
this lifecycle until an originator-owned batch ledger is implemented; they never trigger an
implicit broadcast. Standing monthly spending grants are not inferred from one-time approval.
Storage finalization sends raw transaction bytes plus the matching txid, as required by both
reference toolboxes; wallet results and PeerPay delivery continue to use Atomic BEEF.

## Modules

| Module | Responsibility |
|---|---|
| `ToolboxCore` | Shared vocabulary: the wire error taxonomy, decode limits |
| `ToolboxAuth` | BRC-103 mutual authentication over HTTP |
| `ToolboxPortable` | BRC-38 canonical wallet data and BRC-39 envelope validation |
| `ToolboxStorage` | The storage contract and its record types |
| `ToolboxStorageClient` | Remote storage over JSON-RPC |
| `ToolboxServices` | Broadcast, output status, block headers, exchange rate |
| `ToolboxBRC29` | BRC-29 payment derivation |
| `ToolboxActions` | Building, funding and signing transactions |
| `ToolboxPermissions` | BRC-116 policy, permission tokens, and veto-only module preflight ([details](docs/PERMISSION-MODULES.md)) |
| `ToolboxWallet` | The concrete BRC-100 wallet |
| `ToolboxMonitor` | Scheduled background work |
| `WalletToolbox` | Umbrella, re-exporting all of the above |

Import the umbrella for everything, or one module for a narrower dependency.

```swift
.package(url: "https://github.com/opldotdev/swift-wallet-toolbox.git", branch: "main")
```

## Two decisions worth knowing before you read the code

**Storage is remote-first.** There is no on-device storage engine, and that is deliberate. The
TypeScript toolbox's mobile build exports none either — it ships the remote JSON-RPC client alone.
An engine can be added later against the same `WalletStorageProvider` contract.

**Storage is not trusted with output values.** Before signing, the signer re-verifies that storage
returned the caller's exact requested outputs. Without that check a storage operator can alter an
output and have the wallet sign it. This is advisory GHSA-36f9-7rg5-cpf8 in the TypeScript toolbox.

## Building

### MessageBox identity-key payments

`ToolboxWallet` includes the HTTP PeerPay sending path from
[`@bsv/message-box-client`](https://github.com/bsv-blockchain/ts-stack/tree/main/packages/messaging/message-box-client).
It reuses SDK cryptography and overlay lookup, authenticated HTTP, and BRC-29 payments.
Applications supply the default server; recipient `ls_messagebox` advertisements take precedence.

```swift
let outbox = MessageBoxOutbox(directory: applicationSupport.appendingPathComponent("MessageBoxOutbox"))
let txid = try await outbox.send(
    wallet: wallet, to: recipientIdentityKey, satoshis: 1_000,
    description: "PeerPay payment", fallbackHost: configuredMessageBoxURL
)
```

Keep one outbox instance per directory. Signed BEEF and the encrypted delivery envelope are
saved before broadcast. On a pending-delivery error, use `outbox.retry(wallet:)`, not another
`send`: retry reuses the saved transaction and message ID, including after an app restart.
The recipient must understand standard PeerPay payment tokens. Server acceptance is not proof
that the recipient has internalized the payment.

This slice supports zero-fee delivery. Blocked recipients or quotes requiring an additional
delivery payment are refused before transaction creation. It does not register receiving hosts,
poll inboxes, or silently pay delivery fees. Configured endpoints must use HTTPS.

### Tests

```bash
swift build
swift test
```

## License

[MIT](LICENSE)
