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
`history`, `receiveAddress`, `pay`, `abort`. Recovery-phrase restore and receive-address
derivation match Yours Wallet's paths, checked against vectors from the reference libraries.

Not yet built: the `Services` provider chains and the monitor tasks. See
[`docs/DESIGN.md`](docs/DESIGN.md) §4.

See [`docs/DESIGN.md`](docs/DESIGN.md) for what v1 covers, what it defers, and why.

## Modules

| Module | Responsibility |
|---|---|
| `ToolboxCore` | Shared vocabulary: the wire error taxonomy, decode limits |
| `ToolboxAuth` | BRC-103 mutual authentication over HTTP |
| `ToolboxStorage` | The storage contract and its record types |
| `ToolboxStorageClient` | Remote storage over JSON-RPC |
| `ToolboxServices` | Broadcast, output status, block headers, exchange rate |
| `ToolboxBRC29` | BRC-29 payment derivation |
| `ToolboxActions` | Building, funding and signing transactions |
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

```bash
swift build
swift test
```

## License

[MIT](LICENSE)
