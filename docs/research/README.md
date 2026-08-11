# Research

Surveys of the three implementations this library is built from, made before any code was written.
`../DESIGN.md` states the decisions; these are the evidence behind them.

| Report | Covers |
|---|---|
| `ts-wallet-toolbox-map.md` | `bsv-blockchain/ts-stack` — the authoritative implementation |
| `go-wallet-toolbox-patterns.md` | `bsv-blockchain/go-wallet-toolbox` — the only existing second-language port |
| `swift-sdk-inventory.md` | `opldotdev/swift-sdk` — what already exists below this library |

Each claim carries a `file:line` reference into the repository it describes, so a reader can check
it rather than take it. Where a report is inferring rather than reading, it says so.

**These describe those repositories as they stood on 2026-08-11.** They are a snapshot taken to
make a design decision, not a maintained mirror. Where this library later disagrees with a report,
the library is right and the report is stale — check the source before treating anything here as
current.

Three findings did most of the work:

- The TypeScript mobile build exports no on-device storage engine, which is why storage here is
  remote-first rather than that being a shortcut.
- The Go port ships with the whole certificate and identity surface unimplemented, which sets the
  precedent for what v1 can defer.
- `swift-sdk` already carries the BRC-100 ABI, so this library conforms to an interface rather than
  defining one.

A fourth report, on what the consuming applications actually call, stays in the wallet application's
own repository, since it describes that application's gaps rather than this library.
