# Reference implementations

This package ports `@bsv/wallet-toolbox` and `go-wallet-toolbox`. It is a
generic BRC-100 wallet. It does not own 1Sat protocol.

| Kind | Path |
|---|---|
| Specifications | `~/code/BRCs` |
| TypeScript | `~/code/ts-stack/packages/wallet/wallet-toolbox` (`@bsv/wallet-toolbox`) |
| Go | `~/code/go-wallet-toolbox` |

Read those checkouts before you change behaviour. Match the live reference.
If TypeScript and Go disagree, cite `~/code/BRCs` or a live vector and keep
one behaviour. 1Sat-only conventions belong in `swift-1sat-sdk`.
