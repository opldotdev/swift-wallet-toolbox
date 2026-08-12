# Adversarial review: swift-wallet-toolbox

You are reviewing a Bitcoin SV wallet library. Real money depends on it. Your job is to find
defects, not to praise it. Assume the author was confident and wrong.

## What it is

`swift-wallet-toolbox` implements storage, actions and services for a BRC-100 wallet, on top of
`swift-sdk` (a sibling package at ../swift-sdk providing keys, crypto, transactions, BRC-42
derivation, and the BRC-100 ABI). Storage is a REMOTE server reached over JSON-RPC; the wallet
holds the keys and the server does not.

Read `docs/DESIGN.md` first for the intended architecture and threat model.

## Priorities, highest first

1. **Money loss.** Anything that could produce an unspendable output, sign the wrong thing, spend
   more than intended, or lose funds. Look hard at:
   - `Sources/ToolboxActions/OutputVerification.swift` — the control that stops a malicious storage
     operator redirecting funds (advisory GHSA-36f9-7rg5-cpf8). Can it be bypassed, or is there a
     path to signing that does not go through it?
   - `Sources/ToolboxActions/ActionSigner.swift` and `ActionAssembler.swift` — is the transaction
     assembled faithfully? Are fees, amounts, sequence numbers, lockTime handled correctly? Is
     there any way a partly-signed or wrongly-signed transaction escapes?
   - `Sources/ToolboxBRC29/` — key derivation. A wrong key means money is gone forever.

2. **Authentication and transport.** `Sources/ToolboxAuth/` implements BRC-103 mutual auth over
   HTTP. Can a response be accepted that was not authenticated? Is the session handling
   concurrency-safe? Any replay, confusion, or downgrade issue?

3. **Parsing untrusted input.** `Sources/ToolboxStorageClient/` and `Sources/ToolboxCore/` parse
   responses from a server that may be hostile. Look for unbounded work, integer overflow or
   truncation (note the Int64/UInt64/UInt32 conversions), and fields silently defaulted where
   refusing would be correct.

4. **Swift-specific correctness.** Swift 6 strict concurrency is on. Actor reentrancy, data races,
   `Task` misuse, arithmetic overflow traps, force-unwraps, `try!`.

## Rules

- Do NOT edit any files. This is review only.
- Be specific: cite `file:line`, state the concrete input or sequence that triggers the problem,
  and say what the consequence is.
- Rank findings by severity. Say plainly if something is theoretical versus exploitable.
- If a design decision looks wrong, argue it — do not assume the author had a reason.
- If you find nothing serious in an area, say so briefly rather than padding.

End with a FINAL REPORT: the findings ranked by severity, each with file:line, trigger,
consequence, and suggested fix. If you changed no files, say so explicitly.
