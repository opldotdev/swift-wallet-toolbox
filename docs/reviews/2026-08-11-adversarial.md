# Adversarial review — 2026-08-11

## Remediation status

All 20 confirmed findings are resolved as of commit `ff1075b`. Fixes landed across these commits,
each with tests:

| Findings | Commit | What changed |
|---|---|---|
| #1, #6 (+ change re-derivation) | `7c03f70` | Fee ceiling; two-part output check; change rebuilt from own keys |
| #3, #4, #7, #15 | `284a02a` | Caller options and inputs serialized; funded fields required |
| #5, #16 | `819e0d7` | Signed Atomic BEEF carried into finalization; inputBeef as byte array |
| #2, #11, #12, #13 | `cedb709` | HTTPS default + peer pinning; body cap; session recovery; path fix |
| #8, #9, #14, #17, #18, #19, #20 | `284a02a`, `ff1075b` | Per-input sender; trap-free conversions; strict collections; jsonrpc/id; in-flight settings |

The findings as reported by the reviewer follow, unedited.

---


Reviewer: `gpt-5.6-sol` via codex, high reasoning effort, read-only.
Protocol: Hunter → Skeptic → Referee, each reading the code independently.
Target: commit `725aa5d`, against pinned `swift-sdk` `ebdac0d`.

22 candidates raised, 4 dismissed by the Skeptic, 20 confirmed by the Referee.
Findings are reproduced verbatim below; remediation is tracked in the repository's
commit history rather than edited into this file.

# Final report

Adversarial review completed against `HEAD 725aa5d` and pinned `swift-sdk` revision `ebdac0d`. I confirmed 20 defects: 4 critical, 12 medium, and 4 low.

## Critical

1. **Unbounded transaction fees can destroy wallet funds** — [ActionSigner.swift:32](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxActions/ActionSigner.swift:32)

   Trigger: hostile storage returns the exact requested 1,000-satoshi output, a genuine 100,000,000-satoshi wallet input, and no change. The signer authorizes a valid 99,999,000-satoshi fee. `fee(for:)` is never called and has no maximum anyway.

   Fix: enforce a caller-approved absolute fee and size-based fee-rate ceiling before any input is signed.

2. **Plain-HTTP storage can be impersonated despite BRC-103 authentication** — [AuthenticatedSession.swift:32](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxAuth/AuthenticatedSession.swift:32), [RemoteStorage.swift:28](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/RemoteStorage.swift:28)

   Trigger: configure an `http://` endpoint; an active intermediary completes the handshake with its own valid key because `expectedPeer` defaults to `nil`.

   Consequence: the attacker becomes the authenticated storage peer and can read RPC traffic and return hostile funding data. The default HTTPS endpoint is not vulnerable to this exact sequence.

   Fix: require HTTPS by default, expose mandatory peer pinning, and bind `storageIdentityKey` to the authenticated peer.

3. **Caller action options are discarded, including `noSend`** — [StorageClient+Actions.swift:47](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient+Actions.swift:47)

   Trigger: request `noSend`, delayed broadcast, `sendWith`, known transaction IDs, or output randomization.

   Consequence: storage receives a materially different action; notably, an explicit no-broadcast guarantee becomes false. Unintended broadcasting is latent until the currently broken finalization path is repaired.

   Fix: serialize all caller options faithfully, overriding only `signAndProcess` where local signing requires it.

4. **Sequence, lock-time, and version semantics are not preserved** — [ActionAssembler.swift:45](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxActions/ActionAssembler.swift:45)

   Trigger: use a future `lockTime` with a non-final caller input sequence, or let hostile storage alter the returned header.

   Consequence: every input gets `0xffffffff`, disabling `nLockTime` and potentially making the transaction spendable immediately.

   Fix: retain input provenance and caller sequences, and construct or verify version and lock time against the original request.

## Medium

5. **Finalization omits the signed transaction** — [SignedAction.swift:52](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxActions/SignedAction.swift:52)

   `processRequest()` always sets `rawTX: nil`. Storage cannot commit or broadcast the new transaction, potentially leaving its inputs reserved. Include the serialized signed transaction, txid, and processing flags.

6. **The output-security check rejects every ordinary change output** — [OutputVerification.swift:17](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxActions/OutputVerification.swift:17)

   A normal response contains requested outputs followed by optional commission and change. Exact count equality rejects it. Verify the requested prefix, permit one bounded commission, and independently rederive all change scripts.

7. **Caller-supplied inputs are silently removed from the RPC request** — [StorageClient+Actions.swift:31](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient+Actions.swift:31)

   `"inputs"` is always encoded as `[]`. Explicit ordinal/token UTXOs, outpoints, sequences, and unlocking lengths are lost. Encode every input while stripping only the actual unlocking script where necessary.

8. **One sender key is incorrectly applied to every BRC-29 input** — [ActionSigner.swift:25](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxActions/ActionSigner.swift:25)

   Mixed inputs received from different senders derive different spending keys, so at least one fails to sign. Store and validate `senderIdentityKey` per input.

9. **Hostile JSON numbers can trap during `Double → Int` conversion** — [JSONValue.swift:41](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxCore/JSONValue.swift:41)

   An integral value such as `1e308` passes the rounded check but traps in `Int(value)`. Use `Int(exactly:)` and reject unrepresentable numbers.

10. **Oversized wire integers trap during `UInt32` narrowing** — [StorageClient+Actions.swift:91](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient+Actions.swift:91)

    `sourceVout`, unlocking length, version, or lock time equal to `4294967296` crashes the process. Use `UInt32(exactly:)` and return `unreadableResponse`.

11. **HTTP bodies are unbounded before decoder limits run** — [HTTPTransport.swift:61](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxAuth/HTTPTransport.swift:61)

    `URLSession.data(for:)` buffers the complete response and then copies it into `[UInt8]`; the BRC-104 one-megabyte limit applies afterward. Stream responses and cancel once a transport-level limit is exceeded.

12. **Expired authentication sessions are cached forever** — [AuthenticatedSession.swift:50](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxAuth/AuthenticatedSession.swift:50)

    After the pinned SDK evicts a session at its message limit, the wrapper repeatedly reuses the stale ID. Clear expired sessions and perform one controlled re-handshake/retry.

13. **Storage endpoints with paths are duplicated** — [StorageClient.swift:58](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient.swift:58), [AuthenticatedSession.swift:189](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxAuth/AuthenticatedSession.swift:189)

    `https://host/api` becomes `https://host/api/api`. Separate the base path from the RPC route or replace absolute paths rather than appending them.

14. **Empty-output actions produce invalid transactions** — [ActionAssembler.swift:61](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxActions/ActionAssembler.swift:61)

    `[]` outputs produces a zero-output transaction rejected by transaction validation. Add the reference zero-satoshi `OP_FALSE OP_RETURN` output or reject before reserving inputs.

15. **Missing funded-action fields are silently fabricated** — [StorageClient+Actions.swift:84](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient+Actions.swift:84)

    Missing inputs, outputs, version, and lock time become `[]`, the caller’s outputs, `1`, and `0`. Substituting caller outputs makes the security comparison compare the request with itself. Require every schema-mandated field.

16. **`inputBeef` uses the wrong wire representation and cannot drive packaging** — [StorageClient+Actions.swift:138](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient+Actions.swift:138), [SignedAction.swift:36](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxActions/SignedAction.swift:36)

    Honest servers return a JSON byte array, while Swift accepts only a hex string and silently produces `nil`. The required derivation prefix is also optional, and packaging requires manually supplied source transactions rather than consuming the funded BEEF.

    Fix: decode bounded byte arrays, require the prefix, parse and merge the funded proof graph, and expose an end-to-end packaging API.

## Low

17. **Malformed tags and labels are silently altered** — [StorageClient+Outputs.swift:54](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient+Outputs.swift:54)

    `compactMap` turns `["valid", 7]` into `["valid"]`. Reject the entire malformed collection.

18. **JSON-RPC version and response ID are not validated** — [StorageClient.swift:47](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient.swift:47)

    BRC-104 prevents cross-request network swapping, so this is not an authentication vulnerability, but authenticated malformed envelopes are still accepted. Require version `2.0` and the expected ID.

19. **Concurrent initial availability checks duplicate and race** — [StorageClient.swift:95](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxStorageClient/StorageClient.swift:95)

    Actor reentrancy allows multiple first calls to observe no cached settings and issue separate requests. Cache an in-flight settings task.

20. **The public fee helper traps on extreme values** — [ActionAssembler.swift:92](/Users/satchmo/code/swift-wallet-toolbox/Sources/ToolboxActions/ActionAssembler.swift:92)

    `Int64` sums and `UInt64 → Int64` conversion are unchecked. Use reporting-overflow arithmetic or a wider accumulator.

## Dismissed candidates

The absent `WalletStorageProvider` and `WalletInterface` conformances are genuine release blockers, but the README explicitly identifies these types as unfinished placeholders. I classified them as disclosed scope gaps rather than defects in implemented behavior.

I found no defect in the BRC-29 derivation mathematics itself: payer/payee derivations agree with the independent Go vectors. Authenticated responses are also cryptographically verified and request-correlated before their contents are returned.

No files were edited. The test suite could not execute because the managed read-only environment prevented SwiftPM/Xcode from creating compiler cache files; findings were statically verified against the exact pinned SDK and local TypeScript/Go references.
