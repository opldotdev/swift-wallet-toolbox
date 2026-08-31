# Portable wallet data

`ToolboxPortable` implements the storage-data boundary defined by BRC-38 and the binary envelope
boundary defined by BRC-39.

- `BRC38WalletData.parse` rejects duplicate/unknown document keys, validates the current Wallet
  Toolbox row shapes and portable encodings, and checks table uniqueness and relationship closure.
  Unknown fields inside a known row are preserved so additive storage-schema fields are not lost.
  Schema integers are limited to the interoperable JavaScript safe-integer range used by the
  TypeScript Wallet Toolbox. Byte, row, total-value, object-member, and array-element limits are
  checked by the lexical parser before it builds the corresponding untrusted structures.
- `BRC38WalletData.canonicalJSON` applies RFC 8785 JCS and the table ordering required by BRC-38.
  Its portable object representation identifies and sorts names by raw UTF-16, so distinct
  normalization-equivalent property names remain distinct as JCS requires.
- `BRC39Envelope.parse` validates and splits the version 1 `WDAT` envelope before any password or
  memory-hard work. It returns zero-copy slices of the input. The default untrusted Argon2id ceiling
  is 16 iterations, 256 MiB, and parallelism 4; a caller may opt into larger explicit bounds on a
  platform that can safely afford them. Headers must also satisfy RFC 9106's minimum of 8 KiB of
  Argon2 memory per lane.

This is not a custody backup format. BRC-38 explicitly excludes root keys, profiles, mnemonics,
and encrypted runtime snapshots. Do not label a file containing those values as BRC-38 or BRC-39.

## Deliberate boundary

The current Swift toolbox has a narrow remote-storage contract, not the complete local Wallet
Toolbox table schema required for lossless export or import. Storage integration therefore waits
for the local provider and its full row types. At that point it must expose two explicit policies:

- restore into empty storage, preserving the exported `user.activeStorage` and sync-state values;
- merge into populated storage, preserving the destination's active storage and remapping imported
  IDs and sync maps to the destination provider.

Those are the existing TypeScript reference semantics. A product that wants a safer fresh-device
activation policy should add it explicitly rather than silently changing either mode.

The pinned Swift SDK provides AES-256-GCM but no Argon2id implementation. BRC-39 encryption and
decryption must not be exposed until a reviewed, iOS-compatible Argon2id dependency is selected.
The next bounded change is to add that dependency, cross-language vectors, password NFC handling,
and an authenticated round trip from canonical BRC-38 bytes.
