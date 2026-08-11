# swift-sdk inventory: boundary map for swift-wallet-toolbox

Repo read: `~/code/swift-sdk`, local working tree, no uncommitted state inspected beyond what
`git status` would show (not checked). All line numbers below are from the tree as read.

## 1. Package and module layout

`Package.swift:1` declares `swift-tools-version: 6.1`. Platforms
(`Package.swift:14-20`): macOS 13, iOS 16, tvOS 16, watchOS 9, visionOS 1, plus Linux via the
Swift 6.1 toolchain (asserted in README, not encoded in `Package.swift` platforms since SwiftPM
has no Linux platform gate). `swiftLanguageModes: [.v6]` is set at the bottom of the manifest
(`Package.swift:216`) — the whole package builds under Swift 6 strict concurrency, not an
opt-in subset.

Products (`Package.swift:22-27`):
- `BSV` — umbrella library re-exporting the "modern" module set.
- `BSVCompat` — separate opt-in product, deliberately **not** pulled in by `BSV`.
- One library product per module in `modernPublicModules` (16 modules, listed below), each
  independently importable.

Dependencies (`Package.swift:29-42`): `swift-crypto` 4.5.1 (exact), `swift-secp256k1` 0.23.2
(exact, product `P256K`), `BigInt` 5.7.0 (exact, attaswift). All pinned with `exact:`, not
range-based — a deliberate no-drift policy.

Targets, in dependency order (`Package.swift:44-160`):

| Target | Depends on | Purpose |
|---|---|---|
| `BSVCore` | (none) | Bytes, fixed-length hash types, Base58/Base64/Hex, CompactSize, binary cursor/writer. |
| `BSVBigNum` | `BSVCore`, `BigInt` | Bounded big-integer arithmetic with an explicit operation budget. |
| `BSVCrypto` | `BSVCore`, `BSVBigNum`, `Crypto`, `CryptoExtras` | Hashing, AES, PBKDF2, HMAC-DRBG. |
| `BSVKeys` | `BSVCore`, `BSVBigNum`, `BSVCrypto`, `P256K` | secp256k1 keys, signatures, ECDH, BRC-42, WIF, addresses, BRC-140. |
| `BSVMessage` | `BSVCore`, `BSVCrypto`, `BSVKeys` | BRC-77/78 portable messages. |
| `BSVCompat` | `BSVCore`, `BSVCrypto`, `BSVKeys` | BSM, ECIES (Electrum/Bitcore), BIP-32, BIP-39 — legacy formats only. |
| `BSVScript` | `BSVCore`, `BSVBigNum`, `BSVCrypto`, `BSVKeys` | Script value type, opcodes, ASM, BIP-276, PushDrop/Inscription arg templates. |
| `BSVKVStore` | `BSVKeys`, `BSVScript` | Bounded Go-compatible key-value token codec. |
| `BSVStorage` | `BSVCore`, `BSVCrypto`, `BSVKeys` | UHRP identifiers and a transport-neutral content-provider boundary. |
| `BSVTransaction` | `BSVCore`, `BSVCrypto`, `BSVKeys`, `BSVScript` | Transaction/Input/Output, fees, P2PKH signing, sighash, BUMP/MerklePath, BEEF/AtomicBEEF, wire format, JSON. |
| `BSVInterpreter` | `BSVCore`, `BSVBigNum`, `BSVCrypto`, `BSVKeys`, `BSVScript`, `BSVTransaction` | Full Script VM with explicit limits. |
| `BSVSPV` | `BSVCore`, `BSVCrypto`, `BSVTransaction`, `BSVInterpreter` | 80-byte block headers, BRC-67 SPV proof verification. |
| `BSVOverlay` | `BSVCore`, `BSVCrypto`, `BSVKeys`, `BSVScript`, `BSVTransaction` | SHIP/SLAP models, admin tokens, lookup resolution, topic broadcast policy. |
| `BSVNetwork` | `BSVCore`, `BSVScript`, `BSVStorage`, `BSVTransaction`, `BSVSPV`, `BSVOverlay` | ARC client, WhatsOnChain broadcaster/tracker, Block Headers Service client, overlay HTTP, UHRP downloader. |
| `BSVRegistry` | `BSVCore`, `BSVKeys`, `BSVOverlay`, `BSVScript`, `BSVTransaction`, `BSVWallet` | Registry definitions, PushDrop codec, transport-neutral lookup/publish boundary. |
| `BSVWallet` | `BSVCore`, `BSVCrypto`, `BSVKeys`, `BSVScript`, `BSVTransaction` | Offline BRC-100 `WalletInterface` ABI, wallet crypto (`ProtoWallet`, key deriver), BRC-52 certificates, wire codecs. |
| `BSVAuth` | `BSVCore`, `BSVCrypto`, `BSVKeys`, `BSVTransaction`, `BSVWallet` | BRC-103 mutual auth, certificate exchange, BRC-104 HTTP payload framing. |
| `BSVIdentity` | `BSVCore`, `BSVKeys`, `BSVScript`, `BSVTransaction`, `BSVWallet` | Bounded identity resolution and disclosure creation, transport-neutral. |

There is also `Sources/BSVServices/` — an **empty directory**, present on disk but not declared
as a target in `Package.swift` and not referenced by any product. Treat it as scaffolding, not
a shipped module.

Every module above has a matching `<Module>Tests` target, plus a cross-cutting
`BSVConformanceTests` target that depends on essentially everything and carries a
`Fixtures` resource bundle (`Package.swift:203-211`).

## 2. Public API inventory

### BSVKeys
- `PrivateKey` (`Sources/BSVKeys/Secp256k1/PrivateKey.swift:7`) — struct, holds a validated
  32-byte scalar, exposes `.bytes`, `.publicKey`, equality/hash by derived public key, redacted
  `description`/`debugDescription`/`customMirror`.
- `PublicKey` (`Sources/BSVKeys/Secp256k1/PublicKey.swift:10`) — struct, parses compressed
  (33B), uncompressed (65B) and Go-compatible hybrid (0x06/0x07) SEC1 encodings; exposes
  `.compressedBytes`, `.uncompressedBytes`, `.serialized(as:)`.
- `PublicKeyFormat` enum: `.compressed` / `.uncompressed`.
- `Address` (`Sources/BSVKeys/Formats/Address.swift:5`) — P2PKH only, Base58Check, mainnet/testnet.
- `WIF` (`Sources/BSVKeys/Formats/WIF.swift:2`) — parses/encodes WIF, redacted description.
- `BitcoinNetwork` (`Sources/BSVKeys/Formats/BitcoinNetwork.swift`) — `.mainnet` / `.testnet`.
- BRC-42/43 derivation: `PrivateKey.derivedChild(with:invoiceNumber:)` and
  `PublicKey.derivedChild(with:invoiceNumber:)`
  (`Sources/BSVKeys/Derivation/BRC42.swift:17,40`) plus `BRC42DerivationError`.
- `Secp256k1KeyError`, `Secp256k1OperationError` — typed parse/operation error enums.
- `ECDSASignature`, `RecoverableSignature` (`Sources/BSVKeys/Signatures/`).
- `KeyOperations` (`Sources/BSVKeys/Secp256k1/KeyOperations.swift`) — tweak-add, ECDH,
  `sharedSecret(with:)` used internally by BRC-42.
- `SharedSecretProof` — BRC-94 shared-secret proofs.
- `KeySharing` (`Sources/BSVKeys/Backup/KeySharing.swift`) — BRC-140 key shares for offline
  backup/reconstruction.
- `Base58Check` (`Sources/BSVKeys/Encoding/Base58Check.swift`) — bounded decode with a
  `maximumPayloadByteCount` parameter (see `WIF.swift:27`, `Address.swift:32`).
- `KeyFormatError` — shared error enum for WIF/Address parse failures.

### BSVCrypto
- `BSVHashing` (`Sources/BSVCrypto/Hashing/BSVHashing.swift`) — SHA-256, SHA-512, HMAC,
  `hash160`, double-SHA256, wraps `swift-crypto`.
- `RIPEMD160` — standalone implementation (not in swift-crypto).
- `AESCBC`, `AESGCM` (`Sources/BSVCrypto/Symmetric/`), `AESPrimitiveError`.
- `SymmetricKey` — SDK-owned wrapper, not `CryptoKit.SymmetricKey`.
- `PBKDF2` (`Sources/BSVCrypto/KDF/PBKDF2.swift`).
- `HMACDRBG`, `SecureRandomSource` (`Sources/BSVCrypto/Random/`) — deterministic and
  system-random generation.
- ECDH itself lives in `BSVKeys/Secp256k1/KeyOperations.swift`, not here — hashing/symmetric
  primitives are `BSVCrypto`, key-bearing operations are `BSVKeys`.

### BSVMessage
- `SignedMessage` — BRC-77 signing/verification.
- `EncryptedMessage` — BRC-78 encryption/decryption.
- `PortableMessageError`, `PortableMessageLimits` (explicit bounded-decode limits, matching the
  repo-wide pattern).
- BSM (Bitcoin Signed Message) is explicitly **not** here — it is in `BSVCompat` as a legacy
  format, with `SignedMessage` (BRC-77) called out in the README as its replacement.

### BSVTransaction (primitives)
- `Transaction`, `TransactionInput`, `TransactionOutput`
  (`Sources/BSVTransaction/Transaction.swift`, `TransactionInput.swift`, `TransactionOutput.swift`).
- `TransactionConstruction` — builder-style helpers.
- `Outpoint`, `UnspentTransactionOutput`.
- `P2PKHSigning` (`Sources/BSVTransaction/P2PKHSigning.swift`) — P2PKH-specific signing helper.
  There is **no** general `UnlockingScriptTemplate` protocol or template registry (confirmed:
  no match for `UnlockingScriptTemplate` anywhere in `Sources/`); P2PKH is hand-written, not an
  instance of a pluggable template system.
- `LegacySignatureHash`, `ForkIDSignatureHash` — both pre- and post-fork sighash algorithms.
- `TransactionFeeModel` protocol + `SatoshisPerKilobyteFeeModel`
  (`Sources/BSVTransaction/TransactionFee.swift:2,8`) — the only fee model shipped.
- `TransactionError`, `TransactionLimits` — typed errors and explicit bounded-decode limits.
- `TransactionWireFormat` (`Sources/BSVTransaction/Serialization/`) — raw tx (de)serialization,
  and BRC-30 "Extended Format" parsing per the README.
- `MerklePath`, `MerklePathVerification`, `MerklePathJSON`, `MerklePathError`, `MerklePathLimits`
  (`Sources/BSVTransaction/Merkle/`) — BRC-74 BUMP.
- `BEEF`, `AtomicBEEF`, `BEEFTransaction`, `BEEFGraphOperations`, `BEEFValidation`,
  `BEEFVerification`, `BEEFVersion`, `BEEFError`, `BEEFLimits`
  (`Sources/BSVTransaction/BEEF/`) — BRC-62/95/96. `AtomicBEEF.prefix = 0x0101_0101`
  (`AtomicBEEF.swift:6`), explicit doc comment "BRC-95 envelope" (`AtomicBEEF.swift:3`).
- `Broadcaster` protocol, `BroadcastResult` (`Sources/BSVTransaction/Broadcasting/`) —
  transport-neutral broadcast boundary implemented concretely in `BSVNetwork`.
- `ChainTracker` protocol (`Sources/BSVTransaction/ChainTracking/ChainTracker.swift`) —
  transport-neutral header-lookup boundary, implemented by `WhatsOnChainChainTracker` in
  `BSVNetwork`.
- `TransactionInscriptions` — BRC-307 inscription/specific-ordinal output helpers.
- `TransactionJSON`, `StrictTransactionJSONParser`, `TransactionJSONLimits`,
  `TransactionJSONError` (`Sources/BSVTransaction/JSON/`) — Go-oracle-compatible strict JSON,
  see conventions section on the "strict JSON preflight" pattern.
- `PushDropSigning` (`Sources/BSVTransaction/Templates/PushDrop/`) — signing counterpart to
  `BSVScript`'s `PushDrop` script builder.

### BSVSPV
- `BlockHeader` — 80-byte canonical header parse/hash.
- `SPVProofVerifier`, `SPVValidationError` — BRC-67 SPV verification given an injected chain
  tracker (dependency-injected, not baked to one network service).

### BSVWallet (this is the module the toolbox must not duplicate)
- `WalletInterface` protocol (`Sources/BSVWallet/ABI/WalletInterface.swift:126`) — composed
  from `WalletKeyOperations`, `WalletActionOperations`, `WalletOutputOperations`,
  `WalletCertificateOperations`, `WalletLinkageOperations`, `WalletDiscoveryOperations`,
  `WalletAuthenticationOperations`, `WalletChainInformation`. Doc comment explicitly states
  conformance "does not imply persistence, transport, permission prompting, or successful
  behavior" (`WalletInterface.swift:124-125`) — it is a pure typed-ABI contract, deliberately
  inert.
- Every wallet call has a paired `Wallet<Verb>Request` / `Wallet<Verb>Result` struct
  (e.g. `WalletGetHeightRequest`/`Result`, `WalletCreateActionRequest`/`Result`) — all
  `Equatable, Sendable`, all with explicit `public init`.
- `ProtoWallet`, `WalletKeyDeriver`, `WalletCapabilities`
  (`Sources/BSVWallet/Crypto/`) — the "seven offline BRC-100 cryptographic wallet calls" per
  the README (encrypt/decrypt, HMAC create/verify, sign/verify, derive public key — no
  network/action/output/certificate persistence logic).
- `Certificate` model + `CertificateBinary`, `CertificateJSON`, `CertificateKeyringBinary`,
  `CertificateSignature`, `CertificateValues`, `CertificateCapabilities`
  (`Sources/BSVWallet/Certificates/`) — BRC-52 offline certificate issue/acquire/prove/verify
  value types.
- `WalletWireProcessor`, `WalletWireTransceiver`, `WalletWireTransport`
  (`Sources/BSVWallet/Substrates/`) — a wire substrate abstraction, plus a large `Wire/` codec
  set (`WalletWireActionCodec`, `WalletWireCertificateCodec`, `WalletWireCodec`, primitives and
  type enums) implementing the BRC-100 binary wire protocol end to end.
- `WalletPushDrop` (`Sources/BSVWallet/Templates/PushDrop/`) — wallet-aware PushDrop helper.
- Everything here is **offline/cryptographic only** — no key storage, no UTXO tracking, no
  action persistence, no network calls. It is the ABI + crypto kernel a real wallet
  implementation sits behind, not the wallet itself.

### BSVAuth
- `BRC103` namespace, `AuthCertificateExchange`, `AuthCertificateJSON`, `AuthModels`,
  `StrictAuthJSONPreflight` (`Sources/BSVAuth/BRC103/`) — BRC-103 mutual authentication
  handshake and signed certificate exchange, protocol/value types only (no transport loop).
- `BRC104HTTPFraming`, `BRC104Payload` (`Sources/BSVAuth/BRC104/`) — bounded HTTP request/
  response framing for the authenticated transport, again value-level, no HTTP client wired in.
- `CertificateEngine`, `CertificateModels` (`Sources/BSVAuth/Certificates/`).

### BSVIdentity
- `IdentityClient`, `IdentityModels`, `IdentityParsing`, `IdentityDisclosureJSON` — resolves
  bounded display identities and builds transport-neutral disclosure payloads. No network
  client is bundled (`IdentityClient` is a protocol/coordination type over injected
  dependencies, not an HTTP resolver — confirm exact shape before relying on this if the
  toolbox needs identity resolution; not fully read line-by-line).

### BSVNetwork (the only module that actually talks to the network)
- `ARCClient`, `ARCConfiguration`, `ARCError`, `ARCResponse`, `ARCStatus`
  (`Sources/BSVNetwork/ARC/`) — ARC broadcaster implementation.
- `BlockHeadersServiceClient`, `...Configuration`, `...Models`
  (`Sources/BSVNetwork/BlockHeadersService/`).
- `WhatsOnChainBroadcaster`, `WhatsOnChainChainTracker`
  (`Sources/BSVNetwork/WhatsOnChain/`) — unauthenticated WhatsOnChain integration.
- `URLSessionHTTPTransport`, `HTTPTypes`, `NetworkRequestPolicy`, `ProviderTextSanitizer`
  (`Sources/BSVNetwork/HTTP/`) — the SDK's HTTP client is `URLSession`-based, wrapped behind an
  internal transport abstraction. This is the SDK's **only** HTTP client usage; there is no
  JSON-RPC client anywhere in the tree (no match for "JSON-RPC" or "JSONRPC" in `Sources/`).
- `OverlayHTTP`, `OverlayHTTPCodec`, `StrictOverlayJSONPreflight`
  (`Sources/BSVNetwork/Overlay/`) — overlay-network HTTP facilitator.
- `UHRPDownloader` (`Sources/BSVNetwork/Storage/`) — bounded UHRP content download.
- `NetworkServiceError` — shared error type across these clients.

### BSVOverlay / BSVRegistry / BSVKVStore / BSVStorage
- `BSVOverlay`: `Lookup`, `LookupResolver`, `OverlayAdminToken`, `OverlayModels`, `Topic`,
  `TopicBroadcaster` — SHIP/SLAP value types and lookup/broadcast policy, transport-neutral
  (actual HTTP lives in `BSVNetwork/Overlay`).
- `BSVRegistry`: `RegistryDefinitionCodec`, `RegistryModels` — PushDrop-encoded registry
  records, transport-neutral lookup/publish boundary.
- `BSVKVStore`: `KVStoreModels`, `KVStoreTokenCodec` — one-field Go-compatible KV token.
- `BSVStorage`: `StorageContent`, `UHRPLimits`, `UHRPURL` — UHRP identifier/content value types
  (the actual downloader is in `BSVNetwork`).

### BSVCompat (opt-in legacy formats — separate product, not in `BSV` umbrella)
- `Mnemonic`, `EnglishWordList` (`Sources/BSVCompat/Mnemonic/`) — BIP-39.
- `ExtendedPrivateKey`, `ExtendedPublicKey`, `HDChildNumber`, `HDKeyPath`, `ExtendedKeyError`
  (`Sources/BSVCompat/HD/`) — BIP-32. README example:
  `master.derived(path: "m/44'/236'/0'")`.
- `BitcoinSignedMessage` (`Sources/BSVCompat/BSM/`) — legacy BSM; README explicitly recommends
  BRC-77 `SignedMessage` for new code.
- `BitcoreECIES`, `ElectrumECIES`, `ECIESSupport`, `ECIESError`
  (`Sources/BSVCompat/ECIES/`) — legacy ECIES variants; README recommends BRC-78
  `EncryptedMessage` for new code.

## 3. Conventions in use (read this before designing anything)

**Error handling.** All fallible operations throw typed `enum ... : Error` values, one enum
per concern (`Secp256k1KeyError`, `BigNumError`, `KeyFormatError`, `TransactionError`,
`BEEFError`, `WalletABIError`, `NetworkServiceError`, ~60 error-conforming types total across
`Sources/`). None of them conform to `LocalizedError` — grep for `LocalizedError` in `Sources/`
returns zero matches. There is no top-level umbrella error type; each module owns its own error
surface, and lower-level errors are frequently wrapped rather than propagated raw, e.g. `WIF`
catches `Base58CheckError` and rethrows `KeyFormatError.invalidEncoding(error)`
(`Sources/BSVKeys/Formats/WIF.swift:26-29`), and BRC-42 catches `Secp256k1OperationError`
internally and rethrows its own `BRC42DerivationError` (`Sources/BSVKeys/Derivation/BRC42.swift:26-30`).
A toolbox layered on top should follow the same pattern: catch SDK errors, wrap them in its
own typed errors rather than leaking SDK error cases through its own API, and should not assume
`LocalizedError`/`errorDescription` is available anywhere in the SDK.

**Value vs reference types.** Everything examined is a `struct` or `enum`; no class was found
among the public types read (`PrivateKey`, `PublicKey`, `Address`, `WIF`, `Transaction`-family,
`Certificate`-family, all wallet request/result types). This is a hard convention, not
incidental — it is what makes `Sendable` conformance straightforward everywhere.

**Concurrency.** Strict concurrency is not optional here: `swiftLanguageModes: [.v6]` at
`Package.swift:216` puts the whole package under Swift 6 mode. Every public value type
inspected declares `Sendable` explicitly in its conformance list rather than relying on
implicit synthesis becoming public API by accident (e.g. `PrivateKey.swift:7-12`,
`PublicKey.swift:10`, every `Wallet*Request`/`Wallet*Result` in
`WalletInterface.swift`). Protocols that describe async capability surfaces are declared
`Sendable` themselves (`WalletActionOperations: Sendable`, `WalletInterface.swift:52`, and
similarly for every other operations protocol). No `@MainActor` and no custom `actor` type was
found in `Sources/`. A toolbox built on this SDK should assume it must run cleanly under Swift 6
strict concurrency from day one, not retrofit it later — mixing modes at the boundary would be
the single most disruptive design mistake available here.

**Naming.** Bitcoin domain terms are spelled to match the relevant BRC number, not to match any
other SDK's casing — `derivedChild(with:invoiceNumber:)` for BRC-42/43 rather than
`deriveChild`; `sharedSecret(with:)` for ECDH. Encoded/serialized output uses a small,
consistent vocabulary: `.encoded` for a canonical text encoding (`WIF.encoded`,
`Address.description` doubles as its canonical text via `CustomStringConvertible`),
`.bytes`/`.compressedBytes`/`.uncompressedBytes` for canonical binary forms, `.serialized(as:)`
when a format choice is needed (`PublicKey.serialized(as:)`,
`Sources/BSVKeys/Secp256k1/PublicKey.swift:77`). Parsing initializers are uniformly
`init(_ text: String) throws` for the primary textual form (`WIF.init(_:)` at `WIF.swift:24`,
`Address.init(_:)` at `Address.swift:29`) with a second, non-throwing/validated-input
initializer for programmatic construction from already-validated parts
(`WIF.init(privateKey:network:isCompressed:)`, `Address.init(publicKeyHash:network:)`). Error
enum cases are named as complete, specific facts (`invalidPrivateKeyByteCount(Int)`,
`invalidHybridParity`, not generic `.invalid` or `.parseError`).

**Byte handling.** `[UInt8]` is the boundary type, not `Data`. `import Foundation` appears in
only 22 of the files that reference bytes, versus 112 files using `[UInt8]` directly and 30
using `Data` at all (some of those 30 uses are internal bridging to `swift-crypto`/`P256K` APIs
that require `Data`, not public-API surface). Every public byte-bearing property read
(`PrivateKey.bytes`, `PublicKey.compressedBytes`, `Hash160.bytes`) is `[UInt8]`. A toolbox that
exposes `Data` at its own public boundary instead of `[UInt8]` would be introducing a
foreign convention, not following the SDK's — match `[UInt8]`.

**Optionals vs throwing.** Parse failure is uniformly `throws`, not `Optional`-returning
"try?"-style APIs. No failable initializer (`init?`) was found among the types read. This
matches the "fail informatively" convention already in this user's global CLAUDE.md.

**Explicit bounded limits.** This is the SDK's most distinctive convention and the one most
likely to matter for a toolbox that adds networking or storage on top. Every decoder that
accepts external input takes an explicit limits parameter or type:
`Base58Check.decode(text, maximumPayloadByteCount: 34)` (`WIF.swift:27`),
`Hex.decode(_:maximumDecodedByteCount:)` (README example), `CompactSize.decodeVarBytes(_:maximumLength:)`,
`BEEFLimits`, `TransactionLimits`, `MerklePathLimits`, `PortableMessageLimits`,
`WalletABILimits`, `WalletCryptoLimits`. There is no shared "unbounded by default" decode path
anywhere the README advertises. A toolbox adding its own wire/JSON parsing (e.g. for a
storage backend or a wallet-server protocol) should add its own explicit limits type rather
than trusting an ambient default, to stay consistent.

**Documentation comments.** Triple-slash `///` doc comments on every public declaration,
first line is a complete sentence describing the value's identity or the method's effect
(not a restatement of the signature), e.g. `/// A validated 32-byte secp256k1 private scalar.`
(`PrivateKey.swift:3`), `/// Derives the recipient's BRC-42 child private key.`
(`BRC42.swift:12`). Multi-paragraph doc comments are used sparingly for genuinely subtle
behavior (role semantics in BRC-42, redaction warnings on `WIF.description`).

**Redaction.** Secret-bearing types (`PrivateKey`, `WIF`) override `description`,
`debugDescription`, and `customMirror` to return a fixed redacted string
(`PrivateKey.swift:44-48`, `WIF.swift:69-73`) — string interpolation and reflection/mirroring
of a secret never leaks it, only an explicit `.bytes`/`.encoded` access does. This is called
out as a named feature in the README ("Redacts secret values from default descriptions and
reflection"). A toolbox holding any secret-derived state (session keys, decrypted certificate
fields) should replicate this pattern rather than relying on the SDK to do it for
toolbox-owned types.

**Access control.** `public` is applied deliberately per-declaration, not via a blanket
`public` extension on internal types — no `@_spi` usage was found anywhere in `Sources/`.
`internal` is used sparingly and only found on two `KeyedDecodingContainer`/
`KeyedEncodingContainer` extensions inside `BSVWallet/JSON/WalletJSON.swift:137,152` — i.e.
the SDK does not lean on `internal` as a general design tool, `public` is the default posture
for anything meant to be part of a module's surface.

## 4. Testing conventions

Swift Testing (`import Testing`, `@Suite`, `@Test("description")`, `#expect`) is the framework
in use, not XCTest — confirmed in `Tests/BSVKeysTests/Derivation/BRC42Tests.swift:1-8`. Test
methods use descriptive string labels passed to `@Test(...)` rather than
`test<CamelCase>` method-name conventions (e.g. `@Test("sender public derivation matches
recipient private derivation")`, `BRC42Tests.swift:7`); the underlying Swift method name is a
short camelCase summary (`bilateralConsistency`, `rolesAndDeterminism`). `@testable import`
is used to reach non-public helpers when needed (`BRC42Tests.swift:2`).

**Go SDK conformance is a first-class, CI-enforced testing layer**, not an aspiration. A
dedicated `BSVConformanceTests` target (`Package.swift:203-211`) carries ~35 conformance test
files (`Tests/BSVConformanceTests/`, e.g. `BEEFConformanceTests.swift`,
`WalletWireGoOracleTests.swift`, `MerklePathConformanceTests.swift`,
`Secp256k1KeyConformanceTests.swift`), backed by a `Fixtures` resource bundle
(`Package.swift:210`, `Tests/BSVConformanceTests/Fixtures/`) and a `FixtureManifest` loader
(`Tests/BSVConformanceTests/Support/FixtureManifest.swift`). A subset of these tests
(`*GoOracleTests.swift`) shell out to a **pinned Go SDK build** as a live oracle: CI checks out
`bsv-blockchain/go-sdk` at a pinned commit matching tag `v1.3.3` and verifies the checkout hash
before running (`.github/workflows/ci.yml:47-51`), builds a Go adapter under
`Tools/Conformance/GoOracle/`, and runs required Swift-to-Go differential tests
(`.github/workflows/ci.yml:66-73`) gated by `BSV_ORACLE_REQUIRED=1`. This means official BSV
test vectors are sourced by **running the actual pinned upstream Go implementation**, not by
a static fixture file that could drift from it — the strongest form of conformance testing
available short of a shared formal spec. `Documentation/ADRs/0003-fixture-provenance.md` and
`Documentation/Compatibility/README.md` document the provenance policy: fixtures are "research
inputs, not claims that features are implemented," and every implementation packet must link
applicable BRC-Matrix rows and test vectors. A toolbox that needs its own cross-language
parity guarantees should look at replicating this oracle pattern rather than inventing a new
one.

## 5. Build and CI

Single workflow, `.github/workflows/ci.yml`, three jobs:
1. `test` — matrix over `macos-15` / `ubuntu-24.04` × Swift 6.1, runs
   `swift test --disable-sandbox`, then `Tools/Conformance/check-public-api.sh` to verify
   public-API dependency isolation (line 22-24).
2. `big-number-linux-scale` — a dedicated memory-constrained (`--memory=768m`) Linux container
   job that runs `BigNumScaleTests` in release mode with `BSV_BIG_NUM_SCALE=1`, i.e. a
   deliberate resource-exhaustion/scale gate for the big-integer module, isolated from the main
   test job so a slow scale test can't block ordinary CI turnaround.
3. `go-sdk-conformance` — the pinned-Go-oracle job described above.

No `swift-format` or `SwiftLint` configuration file was found anywhere in the repo root (no
`.swiftlint.yml`, no `.swift-format`) — formatting/linting is not currently automated in CI
beyond what `swift test`/build enforce. No DocC catalog or `Package.swift` DocC plugin was
found. Release/tagging process is not documented in-repo beyond the README's Go-parity pin
(`v1.3.3`); no `CHANGELOG.md` was found at the root.

Architecture decisions live under `Documentation/ADRs/` as numbered records with a template
(`0000-template.md`) and an explicit "never rewrite an accepted ADR, supersede it" policy
(`Documentation/ADRs/README.md`). Six ADRs exist, covering module architecture, the umbrella
module decision, fixture provenance, a big-integer library choice, and transaction-graph
semantics.

## 6. Gaps — what a BRC-100 wallet toolbox still needs

This SDK is considerably further along toward BRC-100 than a "primitives only" library — most
of the checklist items below are **present**, which changes what the toolbox actually needs to
add. Checked explicitly:

| Item | Status | Where |
|---|---|---|
| BEEF / Atomic BEEF (BRC-95) | **Present** | `Sources/BSVTransaction/BEEF/` |
| Merkle proof verification | **Present** | `Sources/BSVTransaction/Merkle/`, `Sources/BSVSPV/SPVProofVerifier.swift` |
| `WalletInterface` / BRC-100 protocol | **Present** | `Sources/BSVWallet/ABI/WalletInterface.swift` |
| Certificates | **Present** (BRC-52 value types + BRC-103 exchange) | `Sources/BSVWallet/Certificates/`, `Sources/BSVAuth/Certificates/` |
| Storage of any kind | **Absent** | no persistence layer anywhere in `Sources/`; `BSVStorage` is UHRP *content addressing*, not key/UTXO/action storage |
| HTTP client usage | **Present, narrow** | `URLSessionHTTPTransport` in `BSVNetwork/HTTP/`, used only for ARC, WhatsOnChain, Block Headers Service, overlay, UHRP download |
| JSON-RPC | **Absent** | no match for JSON-RPC anywhere |
| BRC-103 mutual authentication | **Present** (protocol/value layer) | `Sources/BSVAuth/BRC103/` |
| BRC-29 deposit-address derivation | **Absent** | no match for BRC-29 anywhere in `Sources/` |

So the concrete gap list for the toolbox to fill:

1. **No persistence layer at all.** No key storage, no UTXO/output tracking, no action
   (transaction) history, no certificate storage. `WalletInterface`'s doc comment says this
   outright (`WalletInterface.swift:124-125`). This is the toolbox's primary reason to exist —
   it needs to be (or wrap) a concrete `WalletInterface` implementation with real state.
2. **No `WalletInterface` implementation**, only the ABI contract and the offline crypto kernel
   (`ProtoWallet`) it would be built from. `BSVWallet` gives the toolbox everything needed to
   *implement* the seven wallet-crypto calls, `createAction`/`signAction`/output management/etc.
   need real logic — UTXO selection, change handling, action bookkeeping.
3. **No unlocking-script template system.** Only hand-written P2PKH signing exists
   (`P2PKHSigning.swift`); there is no `UnlockingScriptTemplate`-style protocol comparable to
   the TS/Go toolboxes' pluggable template architecture, so custom-script spending (needed for
   anything beyond plain P2PKH — e.g. BRC-100's own wallet outputs, PushDrop-locked outputs)
   has no shared abstraction to plug into yet.
4. **No BRC-29 deposit-address derivation.** Confirmed absent; needed if the toolbox exposes a
   deposit/payment-address flow.
5. **HTTP client coverage is narrow and provider-specific**, not a general-purpose wallet
   backend client. There is no client for a wallet storage server, no JSON-RPC, and the
   existing HTTP client (`URLSessionHTTPTransport`) is wired to ARC/WhatsOnChain/BlockHeaders/
   overlay/UHRP shapes specifically — a toolbox wallet-server substrate would need its own
   transport wiring, though it could likely reuse `URLSessionHTTPTransport` at the low level.
6. **`BRC104` HTTP framing exists but is unconnected to an actual transport loop** — it defines
   payload framing (`BRC104HTTPFraming.swift`, `BRC104Payload.swift`) but not a client that
   drives a BRC-103 handshake end-to-end over `URLSession`. The toolbox (or a thin adapter) is
   where that gets wired up.
7. **`BSVServices` target is a placeholder** (empty dir, not in `Package.swift`) — worth
   checking with the SDK maintainer whether it is reserved for something the toolbox should
   wait on before claiming that namespace.

## 7. Third-party dependencies

Exactly three direct dependencies, all pinned `exact:` (`Package.swift:29-42`):

- **`swift-secp256k1`** (21-DOT-DEV, 0.23.2) — wraps libsecp256k1 (C), product name `P256K`.
  Used only by `BSVKeys`. This is the dependency most likely to gate Linux support: it builds a
  C target, so Linux support depends on that package's own Linux CI, not assumed here — the
  swift-sdk's own CI does build/test on `ubuntu-24.04` (`ci.yml:14`), which is at least existing
  evidence it works on Linux with Swift 6.1 as configured today.
- **`swift-crypto`** (apple, 4.5.1) — Apple's cross-platform CryptoKit-compatible library,
  explicitly designed to support Linux (uses BoringSSL on non-Apple platforms). Products used:
  `Crypto`, `CryptoExtras`. Low Linux risk.
- **`BigInt`** (attaswift, 5.7.0) — pure Swift, no C dependency, negligible Linux risk.

`Package.resolved` additionally pins `swift-asn1` (apple) as a transitive dependency (pulled in
by `swift-crypto`), not a direct one. No `BigInt`-alternative or `swift-asn1` direct usage was
found in `Sources/` itself.

Net Linux-support risk is concentrated in `swift-secp256k1`'s C bridging, not in the pure-Swift
or Apple cross-platform pieces — worth a quick platform-support check on that specific
dependency before the toolbox commits to Linux, since it sits at the bottom of nearly every
other module's dependency chain (`BSVKeys` is a transitive dependency of 13 of the 16 public
modules).

---

*Not independently verified in this pass: `IdentityClient`'s exact call shape (BSVIdentity),
whether `BSVOverlay`/`BSVRegistry` lookup/publish "boundaries" are protocols or concrete types,
and the full member list of `BSVInterpreter`'s VM types beyond file names. These would need a
closer read before the toolbox designs against them directly.*
