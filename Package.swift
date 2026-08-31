// swift-tools-version: 6.1

import PackageDescription

/// Every module a consumer may import. The umbrella `WalletToolbox` re-exports all of them, so an
/// application can take the whole thing with one import or depend on exactly the layer it needs.
///
/// The split is not cosmetic. Go's toolbox enforces its internal boundaries with `pkg/X/internal/`,
/// which the compiler checks; Swift has no path-based equivalent, so a separate target is the only
/// way to make a boundary real. Each of these is a boundary we intend to keep.
let publicModules = [
    "ToolboxCore",
    "ToolboxAuth",
    "ToolboxBRC29",
    "ToolboxPortable",
    "ToolboxStorage",
    "ToolboxStorageClient",
    "ToolboxServices",
    "ToolboxPaymail",
    "ToolboxActions",
    "ToolboxPermissions",
    "ToolboxWallet",
    "ToolboxMonitor",
]

let package = Package(
    name: "swift-wallet-toolbox",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "WalletToolbox", targets: ["WalletToolbox"])
    ] + publicModules.map { .library(name: $0, targets: [$0]) },
    dependencies: [
        // Pinned to a revision rather than a branch: CI must build the same bytes twice. The pin
        // moves when we mean it to, which is also when we re-run conformance.
        .package(
            url: "https://github.com/opldotdev/swift-sdk.git",
            revision: "941557a257cd3a009d61f953b3d913249c1da69b"
        )
    ],
    targets: [
        .target(
            name: "WalletToolbox",
            dependencies: publicModules.map { .target(name: $0) }
        ),

        // Shared vocabulary: the wire error taxonomy, identity of the authenticated user, and the
        // decode limits every parser takes. Depends on nothing but the SDK's core types.
        .target(
            name: "ToolboxCore",
            dependencies: [
                .product(name: "BSVCore", package: "swift-sdk"),
                .product(name: "BSVKeys", package: "swift-sdk"),
            ]
        ),

        // BRC-103 mutual authentication over HTTP. The SDK carries the protocol and its value
        // types; this drives them over a real transport, which is what remote storage requires.
        .target(
            name: "ToolboxAuth",
            dependencies: [
                "ToolboxCore",
                .product(name: "BSVAuth", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
            ]
        ),

        // BRC-29 payment derivation. Its own module because a receiving screen and the change
        // generator both need it without needing each other, mirroring Go's top-level `pkg/brc29`.
        .target(
            name: "ToolboxBRC29",
            dependencies: [
                "ToolboxCore",
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVScript", package: "swift-sdk"),
            ]
        ),

        // Canonical BRC-38 wallet-data documents and the BRC-39 binary envelope. This target is
        // intentionally independent of a storage engine: portable data can be validated before a
        // caller chooses restore or merge semantics.
        .target(
            name: "ToolboxPortable",
            dependencies: ["ToolboxCore"]
        ),

        // The storage contract and its record types. No implementation lives here, so an engine
        // and a client can be written against the same protocol without seeing each other.
        .target(
            name: "ToolboxStorage",
            dependencies: [
                "ToolboxCore",
                .product(name: "BSVTransaction", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
            ]
        ),

        // Remote storage over JSON-RPC. The only storage engine in v1, matching the TypeScript
        // mobile build, which ships no on-device engine at all.
        .target(
            name: "ToolboxStorageClient",
            dependencies: [
                "ToolboxCore", "ToolboxAuth", "ToolboxStorage",
                .product(name: "BSVAuth", package: "swift-sdk"),
                .product(name: "BSVCore", package: "swift-sdk"),
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVTransaction", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
            ]
        ),

        // The chain-facing layer: broadcast, output status, block headers, exchange rate. Each
        // category is an ordered chain of providers, so one provider failing is not an outage.
        .target(
            name: "ToolboxServices",
            dependencies: [
                "ToolboxCore",
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVScript", package: "swift-sdk"),
                .product(name: "BSVTransaction", package: "swift-sdk"),
                .product(name: "BSVSPV", package: "swift-sdk"),
            ]
        ),

        // Paymail discovery, payment-output resolution, and signed-transaction delivery.
        .target(
            name: "ToolboxPaymail",
            dependencies: ["ToolboxCore"]
        ),

        // Building, funding and signing transactions, and the BRC-29 script template. This is
        // where the output-echo check lives, so it cannot be bypassed by a caller.
        .target(
            name: "ToolboxActions",
            dependencies: [
                "ToolboxCore",
                "ToolboxBRC29",
                "ToolboxStorage",
                "ToolboxServices",
                .product(name: "BSVCore", package: "swift-sdk"),
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVScript", package: "swift-sdk"),
                .product(name: "BSVTransaction", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
            ]
        ),

        // BRC-116's transport-neutral policy vocabulary and request classifier. This target owns
        // no persistence, prompt UI, permission tokens, or wallet calls.
        .target(
            name: "ToolboxPermissions",
            dependencies: [
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
            ]
        ),

        // The concrete BRC-100 wallet, composing storage, services and actions.
        .target(
            name: "ToolboxWallet",
            dependencies: [
                "ToolboxCore",
                "ToolboxBRC29",
                "ToolboxStorage",
                "ToolboxStorageClient",
                "ToolboxServices",
                "ToolboxActions",
                "ToolboxPaymail",
                .product(name: "BSVCore", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVScript", package: "swift-sdk"),
                .product(name: "BSVCompat", package: "swift-sdk"),
                .product(name: "BSVTransaction", package: "swift-sdk"),
            ]
        ),

        // Scheduled background work: rebroadcast, proof collection, abandonment.
        .target(
            name: "ToolboxMonitor",
            dependencies: ["ToolboxCore", "ToolboxStorage", "ToolboxServices"]
        ),

        .testTarget(name: "ToolboxCoreTests", dependencies: ["ToolboxCore"]),
        .testTarget(
            name: "ToolboxAuthTests",
            dependencies: [
                "ToolboxAuth",
                .product(name: "BSVWallet", package: "swift-sdk"),
                .product(name: "BSVAuth", package: "swift-sdk"),
            ]
        ),
        .testTarget(
            name: "ToolboxBRC29Tests",
            dependencies: [
                "ToolboxBRC29",
                .product(name: "BSVKeys", package: "swift-sdk"),
            ]
        ),
        .testTarget(
            name: "ToolboxPortableTests",
            dependencies: ["ToolboxPortable"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(name: "ToolboxStorageTests", dependencies: ["ToolboxStorage"]),
        .testTarget(
            name: "ToolboxStorageClientTests",
            dependencies: [
                "ToolboxStorageClient", "ToolboxStorage", "ToolboxAuth", "ToolboxCore",
                .product(name: "BSVWallet", package: "swift-sdk"),
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVScript", package: "swift-sdk"),
                .product(name: "BSVTransaction", package: "swift-sdk"),
            ]
        ),
        .testTarget(name: "ToolboxServicesTests", dependencies: ["ToolboxServices"]),
        .testTarget(name: "ToolboxPaymailTests", dependencies: ["ToolboxPaymail"]),
        .testTarget(
            name: "ToolboxActionsTests",
            dependencies: [
                "ToolboxActions", "ToolboxStorage", "ToolboxBRC29",
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVTransaction", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
            ]
        ),
        .testTarget(
            name: "ToolboxPermissionsTests",
            dependencies: [
                "ToolboxPermissions",
                .product(name: "BSVCore", package: "swift-sdk"),
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVTransaction", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
            ]
        ),
        .testTarget(
            name: "ToolboxWalletTests",
            dependencies: [
                "ToolboxWallet", "ToolboxStorage", "ToolboxStorageClient", "ToolboxBRC29",
                .product(name: "BSVKeys", package: "swift-sdk"),
                .product(name: "BSVWallet", package: "swift-sdk"),
            ]
        ),
        .testTarget(name: "ToolboxMonitorTests", dependencies: ["ToolboxMonitor"]),
    ],
    swiftLanguageModes: [.v6]
)
