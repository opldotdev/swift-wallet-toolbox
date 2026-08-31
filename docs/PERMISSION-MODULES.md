# Permission-module preflight

`ToolboxPermissions` exposes a small, protocol-neutral registry for host-owned
permission review modules. It is deliberately a **veto-only preflight**. A
module can enrich a prompt or deny a request; it cannot modify wallet arguments,
mint a permission token, replace a BRC-116 decision, or call the wallet through
this API.

## Host sequence

1. Decode the BRC-100 request and normalize/classify it with
   `WalletPermissionClassifier`.
2. Select a host-installed module scheme. Scheme IDs follow BRC-123 section
   3.1: `[a-z][a-z0-9]*`, 2 through 30 characters.
3. Call `PermissionModuleRegistry.dispatch`. A registered handler receives a
   serializable `PermissionModuleRequest` containing:
   - a lifecycle-scoped invocation ID;
   - the exact scheme and BRC-100 method;
   - the canonical originator;
   - the canonical BRC-100 JSON encoding of all request arguments and effects;
   - the unchanged `PermissionDecision`, including its authorization plan.
4. If the review continues, satisfy the original `PermissionDecision` using
   the canonical BRC-116 permission-token repository.
5. Only then call the protected `WalletInterface` operation.

`continueAuthorization` means only “the module did not veto.” It is never a
grant. `.denied` classifier results short-circuit before a module runs. A module
denial, error, invalid originator, encoding failure, or timeout fails closed as
`PermissionModuleRegistryError.permissionDenied` with the stable message
`Permission denied.` Caller cancellation, handler removal, and `cancelAll()`
cancel the lifecycle and must also prevent the wallet call.

An unregistered scheme returns `.noHandler`, preserving the host's existing
classifier behavior. BRC-99 still requires unsupported `p <scheme> ...`
baskets to be rejected; `.noHandler` does not make such a basket valid.

## Cross-language behavior

| Source | Behavior | Swift behavior |
|---|---|---|
| BRC-99 / BRC-123 | Reserve `p <scheme> <basket>` and reject unsupported schemes | Registry validates the scheme ID; the classifier's existing unsupported-scheme denial remains unchanged |
| BRC-116 normative security | Permission is never implicit and on-chain tokens remain authoritative | The module is veto-only and receives, but cannot replace, the canonical decision |
| TypeScript `WalletPermissionsManager` | Module `onRequest` may rewrite arguments and its P-path bypasses ordinary tokens | Deliberate security divergence: no rewriting, response transformation, or token bypass |
| Go wallet-toolbox | No permission-module registry in the inspected live implementation | Swift adds only the host seam; no asset-specific semantics live here |

Swift tasks are cooperatively cancellable, so a hostile handler can ignore task
cancellation and keep its own work alive. The registry uses an independent
first-result deadline and does not await that task after timeout, ensuring the
wallet request itself cannot hang. Hosts should register only trusted modules.
