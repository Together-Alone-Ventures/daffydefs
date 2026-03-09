> [!IMPORTANT]
> **Frozen Snapshot Notice**
> This document is a **frozen integration snapshot** retained in DaffyDefs.
> It is based on the MKTd02 Integration Guide used for the DaffyDefs **v0.2.x** implementation, sourced from MKTd02 commit **`80edaa2`**.
> Canonical protocol/integration guidance lives in the **MKTd02 repository**.
> This local copy is retained for **implementation traceability only** and may not reflect later MKTd02 updates.

# MKTd02 Integration Guide

**Version 3.0** · Updated 27 February 2026

> **Configuration:** MKTd | Library | ICP (StableCell / StableBTreeMap) | Single-canister | Leaf mode | Tombstone (Explicit) | ICP subnet BLS certification

This guide covers the complete integration of MKTd02 into an ICP canister. It combines MKTd02-specific instructions with platform-level documentation shared across all Zombie Delete ICP products.

For the complete deletion process flow, verification procedures, and residual trust analysis, see the MKTd02 tab in the Zombie Delete Configurations spreadsheet. For independent receipt verification tooling, see the MKTd02 README.


---

# 1. Prerequisites

## Platform Prerequisites (ICP)

The following prerequisites apply to all Zombie Delete products deployed on the Internet Computer.

| Prerequisite | Detail | Responsibility |
|---|---|---|
| **Rust toolchain** | Stable Rust (edition 2021+) with `wasm32-unknown-unknown` target installed. | Enterprise dev team |
| **dfx SDK** | DFINITY SDK for local canister development, testing, and deployment. | Enterprise dev team |
| **ic-cdk version** | ic-cdk 0.17 or later. All current Zombie Delete ICP libraries depend on ic-cdk 0.17; canisters using earlier versions must upgrade. | Enterprise dev team |
| **Canister architecture** | A deployed (or deployable) Rust canister using StableCell, StableBTreeMap, or equivalent stable memory structures for PII storage. | Enterprise dev team |
| **Canister upgrade mechanism** | Ability to push new WASM to deployed canisters (e.g., factory `install_code` with Upgrade mode, governance proposal, or direct `dfx deploy`). The Zombie Delete integration is deployed as a standard canister upgrade — the enterprise must already have this infrastructure. | Enterprise dev team |
| **ICP cycles** | Sufficient cycles balance for canister operations (deletion processing, certified variable updates, receipt storage). | Enterprise ops |
| **Subnet ID** | The Principal of the ICP subnet hosting the canister. ICP canisters cannot discover their subnet at runtime. Obtain from the [ICP dashboard](https://dashboard.internetcomputer.org/) or NNS registry. Hardcoded in config for single-subnet deployments; passed as an init/upgrade argument for multi-subnet architectures. | Enterprise ops |
| **PII field inventory** | A complete enumeration of which fields constitute PII and must be included in the state hash and tombstoned (or otherwise erased) on deletion. | Compliance + dev team |
| **Access control design** | A decision on which principals are authorised to trigger deletion (controller, specific principals, DAO governance canister, etc.). | Enterprise governance |
| **Module hash pipeline** | A mechanism to compute SHA-256 of the final deployed WASM bytes and pass the hash to the canister at init or upgrade time. See [Module Hash: Deployment Patterns](#module-hash-deployment-patterns). | Enterprise dev team |

### Compile-time dependency model

All Zombie Delete ICP libraries are compile-time Rust crate dependencies. The library code runs inside the canister's own execution context — there is no external service, no inter-canister call, and no network dependency at runtime. ICP guarantees single-threaded message execution per canister, so all library operations within a single update call are atomic.

### Candid maintenance

After adding library endpoints, regenerate and commit the canister's `.did` file. The Candid interface must match the compiled canister exactly — deployment will fail if they diverge. Include `.did` regeneration in the build pipeline or CI checks.

### MKTd02-Specific Prerequisites

In addition to the platform prerequisites above, MKTd02 requires:

| Prerequisite | Detail | Responsibility |
|---|---|---|
| **Available MemoryId range** | 8 contiguous MemoryIds for MKTd02 (default: 100–107). Must not overlap with existing canister stable memory allocations. | Enterprise dev team |
| **Leaf mode architecture** | One data subject per canister. The canister holds PII for a single user/entity. Multi-subject canisters require MKTd03 (Tree mode) instead. | Enterprise architect |


---

# 2. Step-by-Step Integration

The integration comprises five tasks. Estimated total effort: 1–2 days for a developer familiar with ICP canister development. No changes to the canister's existing business logic are required.

## Add MKTd02 Library Crate

Add the MKTd02 crates as dependencies in the canister's `Cargo.toml`:

```toml
[dependencies]
mktd02 = { git = "https://github.com/Together-Alone-Ventures/MKTd02.git", package = "mktd02" }
zombie-core = { git = "https://github.com/Together-Alone-Ventures/MKTd02.git", package = "zombie-core" }
hex = "0.4"  # For tombstone constant encoding
```

The crate provides: the core engine (state hashing, tombstone operations, receipt generation), the `MKTdDataSource` trait, the receipt export module, and certified variable management helpers.

**ic-cdk version requirement:** MKTd02 depends on ic-cdk 0.17. If the canister uses an earlier version (e.g., 0.15 or 0.16), it must be bumped. This may affect other canisters in the same workspace.

## Implement `MKTdDataSource` Adapter

The host canister implements `MKTdDataSource` to map product storage to MKTd02’s Leaf-mode interface.

### Leaf-Mode Boundary

MKTd02 is for single-subject-per-canister architecture (Leaf mode).
Multi-subject-per-canister architecture is out of scope for MKTd02 and belongs to Tree-mode product lines.

### Required trait methods

| Method | Returns | Purpose |
|---|---|---|
| `mode()` | `CommitMode` (use `CommitMode::Leaf` for MKTd02) | Declares integration mode. |
| `pii_field_manifest()` | `Vec<FieldDescriptor>` | Declares PII boundary metadata and ordering intent. |
| `get_state_bytes()` | `Vec<u8>` | Deterministic encoded state bytes used for hashing. |
| `tombstone_state()` | — | Applies tombstone writes to PII fields. |
| `is_tombstoned()` | `bool` | Post-condition check for tombstone state. |

`manifest_hash()` is not part of the v0.2.x `MKTdDataSource` trait.

### State Encoding Specification Requirement

Integrators should publish a State Encoding Spec documenting:

- Field names
- Field types
- Serialization order assumptions
- Tombstone value mapping
- Encoding library/version assumptions

This supports independent audit/reproduction of state-hash behavior.

### Deterministic CBOR Clarification

Determinism here is defined by project encoding constraints and integration rules.
It is not a blanket claim that arbitrary CBOR encoder output is interchangeable under RFC canonical-CBOR semantics.

### Adapter Correctness Invariant

After `tombstone_state()`, `is_tombstoned()` must reflect the expected post-condition before receipt finalization proceeds.

## Deterministic Encoding Requirements

### CBOR determinism checklist

`pii_field_manifest()` and `get_state_bytes()` (or their product-specific equivalents) MUST produce identical output across builds and upgrades. The encoding is deterministic under this library's encoder (ciborium + serde). This is **not** RFC 8949 canonical CBOR — determinism relies on the specific rules below.

**All of the following must be followed:**

- **Stable field order:** The manifest must be an ordered sequence with fixed `field_order` values. Never change field ordering after deployment.
- **No `HashMap` / `BTreeMap` in PII structs:** Use structs with named fields. ciborium serialises struct fields in declaration order.
- **No floats:** `encode_pii_state()` rejects any floating-point values (non-deterministic NaN representations).
- **Use `encode_pii_state()` as the only encoding path** for `get_state_bytes()`. Do not call ciborium directly.
- **Version bump rule:** Any change to the PII boundary or serialisation rules requires a manifest version bump (new `manifest_hash`). Old receipts remain verifiable under the `manifest_hash` recorded in each receipt.

### State Encoding Spec

The adapter must publish a **State Encoding Spec** documenting:

| Item | Description |
|---|---|
| **Field names** | Exact field names as they appear in the CBOR encoding. |
| **Types** | Rust types and their CBOR representations. |
| **Serialisation order** | The fixed field order used by the manifest. |
| **Tombstone values** | The hex-encoded `TOMBSTONE_CONSTANT` value written to each field on deletion. |
| **Encoding library version** | The ciborium version and any serde configuration. |

This spec is anchored by `manifest_hash` — any change to the spec changes the manifest hash, ensuring receipt–spec alignment. A verifier with the State Encoding Spec can independently reconstruct the expected CBOR encoding and verify state hashes in receipts.

### Adapter correctness invariant

The library calls `adapter.is_tombstoned()` immediately after `adapter.tombstone_state()` as a post-condition check on the PII fields. If it returns `false`, the library traps and the entire message is rolled back. This catches adapter bugs that would produce invalid receipts.

Test this invariant explicitly during adapter development. A simple test case: call `tombstone_state()`, then assert `is_tombstoned()` returns `true`.

## Wire Lifecycle Hooks
Three integration points in the canister's lifecycle, plus a deployment-time module hash pipeline (covered in the next section).
### init()
Call `mktd02::init()` at the end of your canister's init function, after all initial data writes:
```rust
let adapter = MyAdapter;
let module_hash = [0u8; 32]; // ⚠ DEV ONLY — see Module Hash: Deployment Patterns for production
MEMORY_MANAGER.with(|mm| {
    mktd02::init(&adapter, &mm.borrow(), MktdConfig {
        base_memory_id: 100,
        subnet_id: Principal::from_text("jtdsg-3h6gi-...").unwrap(),
    }, module_hash);
});
```
**Subnet ID:** This value cannot be discovered at runtime. Obtain it from the [ICP dashboard](https://dashboard.internetcomputer.org/) (look up your canister, note the subnet it's hosted on) or query the NNS registry. Using `Principal::anonymous()` will produce receipts with an invalid subnet field that cannot be verified.
This computes the initial state hash and publishes the certified commitment.
### post_upgrade()
Call `mktd02::on_post_upgrade()` after schema migration but before any PII reads:
```rust
let adapter = MyAdapter;
let module_hash = [0u8; 32]; // ⚠ DEV ONLY — see Module Hash: Deployment Patterns for production
let config = MktdConfig {
    base_memory_id: 100,
    subnet_id: Principal::from_text("jtdsg-3h6gi-...").unwrap(),
};
MEMORY_MANAGER.with(|mm| {
    mktd02::on_post_upgrade(&adapter, &mm.borrow(), config, module_hash);
});
```
This detects manifest changes and triggers the recomputation cascade. Module hash is updated unconditionally on every `post_upgrade`.
> **Critical:** Any PII migration writes must happen BEFORE this call so the hash computation reflects the migrated state.
### After every PII write
Call `mktd02::refresh_state_hash()` after every successful PII-mutating write:
```rust
// In upsert_profile() or equivalent:
profile_cell.set(updated_profile)?;
mktd02::refresh_state_hash(&MyAdapter);
```
The host canister is responsible for calling `refresh_state_hash()`. The library does not auto-hook into writes.

## Module Hash: Deployment Patterns

The module hash is the SHA-256 of the canister's deployed WASM binary — the exact bytes running on the subnet. Zombie Delete libraries stamp this value into every Cryptographically Verifiable Deletion Receipt (CVDR) as the `canister_module_hash` field. It enables V3 (Canister Module Verification): a verifier can independently confirm the canister was running the expected code at deletion time. If the module hash is zeros, V3 cannot be performed.

**Core rule: Hash what you ship.** The SHA-256 must be computed from the final, post-transformation WASM bytes — the exact bytes that `install_code` receives. Not pre-shrink. Not pre-optimisation. The shipped bytes.

### Why the hash must come from outside the canister

A canister on ICP cannot read its own WASM hash at runtime — there is no system API equivalent to `ic0.self_module_hash()`. The hash must be provided by the entity that performs the deployment. Attempting to embed the hash at compile time creates a circular dependency: embedding it changes the WASM, which changes the hash. The solution is to always pass the hash as an init or upgrade argument from the deploying entity, which already holds the bytes.

### Deployment patterns

Every canister installation or upgrade on ICP flows through one chokepoint: the management canister's `install_code`. Whoever calls `install_code` already has the WASM bytes. The only variable is who makes that call and how the hash reaches the canister. The following table covers the complete space:

| Who calls `install_code` | Hash injection method | Notes |
|---|---|---|
| **Developer / ops (`dfx`)** | Init/upgrade arg from build script | `sha256sum` after all WASM transformations, pass as Candid arg. |
| **Internal deploy service (`ic-agent` library)** | Init/upgrade arg from deploy tool | Enterprise admin tooling that wraps `ic-agent` directly. Same principle as `dfx`. |
| **CI/CD pipeline** | Init/upgrade arg from pipeline step | Automated: build → shrink → hash → deploy in one pipeline. |
| **Factory canister** | Factory computes hash at WASM upload, passes in child's init/upgrade arg | Factory already holds the bytes. Compute once at WASM upload time, store alongside the blob. |
| **Orchestrator canister (fleet)** | Same as factory — one hash computation, N upgrade calls | Enterprise fleet rollout pattern. Hash computed once, passed to all child canisters. |
| **Governance (SNS / DAO)** | Upgrade arg in proposal payload | If your governance path supports passing upgrade args, include the hash. Otherwise, use two-pass attestation (below) immediately after the governance-initiated upgrade. |
| **Self-upgrading canister** | Canister computes hash from fetched WASM before calling `install_code` on itself | The canister has the bytes in hand and can compute SHA-256 before triggering the upgrade. |
| **Blackholed (immutable)** | Set once at final deploy; never changes | Strongest V3 story. The module hash is permanent — code cannot be swapped. |

### Fallback: Two-pass attestation

If your deployment path genuinely cannot plumb the module hash into the init or upgrade argument on first deploy, use the two-pass pattern:

1. Deploy with `[0u8; 32]` as a placeholder.
2. Read the canister's module hash from `canister_status` (or `dfx canister info`) — this is the network's ground truth and resolves all ambiguity about shrink steps, gzip, or build transformations.
3. Immediately upgrade the canister with the correct hash as the upgrade argument.

**Note:** Any receipts generated in the window between first deploy and the corrective upgrade will contain zeros and will fail V3 verification. Minimise this window.

### Byte-identity warnings

- **Hash after all WASM transformations** (`ic-wasm shrink`, `wasm-opt`, gzip, etc.), not before. The canonical rule is: hash the exact bytes `install_code` receives.
- **When in doubt, use two-pass attestation.** Read `canister_status.module_hash` after deployment. The network's view is authoritative and resolves all ambiguity about which bytes were actually deployed.
- **Non-deterministic builds:** Same source code does not guarantee the same module hash across different machines or toolchain versions. If V3 reproducibility matters for auditors, pin your Rust toolchain version and build flags in `RELEASES.md`.

### Warning: `reinstall` mode

> ⚠ **ICP's `reinstall` mode wipes stable memory.** This destroys all Zombie Delete state including stored receipts, tombstone status, and nonce history. Treat `reinstall` as new genesis — prior CVDRs are irrecoverably lost. If your deployment process uses `reinstall` for any reason, be aware that the canister's entire deletion history is erased. Use `upgrade` mode for all routine deployments.

## Expose MKTd02 Canister API

Add the following Candid endpoints to the canister. These are additive — the canister's existing API is unchanged.

| Endpoint | Type | Access | Purpose |
|---|---|---|---|
| `delete_profile()` (or `mktd_delete`) | Update | Restricted | Triggers full deletion flow. Returns `receipt_id` (hex string). |
| `mktd_get_state_hash()` | Query | Public | Returns state hash + optional ICP certificate (via `data_certificate()`). |
| `mktd_get_tombstone_status()` | Query | Public | Returns `{ is_tombstoned: bool, tombstoned_at: Option<u64> }`. |
| `mktd_get_receipt(id_hex)` | Query | Public | Returns full CVDR by `receipt_id`. All hashes as hex strings for readability. |
| `mktd_receipt_count()` | Query | Public | Number of stored receipts (0 or 1 for Leaf mode). |

## Tombstone Protection

### Guard installation

Every update method that modifies PII fields must reject writes when the canister is tombstoned. Three approaches are available; choose based on your crate structure:

#### Approach A: Guard function (recommended when error type is in a separate crate)

```rust
fn mktd_guard_check() -> Result<(), MyError> {
    if !mktd02::is_initialised() { return Err(MyError::NotReady); }
    if mktd02::is_tombstoned() { return Err(MyError::Deleted); }
    Ok(())
}

#[ic_cdk::update]
fn upsert_profile(input: ProfileInput) -> Result<ProfileInfo, MyError> {
    mktd_guard_check()?;
    // ... existing business logic unchanged ...
}
```

#### Approach B: `#[mktd_guard]` macro (when error type implements `GuardError`)

```rust
use mktd02_macros::mktd_guard;

#[mktd_guard]
#[ic_cdk::update]
fn upsert_profile(input: ProfileInput) -> Result<ProfileInfo, MyError> {
    // ... existing business logic unchanged ...
}
```

The macro requires the function to return `Result<T, E>` where `E: mktd02::GuardError`. It parses the return type at compile time and emits a `compile_error!` if the signature doesn't match. If the error type is defined in a separate crate (e.g., a shared library), Rust's orphan rules prevent implementing `GuardError`; use Approach A instead.

#### Approach C: `assert_can_write()` (for non-Result functions)

```rust
mktd02::assert_can_write(); // Traps if tombstoned or uninitialised
```

### Guard ordering

When the canister has both access control (e.g., `require_owner()`) and tombstone protection, **access control should fire first.** This ensures unauthenticated callers are rejected before the tombstone check, and tombstone violations are only reported to authorised callers:

```rust
require_owner()?;       // auth first
mktd_guard_check()?;    // then tombstone
```

### Guard coverage checklist

All of the following must be guarded:

- All Candid-exposed update methods that insert/update/remove PII data
- Internal helpers invoked by update methods (batch updates, maintenance)
- Admin/controller-only methods that touch PII
- Upgrade hooks and migration logic that modify PII fields
- Timers/heartbeat-driven routines that may mutate PII state

### Tombstone semantics

The Zombie Delete library uses Explicit tombstone-type with two distinct checks:

1. **`mktd02::is_tombstoned()`** reads the engine-owned `tombstoned_at` timestamp from stable memory. This is the **write guard**, used to prevent PII writes after deletion. It is unambiguous and does not depend on inspecting field values.

2. **`adapter.is_tombstoned()`** checks whether all PII fields contain the tombstone constant. This is the **post-condition check** used during the deletion flow to verify `tombstone_state()` completed correctly.

These must not be confused. The engine sets `tombstoned_at` later in the deletion flow, so at post-condition check time, only the adapter's PII-field check is meaningful.

This is procedural enforcement, not platform-level prevention. A canister controller who upgrades the code to remove the guard can bypass it. This is documented in the Residual Trust Statement (RT2) and is detectable via module hash verification (V3).

### Anti-resurrection semantics

Tombstoning is permanent for the identity (principal) that owns the canister. The same principal cannot re-register or have data re-written after deletion — the tombstone guard enforces this for every PII-mutating write path.

If the enterprise's UX allows re-registration, it must be via a **new identity** (new principal) mapped to a **new canister**. Any "rejoin" flow that unmaps and remaps the same principal to a fresh canister would defeat the purpose of the CVDR, since the original receipt attests to permanent deletion for that identity.

## Stable Memory Coordination

MKTd02 reserves 8 contiguous memory slots from a configurable base (`base_memory_id`, default `100`).

| Offset | Content | Type | Notes |
|---|---|---|---|
| base+0 | meta | metadata cell | schema/base/init/module-hash fields |
| base+1 | state_hash | `[u8; 32]` | current state hash |
| base+2 | nonce | `u64` | monotonic counter |
| base+3 | certified_commitment | `[u8; 32]` | certified commitment value |
| base+4 | deletion_event_hash | `[u8; 32]` | deletion-event hash value |
| base+5 | finalization_lock | `bool` | prevents certified-data drift between Phase A and C |
| base+6 | receipt store | `StableBTreeMap<[u8;32], Vec<u8>>` | CBOR-encoded receipts |
| base+7 | tombstoned_at | `Option<u64>` | tombstone timestamp cell |

### Safety checks

- Range check on base allocation
- Storage/base collision checks
- Schema/version compatibility checks on reconnect paths

### Upgrade/finalization interaction

When finalization lock is held (pending receipt), operations that would drift certified-data linkage are blocked by implementation guards.

### Clarification

`manifest_hash` is not a v0.2.x stable-memory slot in MKTd02.


---

# 3. Authentication Patterns (ICP)

Zombie Delete libraries do not implement or prescribe an authentication mechanism. On ICP, all calls carry the caller's principal as an intrinsic property of the message, verified by consensus. The canister's own access control checks this principal. The library defers entirely to the host canister's existing auth pattern.

| Pattern | How it works | Typical use case |
|---|---|---|
| **Internet Identity** | User authenticates via WebAuthn passkey, receives a unique principal per dApp. | Consumer-facing applications (e.g., OpenChat). |
| **NFID / alternative IdP** | Third-party identity provider issues delegated principals. | dApps wanting social login. |
| **Canister-to-canister** | Governance canister (e.g., SNS) calls deletion with its own principal. | DAO-governed deletion decisions. |
| **Controller principal** | The canister's controller calls directly. | Admin-triggered deletions. |

Access control on the deletion endpoint is critical and must match the canister's governance model. The Zombie Delete library does not enforce access control — the canister's existing auth pattern (e.g., `require_owner()`) applies. The product-specific integration guide specifies which endpoints require restricted access.


---

# 4. Receipt Export

A CVDR is defined by its fields and verification rules, not by a particular wire encoding. The canister stores and returns receipts as a Candid struct via `mktd_get_receipt()`. The export module provides alternate serialisations for interoperability.

| Function | Purpose |
|---|---|
| `mktd02::export::to_cbor_bytes(receipt)` | Returns the deterministic CBOR encoding of the receipt (the authoritative format). |
| `mktd02::export::to_json(receipt)` [feature: `json`] | Serialises to JSON for SIEM/GRC ingestion (Splunk, ELK, Datadog). |
| `mktd02::export::webhook_push(receipt, url)` [feature: `json`] | Template for HTTP outcall to external webhook. Handles ICP-specific concerns. |

The JSON export option is behind the `json` feature flag. Default builds exclude it to minimise WASM size.

**Receipt delivery:** MKTd02 generates and stores the receipt; how it reaches the data subject is the enterprise's UX decision. Options include: in-app display immediately after deletion, downloadable JSON file, email delivery, or integration with existing GDPR request management workflows. The receipt persists in the canister's stable memory indefinitely and remains queryable via `mktd_get_receipt()` even after tombstoning — the canister stays alive, only PII is erased.


---

# 5. Reference Adapters

| Adapter | Description | Location |
|---|---|---|
| **StableCell adapter** | Reference impl for per-user canister with StableCell. Matches DaffyDefs pattern. | `examples/adapter_stable_cell.rs` |
| **StableBTreeMap adapter** | Stub for MKTd03 Tree mode (multi-record canisters). Deferred. | `examples/adapter_stable_btreemap.rs` |
| **Webhook export** | HTTP outcall example for JSON receipt export to external SIEM. | `examples/webhook_export.rs` |
| **DaffyDefs integration** | Complete working integration with ProfileAdapter, guard function, and lifecycle hooks. | `daffydefs/src/profile_canister/src/lib.rs` |

The DaffyDefs integration is the recommended starting point for new integrators. It demonstrates the complete pattern: adapter implementation, lifecycle hooks, guard function (Approach A), API endpoints, and receipt retrieval.


---

# 6. Assumptions

### MKTd02-Specific

| # | Assumption | Implication |
|---|---|---|
| **A1** | Deletion is triggered by an authorised call. | No CDC, no polling, no external trigger. The caller initiates the request. |
| **A2** | State hash is continuously maintained. | `refresh_state_hash()` after every PII write. No separate pre-delete capture step. |
| **A3** | Canister holds data for a single data subject (Leaf mode). | Multi-subject canisters need MKTd03 (Tree mode). |

## Platform Assumptions (ICP)

The following assumptions apply to all Zombie Delete products deployed on the Internet Computer. Product-specific assumptions are listed in the product's own integration guide.

| # | Assumption | Implication |
|---|---|---|
| **P1** | Library executes within the host canister. | Enterprise retains full control. No external service dependency. |
| **P2** | Receipts contain only hashes, no plaintext PII. | Safe to store publicly. One-way hashes — even the data subject can't reverse them. |
| **P3** | ICP single-threaded execution guarantees atomicity. | No locking or transaction management required. All library operations within a single update call are atomic. |
| **P4** | Canister snapshots may contain pre-deletion state. | Snapshot restore changes the certified commitment, which is detectable by verifiers comparing the receipt's post-state against the canister's current state. |
| **P5** | Code attestation via ICP module hash + subnet BLS. | Replaces TEE attestation model. Trust anchor is subnet consensus, not hardware. See [Module Hash: Deployment Patterns](#module-hash-deployment-patterns) for the deployment pipeline. |
| **P6** | Tombstone guard is procedural enforcement. | No ICP-level triggers exist. Code change (minimal) is required. Guard removal is detectable via module hash verification (V3). |
| **P7** | Tombstoning is irreversible per principal. | The same identity cannot re-register after deletion. Re-registration requires a new identity and a new canister. Enterprise UX must not offer "rejoin with same identity" flows. See [Tombstone Patterns](#tombstone-protection) for anti-resurrection semantics. |
