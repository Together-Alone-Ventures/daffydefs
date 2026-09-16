# zombie-core

Shared protocol types for the Zombie suite — cryptographic deletion receipts,
hashing primitives, and serialisation for GDPR Right to Erasure on ICP.

## What this is

`zombie-core` is the canonical definition of the **CVDR (Cryptographically
Verifiable Deletion Receipt)** data structures and the hash primitives that
produce them. Every Zombie suite product (`MKTd02`, `MKTd03`, future variants)
depends on this crate so that receipts, verification tooling, and protocol
changes all share a single source of truth.

This crate is **pure Rust with zero ICP dependencies**. It compiles and tests
on native targets:

```
cargo test
```

## Crate contents

| Module | Purpose |
|---|---|
| `receipt` | `DeletionReceiptV4`, `DeletionReceiptV5`, `AnyDeletionReceipt`, `ProtocolVersion`, `ReceiptState`, `ReceiptSummary`, `compute_receipt_id`, `deletion_event_hash_v5`, `deletion_event_hash_v1`, `genesis_certified_data`, `check_certified_data_not_genesis`, named rejections `ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT` / `ERR_INVALID_EVENT_HASH_ZERO` / `ERR_NO_DELETION_CERTIFIED` |
| `hashing` | `hash_with_tag`, `sha256`, domain separation tags (incl. `TAG_EVENT_V2`, `TAG_GENESIS`), retired tags (`RetiredTag`, `RETIRED_TAGS`), golden test vectors |
| `tombstone` | `TOMBSTONE_CONSTANT` and derivation |
| `serialisation` | CBOR encode/decode helpers for PII state |
| `manifest` | `compute_manifest_hash`, `FieldDescriptor` |

## Protocol versioning

Each receipt contains a `protocol_version` string (e.g. `"mktd02-v2"`) that
tells verification tooling which hash formulas to use. Domain tags are stable
within a protocol line; retirements are recorded in `RETIRED_TAGS` and never
reused. The version field gates formula selection. Golden test vectors
in `hashing.rs` act as tripwires — any accidental protocol change breaks them
immediately.

## Versioning and pinning

Consumer crates (`MKTd02`, `CVDR-Verify`) pin `zombie-core` by **commit hash
(rev)** during active development, and by **version tag** for releases. Tags
follow the convention `zombie-core-vX.Y.Z` to avoid confusion with consumer
repo version tags.

**Always prefix version strings with the repo name** when both repos are in
scope: write `zombie-core v0.1.0` and `MKTd02 v0.2.0`, never just `v0.1.0`.

## Part of the Zombie suite

```
Together-Alone-Ventures/zombie-core   ← you are here (shared types)
Together-Alone-Ventures/MKTd02        ← Leaf-mode ICP canister library
Together-Alone-Ventures/CVDR-Verify   ← standalone verification tooling
```

Future products (`MKTd03` Tree mode, `ZKPd` family) will add their own repos
and depend on this crate.

## Licence

Apache-2.0 — see [LICENSE](LICENSE).
