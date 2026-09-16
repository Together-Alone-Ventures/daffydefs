# zombie-core release notes

> Historical convention in this repo has been **annotated git tags** (e.g.
> `git tag -a zombie-core-v0.3.1`) rather than a checked-in changelog. This
> file is introduced at v0.4.0 to hold the release-notes **draft** ahead of
> tagging; the annotated tag message for `zombie-core-v0.4.0` should mirror the
> entry below. **No tag is created by this change** — Stef gates tagging.

## v0.5.0 — mktd02-v5 (Direct Certification, SR-06)

**DRAFT — not tagged.** Tag `zombie-core-v0.5.0` will carry crate version `0.5.0`
(`Cargo.toml:4`). Tag, crate version, these notes, and downstream pins must state
`0.5.0` identically. MKTd02 v5 Slice 1, Stef ruling 11 Sep 2026 (SR-01/03/05/06,
Q7/Q8).

### Construction change (SR-06)
- **Retired:** `certified_commitment = SHA-256(MKTD02_CERTIFIED_V1 ‖
  post_state_hash ‖ deletion_event_hash)`, the v2–v4 intermediate commitment
  over the deletion event. mktd02-v5 computes and carries no such value; its
  tag `MKTD02_CERTIFIED_V1` is retired.
- **Direct Certification:** the canister's certified_data carries
  `deletion_event_hash` itself, not a commitment over it. Before any deletion
  it holds the genesis value `SHA-256(MKTD02_GENESIS_V1 ‖ canister_id)`.
- **Event hash rebound (ruling A-1(a), 12 Sep 2026, pre-freeze correction):**
  the v5 deletion event now binds the receipt identity —
  `deletion_event_hash = SHA-256(MKTD02_EVENT_V2 ‖ pre_state_hash ‖
  post_state_hash ‖ receipt_id ‖ u64_be(timestamp) ‖ module_hash ‖
  u64_be(deletion_seq))`, a six-part preimage under a **new tag**. A verifier
  recomputes `receipt_id` first, equality-checks it, then recomputes the event
  hash. `deletion_seq` stays an explicit operand although `receipt_id` already
  binds it. `manifest_hash` remains excluded. zombie-core exposes the single
  normative implementation `deletion_event_hash_v5(...)` at the crate root,
  plus `deletion_event_hash_v1(...)` for recomputing issued v2–v4 receipts, so
  neither construction is reimplemented downstream.
- **Unchanged:** `receipt_id` derivation (`MKTD02_RECEIPT_V3`),
  `tombstone_hash`, `state_hash`, genesis, the named rejections, the
  receipt-state rule and label matching.

### Protocol version
- `ProtocolVersion::V5` → `"mktd02-v5"`. Crate `0.4.1` → `0.5.0`, following
  the v0.4.0 precedent (schema-breaking protocol line ⇒ minor bump).
- `"mktd02-v5"` is matched **exactly**. Suffixed or extended labels
  (`"mktd02-v5-x"`, `"mktd02-v50"`, `"mktd02-v5 "`) are unrecognised and
  hard-error. The frozen v2/v3/v4 prefix matching is unchanged.

### Tag registry
- `MKTD02_CERTIFIED_V1` retired (2026-09-11, SR-06): `TAG_CERTIFIED` is now a
  `RetiredTag` in `RETIRED_TAGS`. Any use as a hashing tag fails to compile,
  and `hash_with_tag` debug-asserts against retired tags.
- `RetiredTag::hash_historical(parts)` — tag-first, same discipline as
  `hash_with_tag`; the only sanctioned way to hash under a retired tag, for
  verifying receipts issued under a retired construction (e.g. recomputing a
  v4 `certified_commitment`).
- `MKTD02_GENESIS_V1` added (`TAG_GENESIS`).
- `MKTD02_EVENT_V2` added (`TAG_EVENT_V2`, ruling A-1(a), 12 Sep 2026):
  active and v5-used, the tag of the rebound deletion-event construction.
- `MKTD02_EVENT_V1` (`TAG_EVENT`) **stays active** — not retired. It is the
  tag for recomputing `deletion_event_hash` on issued v2–v4 receipts, and
  joins `MKTD02_RECEIPT_V1` in the "active, other lines" group. It must never
  produce a v5 value.

### v5 CBOR wire — byte strings (ruling A-2(b), 12 Sep 2026)

- On the CBOR path, every byte-valued field of a `mktd02-v5` receipt
  (`receipt_id`, `record_id`, `pre_state_hash`, `post_state_hash`,
  `tombstone_hash`, `deletion_event_hash`, `module_hash`, `bls_certificate`,
  `module_hash_certificate`) is emitted as a **CBOR byte string** (major
  type 2) instead of an array of integers; `canister_id` already was. An
  absent optional stays `null` with its key present.
- Decode tolerance is unchanged: byte string, hex text (optional `0x`, any
  case), or a sequence of integers all still decode. Only the emitted form is
  narrowed.
- **JSON is unchanged** (lowercase hex, textual principal, `null` for absent).
- The v2–v4 wire is untouched: `DeletionReceiptV4` and the V2/V3/V4 wire types
  keep the shared helpers, and the v3 byte goldens and every v4 wire test pass
  unmodified. v5 has its own serialisation helpers.

### Receipt schema (breaking; ruling 11 Sep 2026, amended §3.2/§3.4)
- **No unversioned `DeletionReceipt` any more — compile-breaking by design.**
  Consumers must choose `DeletionReceiptV4` or `DeletionReceiptV5` explicitly;
  there is no alias or deprecated shim, so every existing `DeletionReceipt`
  use fails to compile on bump instead of silently changing meaning.
- `DeletionReceiptV5` is **v5-only** and has no `certified_commitment` (struct,
  CBOR/JSON wire, Candid). No replacement field. A `mktd02-v5` receipt carrying
  a `certified_commitment` key fails to decode with
  `retired-field:certified_commitment` (`ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT`).
- **v5 wire rejects unknown keys (fail-closed)** (ruling 1d, 12 Sep 2026). Any
  key outside the v5 schema (e.g. `nonce`, `subnet_id`) is a hard decode error
  (`unknown field`), so no unauthenticated data rides alongside a v5 receipt.
  `certified_commitment` is still rejected by name, not as an unknown key.
  Structural serde errors (unknown key, bad hex, missing required field) are
  reported before the named checks (protocol, retired-field, zero-hash). The
  frozen v2–v4 decode is unchanged and still tolerates unknown keys.
- The v0.4.1 struct is frozen verbatim as `DeletionReceiptV4` (protocol_version
  v2, v3, v4): decode, serialise, `state()` and all v2–v4 goldens unchanged,
  byte-identical. Consumers decoding issued v2–v4 receipts switch to this type.
- Parsing dispatches on `protocol_version`: each type refuses the other's labels.
- `AnyDeletionReceipt { V4(DeletionReceiptV4), V5(DeletionReceiptV5) }` for
  callers holding a receipt of unknown line: `from_json_value` (generic over
  an owned self-describing value such as `serde_json::Value`; no runtime
  `serde_json` dependency) and `from_cbor` read `protocol_version`, then decode
  with that line's type, surfacing its named errors unchanged. Unknown labels
  hard-error. Accessors `protocol_version()`, `receipt_id()`, `state()`.

### Receipt-state rule
- The three-state rule (`Pending` / `FinalizedCandidate` /
  `InvalidIncompleteFinalization`) is extended explicitly to v5
  (`DeletionReceiptV5::state()`, `ReceiptSummary: From<&DeletionReceiptV5>`). v4
  classification (`DeletionReceiptV4::state()`) unchanged; v2/v3 keep
  single-certificate semantics.

### Golden vectors
- The deletion-path `certified_commitment` golden (`932e7b4e…`) and the
  `MKTD02_CERTIFIED_V1` tag golden (`b2a533ef…`) are **retired**, retained under
  `v4_historical` test modules (digests unchanged). No v5 golden digests yet
  (slice 3). All other goldens unchanged.

### Named rejections
- `retired-field:certified_commitment` — v5 receipt carrying the key (decode).
- `invalid-event-hash:zero` — v5 receipt with all-zero `deletion_event_hash`,
  refused on both decode and serialise (symmetric). The frozen v4 path does
  not apply this check.
- `no-deletion-certified` — verifier-side `check_certified_data_not_genesis`:
  certified_data equals `genesis_certified_data(canister_id)`.
- Serialise refusal aligned to the §7 fragment freeze (Gate G / B1): a
  `DeletionReceiptV5` with an unrecognised label now refuses serialisation with
  `unrecognised protocol_version`, as decode does; a wrong-line (v2–v4) label
  keeps `… is not mktd02-v5; refusing to serialise`. Message text only.

## v0.4.1 — normative finalization-delay threshold

**DRAFT — not tagged.** Tag `zombie-core-v0.4.1` will carry crate version `0.4.1`
(`Cargo.toml:4`). Tag, crate version, these notes, and downstream pins must state
`0.4.1` identically — the v0.3.1-tag/0.3.0-crate mismatch is the standing lesson.

### Added
- `MAX_FINALIZATION_DELAY_NS` (normative, G ruling 15 Jul 2026). No wire/schema
  change. The threshold (3,600 s in ns) is interpreted authoritatively by
  CVDR-Verify; `delta > MAX_FINALIZATION_DELAY_NS` is a `DELAY_EXCEEDED`
  downgrade (not receipt rejection), `delta < 0` is an ordering failure. Placed
  in `protocol` module, re-exported at crate root.

### Unchanged
- No receipt-schema, serialized-wire, preimage, domain-tag, receipt-ID, or
  golden-vector change. v4 three-state semantics untouched. No dependency bumps.

## v0.4.0 — mktd02-v4 schema (subnet-attested code identity)

**Tag/crate/notes agreement (G ruling):** tag `zombie-core-v0.4.0` will carry
crate version `0.4.0` (`Cargo.toml`). Tag, crate version, these notes, and all
downstream pins must state `0.4.0` identically — the v0.3.1-tag/0.3.0-crate
mismatch is not repeated.

### Added
- `ProtocolVersion::V4` → `"mktd02-v4"`.
- `DeletionReceipt.module_hash_certificate: Option<Vec<u8>>` — raw certificate
  from a `read_state` over `/canister/<id>/module_hash`. Present only on v4
  receipts; `None` for v2/v3. Serialised with the same hex pattern as
  `bls_certificate`, `#[serde(default)]` on decode.
- `ReceiptState` enum + `DeletionReceipt::state()` — three-outcome
  classification (G ruling): `Pending` (neither certificate),
  `FinalizedCandidate` (both), `InvalidIncompleteFinalization` (exactly one).
- `ReceiptSummary.state` reflects the classification.

### Fixed (hazard)
- **Version-dispatched serialisation.** The receipt wire dispatch no longer
  uses `starts_with("mktd02-v3")` with a silent `else`-to-V2 fallback. An
  unrecognised `protocol_version` is now a **hard error** on both serialise and
  deserialise — it can no longer silently degrade to the legacy V2 wire shape
  (which dropped `record_id`, set `subnet_id = anonymous`, and renamed
  `deletion_seq → nonce`). `"mktd02-v4"` routes to the V4 wire; `"mktd02-v3"`
  output is **byte-identical** to v0.3.x (golden vector locked).

### Unchanged (no hash-preimage changes)
- `receipt_id` derivation — still `(canister_id, record_id, deletion_seq)`.
- `deletion_event_hash` and `certified_commitment` preimages.
- Golden vectors prove all three are identical whether certificates are present
  or absent.

### Compatibility
- Clean protocol break (no MKTd02/MKTd03 deployed): no migration, no dual-format
  support. Existing v2/v3 receipts still decode; v3 bytes are unchanged.

### Downstream pins to update (separately, when gated)
- `ICP-Delete-Leaf/mktd02` and `CVDR-Verify` pin `zombie-core` by git tag;
  bump them to `tag = "zombie-core-v0.4.0"` after the tag exists.
