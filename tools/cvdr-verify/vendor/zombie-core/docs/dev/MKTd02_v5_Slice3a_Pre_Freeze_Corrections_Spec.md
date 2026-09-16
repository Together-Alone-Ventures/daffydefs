# MKTd02 v5 Slice 3a — Pre-Freeze Construction Corrections: Specification

**Status:** normative authority for Slice 3a, 12 Sep 2026. Rulings A-1(a) with `MKTD02_EVENT_V2`, A-2(b) (Stef + G, 12 Sep 2026, on C's phase-1 ratification list). **Hard gate:** Slice 3 phase 1b (ratified formula text) lands only on this slice's CD PASS; phase 2 starts after that.
**Base:** zombie-core `v5` @ `ac5c32d`; ICP-Delete-Leaf `v5` @ `b64abbd`.
**Scope — exactly five items, nothing else:**
1. `receipt_id` bound into the v5 deletion-event preimage.
2. New tag `MKTD02_EVENT_V2` for that construction; `MKTD02_EVENT_V1` retained, active, for historical lines only.
3. v5 CBOR: every byte-valued field is a CBOR byte string (major type 2).
4. Tests and construction-level assertions for 1–3.
5. Frozen v2–v4 wire, formulas and goldens **byte-identical** — proven, not assumed.

No version-string change (`mktd02-v5` has been issued nowhere but the lab; both crates remain DRAFT/untagged). No JSON change. No change to `receipt_id`, `tombstone_hash`, `state_hash`, genesis, the named rejections, the receipt-state rule, or label matching.

---

## 1. Deletion-event hash, v5 (ruling A-1(a))

```text
deletion_event_hash_v5 = hash_with_tag(
  "MKTD02_EVENT_V2",
  [ pre_state_hash,
    post_state_hash,
    receipt_id,
    u64_be(timestamp),
    module_hash,
    u64_be(deletion_seq) ]
)
```

- `receipt_id` is the §3.5 value (`MKTD02_RECEIPT_V3` over length-delimited `canister_id`, `record_id`, `deletion_seq`), computed **before** the event hash.
- `deletion_seq` stays as an explicit operand even though it is inside `receipt_id`. Intentional redundancy; not a reason to redesign.
- `manifest_hash` is not in the preimage and must never be added.
- **Verification order consequence (V1):** a verifier recomputes `receipt_id` from `(canister_id, record_id, deletion_seq)` and equality-checks it against the displayed field **first**, then uses it to recompute `deletion_event_hash`. V2 continues to authenticate the resulting event hash against `certified_data`.

**Single normative implementation.** zombie-core exposes `deletion_event_hash_v5(pre, post, receipt_id, timestamp, module_hash, deletion_seq) -> [u8;32]` at the crate root. The Leaf engine calls it; it does not reimplement the preimage. (If zombie-core already exposes a v1-preimage helper used by Leaf, that helper is renamed to make its line explicit and left otherwise untouched.)

## 2. Tag registry

- Add `MKTD02_EVENT_V2` (exact ASCII, 15 bytes, no terminator) as an active, v5-used tag.
- `MKTD02_EVENT_V1` stays **active** (not retired): it is used to recompute `deletion_event_hash` for issued v2–v4 receipts. It joins `MKTD02_RECEIPT_V1` in the "active, other lines" group. It must never produce a v5 value — enforced by the engine calling only the v5 helper, and pinned by a test that the v5 helper's output differs from the V1-tag construction over identical inputs.
- Registry doc table and any "used for" columns updated; `RELEASES.md` v0.5.0 DRAFT entry amended ("Construction change" gains the event-hash change and the new tag).

## 3. v5 CBOR byte strings (ruling A-2(b))

For `DeletionReceiptV5` **only**, in the CBOR (non-human-readable) path: `receipt_id`, `record_id`, `pre_state_hash`, `post_state_hash`, `tombstone_hash`, `deletion_event_hash`, `module_hash`, `bls_certificate`, `module_hash_certificate` encode as CBOR **byte strings** (major type 2). `canister_id` already does. Absent optionals stay `null` with the key present. Decode accepts the byte-string form; the ruled tolerance for byte-array inputs (F-12) may remain on decode if it costs nothing, but the **emitted** form is byte strings only.

**Isolation requirement.** `DeletionReceiptV4` and its wire/raw types share serialisation helpers with V5 today. Those shared helpers are **not** modified. V5 gets its own helpers (or per-field `serialize_with`/`deserialize_with` on the V5 wire/raw types). The v3 CBOR byte golden and every v4 wire test must remain byte-identical — CD proves it by running them and by diffing the V4 code paths against the base.

JSON is unchanged: lowercase hex, textual principal, `null` for absent — the existing V5 JSON tests pass untouched.

## 4. Tests (construction-level; no published digests — those are phase 2/3)

zombie-core:
- T3a-1 `deletion_event_hash_v5` is tag-first over the six parts in order; changing any single part changes the output; swapping `pre`/`post` changes the output.
- T3a-2 v5 output ≠ `hash_with_tag(MKTD02_EVENT_V1, [pre, post, ts, module, seq])` over the same inputs (domain separation between lines).
- T3a-3 `MKTD02_EVENT_V2` exact ASCII, no null byte, distinct from every other active and retired tag.
- T3a-4 Every v5 byte-valued field emits CBOR major type 2 — assert on the raw bytes (the initial byte of each field value is `0x58 0x20` for 32-byte fields, `0x4X`/`0x58 NN` for shorter/longer), not merely on round-trip.
- T3a-5 v5 CBOR round-trip; v5 JSON tests unchanged and passing.
- T3a-6 Existing v3 CBOR/JSON byte goldens and all v4 wire/state tests pass **unmodified** (their bodies byte-identical to base — CD diffs them).

Leaf:
- Engine computes `receipt_id` before the event hash and calls the zombie-core v5 helper. Any inline expectation of the old preimage in Leaf tests is updated to call the helper (no hand-computed digests).
- T6/T7/T8a/T8b/T9/T10 rerun green; helper 27+ green; PocketIC 7/7.
- A test that the stored/exported v5 receipt's `deletion_event_hash` equals `deletion_event_hash_v5(...)` recomputed from the receipt's own fields including its `receipt_id` (V1 as the verifier will do it).

## 5. Documentation touched (and only these)

- zombie-core `RELEASES.md` v0.5.0 DRAFT entry; tag-registry doc table in `hashing.rs`; README module table if it lists tags.
- Leaf `RELEASES.md` v0.6.0 DRAFT entry; the README "Key Invariants" block gains the v5 event-hash formula beside the existing `receipt_id` line; `docs/sections/10-verification.md` V1 bullet gains the recompute order (receipt_id first).
- The formula text draft (uncommitted) is amended by CC in phase 1b, not here.

## 6. CD delta checklist

1. Diff zombie-core `src/` and Leaf `mktd02/src/` against base: changes confined to the event-hash helper/tag, the V5 serialisation helpers, the engine call order, tests and the listed docs.
2. `MKTD02_EVENT_V2` present, exact bytes; `MKTD02_EVENT_V1` still active; no retirement entry added.
3. Engine: `receipt_id` computed before `deletion_event_hash`; the event hash comes from the zombie-core v5 helper; grep finds no other event-hash construction in Leaf.
4. **Byte-for-byte:** for a finalized and a pending v5 fixture, dump the CBOR and show each byte-valued field's leading byte is major type 2; JSON output identical to base for the same fixtures (diff the strings); the v3 CBOR and JSON goldens and every v4 test body unchanged (diff against base) and passing.
5. T3a-1…6 present and passing; Leaf suites green (root ±features, helper, harness wasm, PocketIC).
6. No version-string change; both RELEASES entries still DRAFT/untagged; no JSON change; no change to any other construction.
7. Verdict: CONFORMANT / NOT CONFORMANT.

On PASS: phase 1b — CC amends the formula text (§3.4 → V2 construction and tag; §4.2 → byte strings; origins per the ratification list; lock gate), commits text + findings + rulings together with the ratification line, and phase 2 begins.
