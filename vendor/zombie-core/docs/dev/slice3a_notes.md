# MKTd02 v5 Slice 3a — implementer notes (zombie-core)

- **Repo / branch:** `zombie-core`, branch `v5`.
- **Base:** `ac5c32d`; the authority `docs/dev/MKTd02_v5_Slice3a_Pre_Freeze_Corrections_Spec.md` landed at `2859fe4`.
- **Scope implemented here:** §1–§4 and the zombie-core lines of §5. Leaf is untouched and moves in lockstep in a later session (authority §4 "Leaf", §5 second bullet).
- **Rulings:** A-1(a) and A-2(b) (Stef + G, 12 Sep 2026), plus the T3a-4 amendment (G, 12 Sep 2026): major type 2 is asserted **semantically**, not by lead-byte pattern.
- **Untouched, as instructed:** the two uncommitted phase-1 files `docs/spec/mktd02-v5-serialization.md` and `docs/dev/slice3_phase1_findings.md` remain uncommitted and unmodified.

## 1. Item → commit map

| Item | SHA | Summary |
|---|---|---|
| 1 | `e22a04b` | `MKTD02_EVENT_V2` in the registry, active and v5-used; `MKTD02_EVENT_V1` stays active, grouped "other lines" |
| 2 | `77c7081` | crate-root `deletion_event_hash_v5(...)`; `deletion_event_hash_v1(...)` for the historical lines |
| 3 | `d82b3f8` | v5-only CBOR byte strings; V4's shared helpers untouched |
| 4 | `e6eb030` | T3a-1…6 (126 → 134 tests) |
| 5 | `b50a70a` | `RELEASES.md` v0.5.0 DRAFT entry; `hashing.rs` registry doc table; README module table |
| — | `bdb1369` | these notes |
| 6 | (this commit) | `TAG_EVENT_V2` re-exported at the crate root (U-7 ruling, 13 Sep 2026) |

## 2. The serialisation helper split (item 3), before and after

**Before.** One module, `serde_hex_bytes`, served every line. `DeletionReceiptV5Wire` / `DeletionReceiptV5RawWire` pointed at exactly the same six functions as `DeletionReceiptV4` and the V2/V3/V4 wire types:

```rust
// V5Wire, before
#[serde(serialize_with = "serde_hex_bytes::serialize_array_32")]
receipt_id: [u8; 32],
...
#[serde(serialize_with = "serde_hex_bytes::serialize_option_vec")]
bls_certificate: Option<Vec<u8>>,

// the shared helper, unchanged by this slice
pub fn serialize_array_32<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(value))   // JSON: lowercase hex
    } else {
        value.serialize(serializer)                     // CBOR: array of 32 uints
    }
}
```

**After.** A second module, `serde_bytes_v5`, is used by the V5 wire/raw types only. The JSON arm is identical; the CBOR arm emits a byte string:

```rust
// V5Wire, after
#[serde(serialize_with = "serde_bytes_v5::serialize_array_32")]
receipt_id: [u8; 32],
...
#[serde(serialize_with = "serde_bytes_v5::serialize_option_vec")]
bls_certificate: Option<Vec<u8>>,

// the new, v5-only helper
pub fn serialize_array_32<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(value))   // JSON: unchanged
    } else {
        serializer.serialize_bytes(value)               // CBOR: major type 2
    }
}
```

`Option` needed one extra piece: `serialize_some` takes a `Serialize`, so a private `ByteStr(&[u8])` wrapper carries the byte-string form through it. `None` still goes through `serialize_none`, so an absent optional stays `null` with its key present.

Decode delegates: `serde_bytes_v5::deserialize_*` call straight into the shared visitors, so byte strings, hex text (optional `0x`, any case) and sequences of integers all still decode. Only the **emitted** form narrowed — the authority's §3 explicitly permits keeping that tolerance.

**Isolation evidence (authority §3, CD item 4):**

- `serde_hex_bytes` is not modified; the V2/V3/V4 wire and raw types still point at it.
- Exactly 18 attribute lines moved (9 `serialize_with`, 8 `deserialize_with`, plus `deserialize_some_vec`'s body). Reference count `serde_hex_bytes::` 102 → 87 = −18 + 3 delegation lines in the new module.
- `git diff ac5c32d -- src/receipt.rs` filtered to the v3 goldens, their fixture and every v4 wire/state test body is **empty**.
- `t3a6_frozen_v4_wire_still_encodes_arrays_not_byte_strings` asserts the complement directly: the v4 wire still emits CBOR arrays.

## 3. Quality gate

Same at every commit (`cargo +stable` is used because the default 1.97.1 toolchain carries no rustfmt/clippy components — same rustc):

| Check | Result |
|---|---|
| `cargo +stable fmt --all -- --check` | clean |
| `cargo +stable clippy --all-targets -- -D warnings` | clean |
| `cargo +stable clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test` / `cargo test --all-features` | 134 passed (126 before item 4), plus 2 compile_fail doctests |
| `cargo audit` | exit 0; 1 allowed warning, RUSTSEC-2024-0436 (`paste`, unmaintained, via `candid`) — pre-existing |
| New dependencies | none (`Cargo.toml` untouched) |

## 4. Mandated frozen-wire verification (run before the last commit)

Tests run by name, all passing: `v3_cbor_byte_identical_to_head_golden`, `v3_json_byte_identical_to_head_golden`, `v3_output_omits_module_hash_certificate_field`, `v3_json_serializes_portable_bytes_as_hex_strings`, `v3_json_deserializes_hex_strings_for_portable_bytes`, `v4_cbor_round_trip_preserves_record_id_and_both_certificates`, `v4_json_round_trip_preserves_record_id_and_both_certificates`, `v4_without_module_hash_certificate_decodes_as_pending`, `v4_type_refuses_v5_wire`, `t1d_v4_unknown_key_tolerance_unchanged`, `t1b7_frozen_v4_prefix_arm_unchanged`, `legacy_v2_cbor_decodes_safely_to_v3_shape`, `legacy_v3_cbor_decodes_with_default_none`, and both `v4_historical` goldens.

Body identity: `git diff ac5c32d -- src/receipt.rs` restricted to those test bodies, their fixtures (`golden_v3_receipt`, `test_receipt_v4`) and the golden constants (`V3_CBOR_HEX`, `V3_JSON`) returns **nothing**.

## 5. Unanticipated, and decisions taken (reported, not resolved)

- **U-1 No helper to rename.** §1's parenthetical assumed zombie-core might already expose a v1-preimage helper. It did not — the v2–v4 preimage was only ever built inline in the Leaf engine. Per the session ruling, `deletion_event_hash_v1` was **created**, so neither construction is reimplemented downstream. **RULED 13 Sep 2026: accepted as implemented.**
- **U-2 Tag constant naming.** `TAG_EVENT` was **not** renamed to `TAG_EVENT_V1`; `TAG_EVENT_V2` was added beside it. This follows the house `TAG_RECEIPT` / `TAG_RECEIPT_V3` precedent and keeps the rev-pinned Leaf build compiling until it moves in lockstep. The tag *bytes* are exactly as ruled. **RULED 13 Sep 2026: accepted as implemented.**
- **U-3 Registry-invariant arrays moved in item 1, not item 4.** `domain_tags_are_distinct`, `tombstone_seed_differs_from_all_tags` and `no_active_tag_is_retired` gained the new tag in item 1, so that commit is self-consistent; T3a-3 is the new dedicated test in item 4.
- **U-4 T3a-6 was given real content.** Re-asserting the v3 goldens would only have duplicated existing tests, so T3a-6 asserts the complement invariant (v4 still encodes arrays). Byte-identity itself stays pinned by the unmodified goldens plus the diff in §4.
- **U-5 T3a-4 needed a CBOR reader.** The amended semantic assertion required parsing, so the test module gained `cbor_map_fields` (a definite-length map walker returning each key with its exact value extent) and `assert_cbor_byte_string` (major type 2; declared length == payload length in whichever form; encoded extent; payload == field value). Test-only, no new dependencies. It also covers `canister_id` (already a byte string) and the pending/`null` case.
- **U-6 `MKTD02_MANIFEST_V1` placement — RULED 13 Sep 2026.** Already settled by the phase-1 ratification list (F-2): it is **active, "other lines"**, and `gv5-010` covers the **v5-used set only**. The registry grouping in `hashing.rs` is confirmed correct as written, and phase-1 finding D-3 is answered.
- **U-7 `TAG_EVENT_V2` crate-root export — RULED 13 Sep 2026: yes.** Re-exported at the crate root in item 3a.6 (this commit) for symmetry with `TAG_GENESIS`. Calling the helper remains the normative path for producing the value; the tag is exported so consumers can name it without reaching into `hashing::`.
- **U-8 The phase-1 formula text is now stale in two places.** The uncommitted draft's §3.4 (five-part preimage under `MKTD02_EVENT_V1`) and §4.2 (32-byte fields as arrays of uints) describe what this slice just replaced, and its flags F-5 and F-8 change meaning. Per authority §5 and the closing line, amending it is **phase 1b**, not this slice; the file was left untouched and uncommitted. **RULED 13 Sep 2026: expected; amended in phase 1b. No action here.**
- **U-9 zombie-core and Leaf now disagree until Leaf moves.** This crate's normative v5 helper binds `receipt_id` under `MKTD02_EVENT_V2`; the pinned Leaf engine still computes the old five-part `MKTD02_EVENT_V1` preimage inline. That is the planned lockstep, but until Leaf re-pins and calls `deletion_event_hash_v5`, a v5 receipt produced by the engine will not match this crate's helper. **RULED 13 Sep 2026: expected; Leaf moves next and pins the 3a.6 tip. No action here.**
- **U-10 Any v5 CBOR bytes captured before `d82b3f8` are stale.** The v5 wire changed shape. Nothing is published (`mktd02-v5` is lab-only, both crates DRAFT/untagged), and no v5 byte golden exists yet — the first ones are phase-2 vectors.
- **U-11 CI does not enforce this gate.** `.github/workflows/ci.yml` runs `cargo fmt --check` and `cargo test` on push/PR to `main` only — not on `v5` — and runs neither clippy nor audit. Pre-existing, already filed for slice 6; unchanged here.
