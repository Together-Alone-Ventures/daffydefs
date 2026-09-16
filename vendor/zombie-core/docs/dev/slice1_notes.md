# MKTd02 v5 Slice 1 (Direct Certification) — implementer notes

- **Repo / branch:** `zombie-core`, branch `v5`, cut from `main` @ `27d508f`.
- **Code tip:** `5b332c6` (item 3.6). This notes file is committed on top of it.
- **Spec:** MKTd02 v5 Slice 1, Stef-ruled 11 Sep 2026 under SR-01/03/05/06, Q7/Q8.
- **Amending ruling (Stef, via C, 11 Sep 2026):** Option 1, frozen v4 type.
  §3.2/§3.4 amended to: keep the v0.4.1 struct verbatim as `DeletionReceiptV4`
  (v2/v3/v4), with a new v5-only `DeletionReceipt`. Parsing dispatches on
  `protocol_version`. A v5 label carrying `certified_commitment` fails with
  `retired-field:certified_commitment`. §3.6(a) is a v5-labelled receipt with the key.
  Baseline: fmt-only commit first, then a clippy commit only if the fixes are
  mechanical.

## 1. Commits

| SHA       | Item   | Summary |
|-----------|--------|---------|
| `8ea41e1` | chore  | fmt baseline (pre-existing on main) — `cargo fmt` only |
| `8ac3ff9` | chore  | clippy baseline (pre-existing on main) — 2 `#[allow]` attributes |
| `0a14100` | 3.1    | tag registry: retire `MKTD02_CERTIFIED_V1` (SR-06), add `MKTD02_GENESIS_V1` |
| `5eee62d` | 3.3    | protocol version `mktd02-v5` and version note |
| `937dcf7` | 3.2    | v5-only `DeletionReceipt`; v0.4.1 struct frozen as `DeletionReceiptV4` |
| `2b4fd18` | 3.4    | three-state rule extended explicitly to v5 |
| `605449b` | 3.5    | deletion-path `certified_commitment` golden moved under the v4-historical marker |
| `5b332c6` | 3.6    | negatives: retired-field, no-deletion-certified, invalid-event-hash:zero |

**3.3 was committed before 3.2** (see U-10).

## 2. Quality gate

| Check | `main` @ 27d508f | tip @ 5b332c6 |
|---|---|---|
| `cargo +stable fmt --all -- --check` | **FAIL** (19 hunks: lib.rs, nns_keys.rs, receipt.rs) | clean |
| `cargo +stable clippy --all-targets --all-features` | **FAIL**: 1 error `clippy::approx_constant` (serialisation.rs:174), 1 warning `unreachable_code` (nns_keys.rs:184) | clean with `-D warnings` |
| `cargo +stable clippy --all-targets` | clean | clean with `-D warnings` |
| `cargo test --all-features` / `cargo test` | 89 pass | 113 pass (plus 1 compile_fail doctest) |
| `cargo test --release --all-features` | — | 112 pass (the debug-only guard test is compiled out) |
| `cargo audit` | exit 0; 1 allowed warning RUSTSEC-2024-0436 (`paste` unmaintained, via `candid`) | identical |
| New deps | — | none (`Cargo.toml` diff is the version line only) |
| New `unsafe` | — | none (`grep unsafe src/` is empty) |

The local default toolchain (1.97.1) has no rustfmt/clippy components, so I
used `cargo +stable`, which is the same rustc (1.97.1 8bab26f4f).

Baseline commits:
- `8ea41e1` fmt: verified semantics-free. nns_keys.rs and receipt.rs are
  identical modulo whitespace and trailing commas. lib.rs has an identical
  line multiset (one `use` reordered).
- `8ac3ff9` clippy: both fixes are lint suppressions, with no logic or value change:
  - `src/serialisation.rs` `rejects_float`: `#[allow(clippy::approx_constant)] // 3.14 is arbitrary float test data, not PI`
  - `src/nns_keys.rs` `active_key_id`: `#[allow(unreachable_code)]` (the tail after the `cfg(local-replica)` early return)

**Hygiene finding for slice 6 (not fixed here):** `main` was not fmt/clippy
clean, yet `.github/workflows/ci.yml` runs `cargo fmt --all -- --check` on push
and PR to main. CI is evidently not enforcing it. CI also runs neither clippy
nor `cargo audit`.

## 3. Sites changed, with before/after excerpts

### 3.1 Tag registry (`0a14100`)

`src/hashing.rs` module-doc naming table (~:12). The active row was removed
and moved to a new Retired table (~:21):
```
before: //! | MKTD02_CERTIFIED_V1        | Domain tag     | Tag for certified_commitment                  | certified.rs     |
after:  //! | MKTD02_GENESIS_V1          | Domain tag     | Tag for v5 genesis certified_data (verifier)  | receipt.rs       |
        //! ## Retired Tags ...
        //! | MKTD02_CERTIFIED_V1        | 2026-09-11     | SR-06  | certified_commitment (mktd02-v2..v4)      |
```
`src/hashing.rs:101` / `:108` / `:83` (the constant changes type, it is not deleted):
```
before: pub const TAG_CERTIFIED: DomainTag = DomainTag(b"MKTD02_CERTIFIED_V1");
after:  pub struct RetiredTag { pub bytes, pub retired_on, pub ruling }
        pub const TAG_CERTIFIED: RetiredTag = RetiredTag {
            bytes: b"MKTD02_CERTIFIED_V1", retired_on: "2026-09-11", ruling: "SR-06" };
        pub const RETIRED_TAGS: &[RetiredTag] = &[TAG_CERTIFIED];
```
`src/hashing.rs:71`:
```
after:  pub const TAG_GENESIS: DomainTag = DomainTag(b"MKTD02_GENESIS_V1");
```
`src/hashing.rs:130`, `hash_with_tag` (guard added; output unchanged):
```
after:  debug_assert!(!RETIRED_TAGS.iter().any(|r| r.bytes == tag.0),
                      "hash_with_tag: retired domain tag {}", ...);
```
`src/hashing.rs` tests, `domain_tags_are_distinct` and `tombstone_seed_differs_from_all_tags`:
```
before: TAG_EVENT, TAG_CERTIFIED, TAG_RECEIPT, ... TAG_MANIFEST,
after:  TAG_EVENT, TAG_RECEIPT, ... TAG_MANIFEST, TAG_GENESIS,
```
`src/hashing.rs` `golden_tag_certified` moved to `tests::v4_historical` (:386). The digest is unchanged:
```
before: hex::encode(hash_with_tag(TAG_CERTIFIED, &[b"test"]))                 == "b2a533ef…cf5c"
after:  hex::encode(sha256_concat(&[TAG_CERTIFIED.bytes, b"test"]))            == "b2a533ef…cf5c"
```
`src/receipt.rs` golden (then at :1454/:1473). This was a forced adaptation:
its ad-hoc retired `DomainTag` tripped the new guard, and I observed it fail
before adapting. Digest unchanged:
```
before: const TAG_CERTIFIED: DomainTag = DomainTag(b"MKTD02_CERTIFIED_V1");
        let certified = hash_with_tag(TAG_CERTIFIED, &[&post, &event]);
after:  use crate::hashing::{sha256_concat, DomainTag, TAG_CERTIFIED};
        let certified = sha256_concat(&[TAG_CERTIFIED.bytes, &post, &event]);
```

### 3.3 Protocol version (`5eee62d`)

`src/receipt.rs:229`, `:238`, `:250`:
```
after:  V5,                                          // enum variant, doc cites SR-06
        ProtocolVersion::V5 => "mktd02-v5",
        if protocol_version.starts_with("mktd02-v5") { Some(ProtocolVersion::V5) } else if …v4…
```
The frozen type's three exhaustive matches (`DeletionReceiptV4::state` :440,
`TryFrom` :827, `Serialize` :898). A v5 label is folded into the pre-existing
`None` arm, so the behaviour and error text match what that then-unrecognised
string produced before v5 existed:
```
before: None => ReceiptState::InvalidIncompleteFinalization,
after:  Some(ProtocolVersion::V5) | None => ReceiptState::InvalidIncompleteFinalization,
before: None => Err(format!("DeletionReceipt: unrecognised protocol_version {:?}; …
after:  Some(ProtocolVersion::V5) | None => Err(format!("DeletionReceipt: unrecognised protocol_version {:?}; …
```
`Cargo.toml:4`: `version = "0.4.1"` → `version = "0.5.0"`.
`RELEASES.md`: new `## v0.5.0 — mktd02-v5 (Direct Certification, SR-06)` DRAFT
version note (construction change, protocol version, tag registry). No tag was created.

### 3.2 Receipt schema (`937dcf7`)

`src/receipt.rs`: mechanical rename `DeletionReceipt` → `DeletionReceiptV4`
across 45 lines (struct, impls, doc links, tests). Verified: every changed
pre-existing line is a pure substitution. Error-message literals
`"DeletionReceipt: …"` are kept verbatim.
```
before: pub struct DeletionReceipt {            // with certified_commitment
after:  /// Deletion receipt covering protocol_version v2, v3 and v4 (frozen by ruling, 11 Sep 2026). …
        pub struct DeletionReceiptV4 {          // byte-for-byte same fields/attrs
```
New v5 section, `src/receipt.rs:907`–`:1180`:
```
after:  pub const ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT: &str = "retired-field:certified_commitment";
        #[serde(try_from = "DeletionReceiptV5RawWire")]
        pub struct DeletionReceipt { …V4 fields minus certified_commitment… }   // :955, CandidType derived
        struct DeletionReceiptV5Wire { … }        // :1004, serialise shape, no certified_commitment
        struct DeletionReceiptV5RawWire { …       // :1038, decode shape
            #[serde(default, rename = "certified_commitment")]
            #[serde(deserialize_with = "deserialize_key_present")]
            certified_commitment_present: bool }  // key presence only, any value incl. null
        impl TryFrom<DeletionReceiptV5RawWire> for DeletionReceipt   // :1090
            // non-v5 label -> error; v5 + key -> ERR_RETIRED_FIELD_…; missing record_id/deletion_seq -> error
        impl Serialize for DeletionReceipt         // :1148, non-v5 label -> hard error
```
Module docs: `src/receipt.rs:8`–`:18` (v2–v4 qualifier and a "v0.5.0 Changes" section).
`src/lib.rs:21`:
```
before: pub use receipt::{compute_receipt_id, DeletionReceipt, ProtocolVersion, ReceiptSummary};
after:  pub use receipt::{
            compute_receipt_id, DeletionReceipt, DeletionReceiptV4, ProtocolVersion, ReceiptSummary,
        };
```
`RELEASES.md`: "Receipt schema" section.

### 3.4 Receipt-state rule (`2b4fd18`), additions only

`src/receipt.rs:275` `ReceiptState` doc: "Scope: the three-state rule applies
to **v4** (…unchanged) and, explicitly, to **v5**…".
`src/receipt.rs:980` `impl DeletionReceipt { pub fn state() }` (v5 three-state;
a non-v5 label gives `InvalidIncompleteFinalization`).
`src/receipt.rs:471` `impl From<&DeletionReceipt> for ReceiptSummary`.
`DeletionReceiptV4::state()` is not modified in this commit.
`RELEASES.md`: "Receipt-state rule" section.

### 3.5 Goldens (`605449b`)

`golden_event_and_certified_preimages_cert_independent` (spec "receipt.rs:~1430";
:1450 after fmt, :1738 before the move) moved verbatim (re-indented only) to
`receipt::tests::v4_historical` (`src/receipt.rs:2290`/`:2298`) under a
`/// v4-HISTORICAL — retired pins (SR-06, 11 Sep 2026; spec item 3.5)` marker.
Digests unchanged. No v5 digests generated. `RELEASES.md`: "Golden vectors" section.

### 3.6 Negatives (`5b332c6`)

`src/receipt.rs:38` import: `+ TAG_GENESIS, ZERO_HASH`.
`src/receipt.rs:917`–`:941`:
```
after:  pub const ERR_INVALID_EVENT_HASH_ZERO: &str = "invalid-event-hash:zero";
        pub const ERR_NO_DELETION_CERTIFIED: &str = "no-deletion-certified";
        pub fn genesis_certified_data(canister_id: &Principal) -> [u8; 32] {
            hash_with_tag(TAG_GENESIS, &[canister_id.as_slice()]) }          // verifier-side only
        pub fn check_certified_data_not_genesis(canister_id, certified_data: &[u8])
            -> Result<(), &'static str>                                      // Err(ERR_NO_DELETION_CERTIFIED)
```
`src/receipt.rs:1114` (v5 `TryFrom`, after the retired-field check):
```
after:  if w.deletion_event_hash == ZERO_HASH { return Err(ERR_INVALID_EVENT_HASH_ZERO.to_string()); }
```
`RELEASES.md`: "Named rejections" section.

### Complete accounting

Relative to the fmt baseline `8ea41e1` (base renamed `DeletionReceipt` →
`DeletionReceiptV4`), the only pre-existing lines changed anywhere are those
quoted above. Every other pre-existing function body is byte-identical modulo
the rename: 71 fns in receipt.rs, 20 in hashing.rs, including every v2/v3/v4
wire, golden, round-trip, T-1/T-2/T-3 and state test.

## 4. Where each item is observable

| Item | Code | Tests / evidence |
|---|---|---|
| 3.1 retired + registry | `hashing.rs:21` (doc), `:83`, `:101`, `:108` | `retired_tag_certified_is_registered`, `no_active_tag_is_retired` |
| 3.1 "any use fails compile" | `TAG_CERTIFIED: RetiredTag` | doctest on `TAG_CERTIFIED` (`compile_fail,E0308`); I also confirmed out-of-band that the snippet fails with `E0308 expected DomainTag, found RetiredTag` |
| 3.1 "any use fails test" | `hashing.rs:130` `debug_assert!` | `hash_with_tag_rejects_rebuilt_retired_tag` (`should_panic`, debug only); the unadapted receipt.rs golden failed under it before 3.1 adapted it |
| 3.1 GENESIS tag | `hashing.rs:71` | `tag_genesis_is_exact_ascii_without_terminator`, `tag_genesis_follows_hash_with_tag_discipline`, both distinctness tests |
| 3.2 field removed | `receipt.rs:955`, `:1004` | `v5_json_keys_exclude_certified_commitment`, `v5_cbor_keys_exclude_certified_commitment`, `candid_type_v5_excludes_certified_commitment_v4_keeps_it`, `v5_cbor_round_trip`, `v5_json_round_trip_uses_hex_bytes` |
| 3.2 dispatch | `receipt.rs:1090`, `:1148`; V4 arms `:827`, `:898` | `v5_type_refuses_v2_v3_v4_labels`, `v4_type_refuses_v5_wire` |
| 3.2 v4 frozen | `receipt.rs:320` | all pre-existing v2–v4 tests unchanged modulo rename, incl. `v3_cbor_byte_identical_to_head_golden`, `v3_json_byte_identical_to_head_golden` |
| 3.3 version | `receipt.rs:229`, `:238`, `:250`; `Cargo.toml:4`; `RELEASES.md` | `protocol_version_v5_serialises_correctly`, `v5_label_on_cc_bearing_type_behaves_as_before_v5`; pre-existing `unrecognised_protocol_string_errors_on_serialize` passes untouched |
| 3.4 state | `receipt.rs:275`, `:471`, `:980` | `v5_state_*` (4 permutations), `v5_type_with_non_v5_label_is_invalid`, `v5_receipt_summary_carries_state`; v4 `state_*` tests unchanged |
| 3.5 goldens | `receipt.rs:2290`; `hashing.rs:386` | `receipt::tests::v4_historical::golden_event_and_certified_preimages_cert_independent`, `hashing::tests::v4_historical::golden_tag_certified` |
| 3.6(a) | `receipt.rs:913`, `:1111` | `t6a_v5_with_certified_commitment_key_is_retired_field` (JSON hex/null/non-hex; CBOR bytes/null) |
| 3.6(b) | `receipt.rs:927`, `:933` | `t6b_genesis_certified_data_is_no_deletion_certified` |
| 3.6(c) | `receipt.rs:917`, `:1114` | `t6c_v5_zero_event_hash_is_invalid_event_hash_zero` (incl. precedence and the v4-unchanged assertion) |
| 3.6 inequality | — | `t6_genesis_differs_from_event_hash_over_same_inputs` |

## 5. Things this spec did not anticipate (reported, not resolved)

Resolved by ruling during the slice (recorded for completeness):
- **U-0a** §3.2 vs §3.4: removing the field from the one shared struct stranded
  v2–v4 receipts. The frozen v4 type (Option 1) resolved it.
- **U-0b** Baseline fmt/clippy failures on `main`: handled per ruling (§2).

Open:

- **U-1 No retired list existed.** "The registry's retired list" was not in the
  code. I created `RetiredTag`, `RETIRED_TAGS` and a "Retired Tags" doc table.
- **U-2 The "any use fails test" mechanism touches `hash_with_tag`.** The only
  way to catch a retired tag rebuilt as `DomainTag(b"MKTD02_CERTIFIED_V1")` was
  a `debug_assert!` in the core primitive. Its output is unchanged and release
  builds are unaffected, but the assert also fires in *downstream* debug and
  test builds (MKTd02, CVDR-Verify). `DomainTag.0` is `pub`, so in release
  builds nothing prevents that reconstruction.
- **U-3 Tension with permanent verifiability of issued receipts** (the stated
  reason for rejecting Option 2). Verifying an issued v4 receipt means
  recomputing `certified_commitment` with the retired tag. Under 3.1 that can
  only be done via `sha256_concat(&[TAG_CERTIFIED.bytes, …])`. Using
  `hash_with_tag` panics in debug, and `TAG_CERTIFIED` no longer typechecks as a
  tag. This crate ships no v4 certified_commitment helper. CVDR-Verify will hit
  this when it bumps.
- **U-4 A second retired golden.** `hashing.rs::golden_tag_certified` pins the
  retired tag but is not named in 3.5. The 3.1 type change forced a change, so
  it moved (digest unchanged) under its own `v4_historical` module in 3.1.
- **U-5 The 3.5 golden was modified before it moved.** In 3.1 its
  certified_commitment computation switched from `hash_with_tag` to
  `sha256_concat`, because the guard failed it. Digests unchanged.
- **U-6 GENESIS has no per-tag golden.** Every other tag has a
  `golden_tag_*`; the no-digests rule precluded one for `MKTD02_GENESIS_V1`.
  Slice 3 should add it.
- **U-7 Genesis preimage encoding was assumed.** `canister_id` is hashed as
  raw principal bytes (`Principal::as_slice()`), with no length prefix. The v3
  `receipt_id`, by contrast, length-prefixes canister bytes. I took the spec's
  `hash_with_tag("MKTD02_GENESIS_V1", canister_id)` literally; confirm before
  slice 3 pins it.
- **U-8 No certificate parsing in this crate.** 3.6(b) says "certificate whose
  certified_data…". zombie-core only carries certificate blobs, so the helper
  takes the caller-extracted `certified_data` bytes. The extraction path
  (CVDR-Verify) is untouched.
- **U-9 No "protocol constant", no `receipt_version` / `interface_version`.**
  None of these exist in this crate. "Bump the protocol constant" was
  implemented per the v0.4.0 precedent: an enum variant, `as_str`, a
  `classify_protocol` arm, and a crate minor bump to 0.5.0.
- **U-10 Commit order is 3.1, 3.3, 3.2, 3.4, 3.5, 3.6.** 3.2's v5-only parser
  dispatches on the `"mktd02-v5"` label, which only 3.3 introduces.
- **U-11 The frozen type is not textually verbatim.** Adding `V5` forced the
  exhaustive matches in `DeletionReceiptV4::{state, try_from, serialize}` to
  change (`Some(V5) | None`). Behaviour is byte-identical.
- **U-12 Stale and misleading texts kept verbatim.**
  - `DeletionReceiptV4` reports a v5 label as "unrecognised protocol_version",
    and its errors still say `DeletionReceipt:`.
  - The pre-existing test `unrecognised_protocol_string_errors_on_serialize`
    (`receipt.rs:1609`) still labels `"mktd02-v5"` as `// unknown line`. It
    passes, but the comment is now stale.
- **U-13 No unified parse entry point.** "Parsing dispatches on
  protocol_version" is implemented per type: each type refuses the other's
  labels, following the house pattern. A caller holding bytes of unknown version
  must peek `protocol_version` or try one type then the other. No
  `AnyReceipt`-style entry point was built.
- **U-14 `zombie_core::DeletionReceipt` silently changes meaning downstream.**
  The name now denotes the v5 type. Downstream code that only *decodes* issued
  v4 receipts as `DeletionReceipt` will still compile, then fail at runtime
  ("decode v2/v3/v4 receipts as DeletionReceiptV4"). Code touching
  `certified_commitment` or `TAG_CERTIFIED` fails to compile.
- **U-15 No JSON schema or `.did` file exists in the repo.** "Remove from JSON
  schema / Candid" is satisfied by the serde wire shape and the derived
  `CandidType`. The new type inherits the pre-existing limitation that Candid
  *decode* of the receipt type is non-functional (try_from indirection).
- **U-16 The Direct Certification formula is inferred.** The version note
  states that under Direct Certification certified_data carries
  `deletion_event_hash` itself. The spec text never states that formula; I
  inferred it from the slice title and 3.6(b)/(c). Confirm before tagging.
- **U-17 `ZERO_HASH` doc is now v4-era.** `hashing.rs:155` describes
  `ZERO_HASH` as "the initial value for deletion_event_hash before any
  deletion". Under v5, zero is a named rejection and genesis is the pre-deletion
  certified_data. Unchanged.
- **U-18 The zero-hash check is decode-only.** `Serialize for DeletionReceipt`
  does not refuse a zero `deletion_event_hash`, and `state()` ignores it. A
  programmatically built receipt can serialise, then fail to decode.
- **U-19 v5 decode error precedence.** Structural serde errors (bad hex,
  missing required hash field) are reported before the protocol, retired-field
  or zero-hash checks. So a v5 receipt carrying `certified_commitment` *and* a
  malformed field reports the structural error. Unknown keys other than
  `certified_commitment` (e.g. `nonce`, `subnet_id`) are silently ignored,
  inherited from the v4 raw wire.
- **U-20 `classify_protocol` uses `starts_with`** (pre-existing). `"mktd02-v5"`
  also matches `"mktd02-v50"` and `"mktd02-v5…"`. It was the same for v4.
- **U-21 README says "Domain tags are stable across versions".** That is no
  longer strictly true. Not edited (docs beyond the version note are out of scope).
- **U-22 `Cargo.lock` is gitignored.** `cargo audit` therefore runs against an
  uncommitted local lockfile, so results are not reproducible from the repo.
- **U-23 New public items are not re-exported at the crate root.** The `ERR_*`
  constants, `genesis_certified_data`, `check_certified_data_not_genesis` and
  `hashing::{RetiredTag, RETIRED_TAGS, TAG_GENESIS}` are reachable via their
  modules only. `ReceiptState` also was not re-exported (pre-existing).
- **U-24 The version note is spread over several commits.** `RELEASES.md` was
  written in 3.3 and extended in 3.2, 3.4, 3.5 and 3.6, so each commit's note
  matches its code.

## 6. Rulings received (Stef, via C, 11–12 Sep 2026)

Implemented on `v5` on top of `4f8c117`, one commit per item:

| SHA       | Item | Summary |
|-----------|------|---------|
| `f81b62b` | 1b.1 | `RetiredTag::hash_historical`, the sole sanctioned retired-tag hash; v4_historical bypasses replaced |
| `e494145` | 1b.2 | v5 type renamed `DeletionReceiptV5`; unversioned `DeletionReceipt` removed (no alias, no shim) |
| `384e820` | 1b.3 | `AnyDeletionReceipt` version-dispatching decode (`from_json_value`, `from_cbor`, accessors) |
| `bc1dc26` | 1b.4 | `DeletionReceiptV5` serialise refuses all-zero `deletion_event_hash` (`invalid-event-hash:zero`) |
| `d5511bb` | 1b.5 | genesis preimage doc: tag ‖ raw principal bytes, no length prefix |
| `e0caea2` | 1b.6 | first version of this section; §7 "Slice 6 candidates" |
| `e587ec3` | 1b.7 | `classify_protocol`: v5 arm exact; v2–v4 prefix arms frozen (see "1b.7" below) |
| `13601ad` | —    | `docs: README type name after 1b.2` (README.md:25, per follow-up ruling) |
| (this)    | —    | §6 rewritten per the follow-up rulings on U-numbering, U-8, U-10, U-16 |

Gate at `e587ec3` (last code change): fmt clean. clippy `-D warnings` clean
(default and `--all-features`). 122 tests pass plus 2 compile_fail doctests;
release passes 121. `cargo audit` exit 0 with the same single allowed warning.
No Cargo.toml dependency change.

### Ruling → U-item resolved

The rulings' "items 1–8" referred to the eight-item list in my end-of-slice
chat summary, not to U-1…U-8 in this file (confirmed by Stef). Each ruling
below cites the filed U-item it actually resolves. The filed U-items in §5
are unchanged.

| Ruling | Resolves | Decision | Where |
|---|---|---|---|
| 1b.1 | **U-3** | `RetiredTag::hash_historical` is the ONLY sanctioned way to hash under a retired tag, "for verifying receipts issued under a retired construction" | `hashing.rs` `RetiredTag::hash_historical`; test `hash_historical_follows_hash_with_tag_discipline` |
| 1b.1 | **U-2** | `hash_with_tag` keeps its debug-assert | `hashing.rs` `hash_with_tag` (unchanged) |
| 1b.1 | **U-4**, **U-5** | every `sha256_concat` bypass in v4_historical tests replaced with `TAG_CERTIFIED.hash_historical`; digests unchanged; placement under `v4_historical` stands | `hashing::tests::v4_historical::golden_tag_certified`, `receipt::tests::v4_historical::golden_event_and_certified_preimages_cert_independent` |
| 1b.2 | **U-14** | v5 type is `DeletionReceiptV5`; no unversioned `DeletionReceipt` export (no alias, no shim); compile-breaking by design | `receipt.rs`, `lib.rs`; `compile_fail,E0432` doctest; RELEASES.md |
| 1b.3 | **U-13** | `AnyDeletionReceipt` dispatches on `protocol_version`; named errors surface unchanged | `receipt.rs` `AnyDeletionReceipt`; tests `any_*` |
| 1b.4 | **U-18** | `DeletionReceiptV5` serialise refuses all-zero `deletion_event_hash` (symmetric with decode) | `receipt.rs` `Serialize for DeletionReceiptV5`; test `t1b4_v5_serialize_refuses_zero_event_hash` |
| 1b.5 | **U-7** | ruled: genesis preimage is tag ‖ raw principal bytes, no length prefix; doc line added | `receipt.rs` `genesis_certified_data` doc |
| 1b.5 | **U-6** | no genesis digest pin yet (slice 3) | — |
| 1b.7 | **U-20** (v5 part) | `"mktd02-v5"` matches exactly; v2–v4 prefix matching is an accident, filed under §7 | `receipt.rs` `classify_protocol`; tests `t1b7_*` |
| follow-up | **U-10** | commit order 3.1, 3.3, 3.2, …: **accepted, no action** | — |
| follow-up | **U-16** | **confirmed correct**: under Direct Certification certified_data holds `deletion_event_hash` directly. Version note unchanged | RELEASES.md v0.5.0 "Construction change" |
| follow-up | **U-8** | **ruled: out of scope, by design.** Certificate parsing is the verifier's job; zombie-core exposes `check_certified_data_not_genesis` over already-extracted bytes and stops there | `receipt.rs` `check_certified_data_not_genesis` |

Chat-summary item → filed U-item, for traceability: 1 commit order → U-10;
2 verifiability → U-3; 3 assert fires downstream → U-2; 4 genesis encoding →
U-7; 5 version-note formula → U-16; 6 `DeletionReceipt` meaning → U-14;
7 no single parse function → U-13; 8 zero-hash decode-only → U-18.

Not ruled at 1b, left as filed: U-1 (the retired list, retained as built; 1b.1
builds on it), the `DomainTag.0`-is-`pub` sub-point of U-2, U-9, U-11, U-12,
U-15, U-17, U-19, U-21, U-22, U-23, U-24. All of these were ruled on 12 Sep
2026; see "1c rulings" below.

### Follow-up rulings on the 1b implementation notes

- **`RetiredTag.bytes` stays `pub`: ruled, leave it.** The greppable
  `hash_historical` name is the control. A determined bypass isn't
  preventable, and CD greps for `sha256_concat` anyway.
- **`README.md:25` named the removed `DeletionReceipt`: ruled, fix that one
  line.** Done in `13601ad`. It now lists `DeletionReceiptV4`,
  `DeletionReceiptV5` and `AnyDeletionReceipt`. No wider README sweep (U-21
  stands).
- **`from_json_value` parses twice: accepted.** It is generic over
  `V: Clone + for<'de> Deserializer<'de>` (e.g. `serde_json::Value`) because
  `serde_json` is dev-only. It probes `protocol_version`, then runs one
  versioned decoder, so the returned error string equals the direct decode's
  (asserted). Errors are `String`.
- Unchanged facts, for the record:
  - 1b.2: a `compile_fail,E0432` doctest pins that `zombie_core::DeletionReceipt`
    does not exist. The frozen V4 error literals still read `"DeletionReceipt: …"`
    (U-12, kept verbatim).
  - 1b.4: with both a non-v5 label and a zero hash, serialise reports the label
    first, mirroring decode; `state()` ignores the event hash.

### 1b.7: prefix matching for v2–v4. Documented convention, or accident?

**Ruling applied:** the v5 arm of `classify_protocol` now matches exactly
(`protocol_version == ProtocolVersion::V5.as_str()`). `"mktd02-v5-x"`,
`"mktd02-v50"` and `"mktd02-v5 "` → `None` → hard error on V5 decode, V5
serialise, and both `AnyDeletionReceipt` constructors. The frozen v2/v3/v4
`starts_with` arms are untouched. This addresses filed U-20, which is left as filed.
Tests: `t1b7_classify_v5_is_exact`, `t1b7_near_v5_labels_hard_error`,
`t1b7_frozen_v4_prefix_arm_unchanged`.

**Finding: accident (inherited), not a documented convention.** Evidence:
- **Origin, `508f2f8` (12 Mar 2026)**, "fix: add serde into impl for
  DeletionReceipt to preserve V3 wire format". The first `starts_with` is
  `if r.protocol_version.starts_with("mktd02-v3") { …V3… } else { …V2… }`. The
  commit message discusses only the V3/V2 wire-variant bug; it gives no
  rationale for prefix matching, and nothing there mentions suffixed labels.
- **Carried forward, `f3ab186` (14 Jul 2026, G ratification)**. Its message
  reads "Versioned wire dispatch replaces starts_with("mktd02-v3")", yet the
  new `classify_protocol` kept `starts_with`. The only justification is its doc
  comment: "Uses `starts_with` for parity with the historical dispatch, so a
  suffixed string (e.g. `"mktd02-v4-rc1"`) still classifies". That describes
  the behaviour; it does not cite any requirement. RELEASES.md v0.4.0 treats
  that dispatch as the *hazard* being fixed (the silent else-to-V2 fallback)
  and says nothing about suffixes being valid.
- **Nothing establishes suffixed labels:** no spec text, RELEASES.md entry,
  README line, or ruling I can find. Before 1b.7 no test exercised a suffixed
  label (`"mktd02-v4-rc1"` appeared only in the doc comment).
  `ProtocolVersion::as_str()` only ever emits exact labels, so this crate never
  produces a suffixed one.
- **Consequences today:** `"mktd02-v2"` also matches `"mktd02-v20"`…`"mktd02-v29"`
  and `"mktd02-v2junk"`; likewise for v3/v4. `t1b7_frozen_v4_prefix_arm_unchanged`
  pins the current v4 behaviour, so a slice 6 change has to update it deliberately.

### 1c rulings (Stef, via C, 12 Sep 2026)

Implemented on `v5` on top of `f048786`, one commit per item. None changes
behaviour.

| SHA       | Item | Resolves | Summary |
|-----------|------|----------|---------|
| `99978da` | 1c.1 | **U-23** | crate-root re-exports: `genesis_certified_data`, `check_certified_data_not_genesis`, `ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT`, `ERR_INVALID_EVENT_HASH_ZERO`, `ERR_NO_DELETION_CERTIFIED`, `ReceiptState`, `hashing::{RetiredTag, RETIRED_TAGS, TAG_GENESIS}`; README module table updated |
| `18a3743` | 1c.2 | **U-17** | `ZERO_HASH` doc: "v2–v4: initial deletion_event_hash before any deletion. v5: a named rejection (invalid-event-hash:zero); the pre-deletion certified_data is genesis_certified_data." Summary line "A zero-filled 32-byte hash." kept |
| `d0c6e95` | 1c.3 | **U-21** | README: "Domain tags are stable within a protocol line; retirements are recorded in `RETIRED_TAGS` and never reused." |
| `a9de3b3` | 1c.4 | **U-12** | stale `// unknown line` comment in `unrecognised_protocol_string_errors_on_serialize` fixed. Comment only; the frozen V4 `"DeletionReceipt: …"` error strings stay verbatim |
| (this)    | —    | —        | this subsection and the §7 additions |

Gate at `a9de3b3` (last code change): fmt clean. clippy `-D warnings` clean
(default and `--all-features`). 122 tests pass plus 2 compile_fail doctests;
release passes 121. `cargo audit` exit 0 with the same single allowed warning.
No Cargo.toml change.

Rulings on the remaining filed U-items, verbatim:

- **U-1** Accepted as built. Creating RetiredTag / RETIRED_TAGS and the
  Retired Tags table was the ruling's intent; "the registry's retired list"
  now exists because you created it.
- **U-2** (DomainTag.0 public sub-point) Leave as is. The compile-fail
  doctest, the debug-assert, and the greppable hash_historical name are the
  control; a private constructor would break every DomainTag(b"…") in tests
  and consumers. Filed as a Slice 6 candidate ("consider a private
  constructor").
- **U-9** Accepted as built. There is no protocol constant and no
  receipt_version / interface_version in this crate; the v0.4.0 precedent
  (enum variant, as_str, classify arm, crate minor bump) is the correct
  implementation of "bump the protocol constant". Versioning fields are never
  to be invented to satisfy spec wording.
- **U-11** Accepted as built. The frozen type is behaviourally byte-identical;
  textual non-verbatim-ness from exhaustive match arms (Some(V5) | None) is
  unavoidable and CD verifies behaviour, not text.
- **U-15** Accepted as built. "JSON schema / Candid" in the spec means the
  serde wire shape and the derived CandidType. The pre-existing Candid-decode
  limitation (try_from indirection) is filed as a Slice 6 candidate and noted
  for CVDR-Verify.
- **U-19** — **SUPERSEDED 12 Sep 2026 by the 1d re-ruling below (deferral
  withdrawn). Original text kept for the record:**
  Deferred to Slice 3 — reason: rejecting unknown keys on the v5 wire
  (fail-closed) is a schema-coherence change that belongs with the corpus
  rebuild, where it gets its negative vector; landing it now would force a
  mid-Leaf re-pin. Structural-error precedence (serde reports structure before
  named checks) is accepted and documented as expected behaviour.
- **U-22** Deferred to Slice 6, yes; also add to §7 "Slice 6 candidates":
  commit Cargo.lock in every repo (current Cargo guidance for libraries;
  consistent with the DaffyDefs action).
- **U-24** Accepted as built. A version note extended per commit so each
  commit's note matches its code is correct practice.

With these, every filed U-item in §5 has a ruling. U-6 is deferred to
slice 3, and U-22 to slice 6. U-20's frozen v2–v4 part is a §7 candidate.
(U-19 was also deferred to slice 3 at 1c; the 1d re-ruling below withdrew
that.)

### 1d ruling (Stef, via C, 12 Sep 2026): re-rules U-19

**U-19 RE-RULED 12 Sep 2026.** The slice 3 deferral is withdrawn. The parser
fix landed in 1d, and the negative vector still goes into the slice 3 corpus.
The ruling: reject unknown keys on the v5 wire now, not in slice 3. The frozen
v4 path is unchanged and still tolerant, since issued receipts may rely on it.
The rustdoc states the precedence (the answer to the 1c precedence question:
rustdoc, not just notes).

| SHA       | Item | Summary |
|-----------|------|---------|
| `43c78b6` | 1d   | `#[serde(deny_unknown_fields)]` on `DeletionReceiptV5RawWire`; tests; rustdoc on `DeletionReceiptV5` and `AnyDeletionReceipt` |
| (this)    | 1d   | RELEASES.md "v5 wire rejects unknown keys (fail-closed)"; this subsection |

- **Where:** `receipt.rs` `DeletionReceiptV5RawWire`. `certified_commitment`
  stays a declared key-presence field, so it is still rejected by name
  (`retired-field:certified_commitment`), never as a generic unknown key. Any
  other undeclared key → serde ``unknown field `<key>` ``, a hard error.
  `DeletionReceiptRawWire` (v2–v4) is untouched.
- **Tests** (JSON and CBOR, direct and via `AnyDeletionReceipt`, whose error
  equals the direct one):
  - `t1d_v5_unknown_keys_hard_error`: `nonce`, `subnet_id`, `extra`.
  - `t1d_certified_commitment_still_rejected_by_name`: exact named error, no
    `unknown field`.
  - `t1d_unknown_key_reported_before_retired_field`: pins the documented
    precedence. With the retired key *and* an unknown key, the unknown key
    is reported.
  - `t1d_v4_unknown_key_tolerance_unchanged`: v2/v3/v4 fixtures with the same
    keys decode to the same receipt as without them.
- **Existing test adapted:** `v5_type_refuses_v2_v3_v4_labels`. A raw v2 wire
  carries `nonce`/`subnet_id`, so the v5 type now reports `unknown field`
  before the label check. The test pins that, then strips those two keys and
  asserts the label error as before. The v3/v4 cases are unchanged.
- **Mutation check:** without the attribute, `t1d_v5_unknown_keys_hard_error`,
  `t1d_unknown_key_reported_before_retired_field` and the adapted test fail.
- **Behaviour change:** a `mktd02-v5` receipt with extra keys, previously
  accepted, is now refused.
- **Gate at `43c78b6`:** fmt clean. clippy `-D warnings` clean (default and
  `--all-features`). 126 tests pass plus 2 compile_fail doctests; release
  passes 125. `cargo audit` exit 0 with the same single allowed warning. No
  Cargo.toml change.

## 7. Slice 6 candidates

**Prefix matching for frozen v2/v3/v4 labels (from 1b.7): accident.**
`classify_protocol`'s v2/v3/v4 arms use `starts_with`, inherited from
`508f2f8` without rationale (evidence in §6 "1b.7"). A label such as
`"mktd02-v4-rc1"`, `"mktd02-v20"` or `"mktd02-v3junk"` classifies as a frozen
line. Candidate: exact-match the frozen arms too. That is a behaviour change to
v2–v4 decode/serialise/state(), so it needs a ruling on whether any issued
receipt carries a suffixed label.

**`DomainTag` private constructor (from U-2, ruled 12 Sep 2026).** "Consider a
private constructor." `DomainTag.0` is `pub`, so in release builds nothing
stops a retired tag being rebuilt as `DomainTag(b"MKTD02_CERTIFIED_V1")`. A
private constructor would break every `DomainTag(b"…")` in tests and consumers.
That is why it is a candidate and not a fix: the compile-fail doctest, the
debug-assert and `hash_historical` are the control today.

**Candid decode of receipt types (from U-15, ruled 12 Sep 2026).** Candid
*decode* of the receipt types is non-functional because of the `try_from`
indirection. This is pre-existing: it applies to `DeletionReceiptV4` and is
inherited by `DeletionReceiptV5`. Also noted for CVDR-Verify.

**Commit `Cargo.lock` in every repo (from U-22, ruled 12 Sep 2026).** This
follows current Cargo guidance for libraries and is consistent with the
DaffyDefs action. Today `.gitignore` excludes `Cargo.lock`, so `cargo audit`
runs against an uncommitted local lockfile and its results can't be
reproduced from the repo.

**Hygiene finding for slice 6 (not fixed here):** `main` was not fmt/clippy
clean, yet `.github/workflows/ci.yml` runs `cargo fmt --all -- --check` on push
and PR to main. CI is evidently not enforcing it. CI also runs neither clippy
nor `cargo audit`.
