# MKTd02 v5 Slice 3 — phases 2–5 implementation notes

Status: phases 2–5 implemented on 13 Sep 2026. No clean-room rederivation or countersignature was performed.

## Commit map

| Phase | Commit | Deliverable |
|---|---|---|
| 2 | `9b75ec2` | Input-only corpus, README, and pre-countersignature manifest |
| 3 | `5ccc187` | Standard-library derivation harness, generated expectations, provenance, and CI check mode |
| 4 | `4b9fdfe` | Rust implementation-to-JSON cross-check |
| 5 | this commit | Final README, manifest, status/provenance cleanup, and these notes |

## Commands and provenance

The single initial generation command was:

```text
python3 scripts/rederive-v5-vectors.py --generate
```

The normal read-only check command is:

```text
python3 scripts/rederive-v5-vectors.py
```

After the initial clean check, provenance was written with:

```text
python3 scripts/rederive-v5-vectors.py --update-notes
```

One guarded regeneration was subsequently required for nv5-008 after the code cross-check showed that its input paraphrased the already-recorded D-9 frozen V4 error. It used:

```text
python3 scripts/rederive-v5-vectors.py --force-regenerate --reason "D-9 frozen V4 error text"
```

No expected value was manually edited to obtain a green check or Rust test. The initial implementation's negative inputs nevertheless contained expectation-bearing fields, and its historical v3 wire was initially generated rather than copied; those defects and their later remediation are recorded below. No vector claims clean-room independence or countersignature.

## Inventory and coverage

- Positive: `gv5-001` through `gv5-012` — harness and Rust cross-check covered.
- Negative/compatibility: `nv5-001` through `nv5-010`, plus `nv5-011a`, `nv5-011b`, and `nv5-011c` — the original Rust test did not substantively consume each JSON vector; the CD remediation below closes that coverage defect.
- Historical: `v4h-certified-commitment`, `v4h-certified-tag`, and `v4h-event-v1` — harness and Rust cross-check covered as historical hashes only.
- Frozen historical wire: `v4h-v3-wire` — Rust cross-check covered; deliberately not claimed as spec-derived by the harness.

The harness has no dependency on zombie-core or any Rust artefact. Its imports are `argparse`, `hashlib`, `json`, `sys`, and `pathlib`; it uses no subprocess, FFI, `ctypes`, or `cffi`. Its CBOR routines implement only the definite map/text/byte-string/unsigned-integer/null subset required by the ratified v5 receipt text.

## Text ↔ code findings

No runtime disagreement was found between the ratified v5 formulas/wire rules and zombie-core. The first corpus cross-check did not, however, establish every claimed negative-vector result because several cases and expectations were hard-coded in Rust; the CD remediation below corrects that evidence gap.

The frozen v3 CBOR/JSON bytes are not independently derivable from the ratified v5 document: §8 preserves the historical behavior but does not restate its complete encoder. They remain in the corpus as an implementation regression reference and are checked only by Rust. This is a coverage boundary, not a v5 text↔code mismatch.

`gv5-011` uses a synthetic, explicitly described two-field tombstone-state fixture under the requirements in `ICP-Delete-Leaf/docs/sections/11-deterministic-encoding.md`. That Leaf document specifies what a product State Encoding Specification must contain, but the generic Leaf repository has no product-specific schema. The vector therefore identifies its exact synthetic schema in-file; the ruled Phase-9 Leaf engine cross-check remains required.

## Unanticipated

- The pinned Rust 1.97.1 toolchain lacks installed `rustfmt` and `clippy` components. The installed stable toolchain was used explicitly for formatting and clippy; the pinned toolchain was retained for tests and no component/toolchain was installed or changed.
- The first nv5-008 wording was a paraphrase rather than frozen D-9 text. The guarded regeneration described above corrected the corpus input and expectation; code and the ratified historical ruling already agreed.
- The v3 wire reference is not derivable from the v5 normative encoder, so the final harness explicitly skips it rather than making a false provenance claim.
- The generic Leaf repository publishes State Encoding Specification requirements but no product-specific state schema; gv5-011 records a synthetic schema and Phase 9 retains the Leaf-side cross-check.
- Offline audit could not acquire the local crates.io index lock; it completed against the cached advisory database and reported the established single allowed `paste` warning.

## CI and exclusions

The existing `.github/workflows/ci.yml` is authoritative and now runs `python3 scripts/rederive-v5-vectors.py` in check mode only. No new CI architecture was introduced.

The harness does not cover platform publication of certified data (Leaf T6/T7), product-specific state-schema correctness, the future Phase-9 engine checks for gv5-002/gv5-011, or the frozen v3 wire encoder. No Phase-6 clean-room rederivation was attempted.

## CD remediation — provenance and coverage closure

Fresh CD review of the original phases 2–5 tip returned **NOT CONFORMANT** for four corpus-evidence defects: negative answers were embedded in `inputs`; the v3 wire values had not been established as copied frozen goldens; the Rust negative tests hard-coded several cases and results instead of consuming each JSON vector; and the README/notes consequently overstated provenance and coverage.

The remediation removes every expectation-bearing negative-input field. The Python harness now selects each outcome from the vector id and the ratified normative rule while using `inputs` only for malformed/candidate artefacts and neutral operation/case metadata. Expectations were replaced only through this guarded command:

```text
python3 scripts/rederive-v5-vectors.py --force-regenerate --reason "Slice 3 CD remediation R1: remove expectation-bearing negative inputs; incorporate ratified D-9"
```

No generated `expected` value was manually edited. The D-9 prefix is now incorporated into §8.4 of the ratified serialization document as an already-ratified historical fact and is derived by the harness rather than copied from runtime output.

The `v4h-v3-wire` CBOR and JSON values were compared byte-for-byte with the immutable pre-Slice-3 constants in commit `ac5c32de499563efcf291ec3d4c90c36b217db8d`, path `src/receipt.rs`, tests `v3_cbor_byte_identical_to_head_golden` and `v3_json_byte_identical_to_head_golden`. Their SHA-256 values are recorded in the vector. They matched. This vector remains a historical implementation-regression reference and remains skipped by the v5 Python harness.

The Rust integration test now loads and consumes the malformed/candidate input and generated expected result, layer, prefix, or acceptance from every `nv5-001`…`nv5-011c` JSON file. The inventory test remains supplemental. A temporary expected-value mutation was demonstrated to fail the corresponding substantive test and was reverted before commit.

The zombie-core checks for `gv5-002` and `gv5-011` prove only formula/primitive agreement against supplied inputs. They do not prove Leaf engine conformity. Ruling D-2 still requires the Phase-9 Leaf engine-to-JSON checks for both vectors. The `gv5-011` state bytes use a synthetic fixed corpus schema, not a product-specific Leaf state schema.

This remediation changes no protocol, runtime construction, tag, preimage, wire implementation, named-error implementation, dependency, or lock file. It does not perform Phase 6 or add a countersignature.

## Phase 6 — clean-room rederivation and Phase 1c closure

G-1 = nv5-009 / nv5-010:
      no named V1 rejections in §7.
      Closed by 1c.2 names + 1c.3 regeneration.

G-2 = nv5-007 / nv5-008 case 1:
      message fragments relied on by the corpus but unfrozen by §7.
      Closed by 1c.2 fragment freeze.

G-3 = gv5-012:
      principal textual form ↔ raw-byte relation undefined.
      Closed by 1c.1.

G-4 = v4h-v3-wire:
      UNDERIVABLE BY DESIGN because it is a copied frozen historical
      artefact, not a spec-derived value.
      This is NOT repaired by inventing a v3 encoder. Record it as an
      explicit Phase-6 exclusion.

The layer vocabulary is NOT a G-item. It is the ratified corpus convention introduced by 1c.2 so layer strings are themselves derivable.

The isolated bundle SHA-256 was `5dc6e2b2a356c0d780538adeba373514c527e99578fd87dc775c49c72a33468a`. Phase 6 compared 47/47 derivable values: all matched, with 0 mismatches. There were zero underivable values among the derivable corpus. The copied historical `v4h-v3-wire` reference was excluded by design. The first implementation placed reconstructed report/script artefacts in `docs/dev/slice3_phase6_evidence/`; these are now explicitly superseded by the exact original archive in `docs/dev/phase6/`. The tarball and comparison-side `expected_3a3e01d.json` are deliberately absent. See the corrective record below.

### Phase 1c item-to-commit map

| Item | Commit | Closure |
|---|---|---|
| 1c.1 | `8d1406e` | Principal textual/raw-byte convention and `gv5-012.canister_id_hex` |
| 1c.2 | `8797928` | V1 named rejections, layer vocabulary, and frozen message fragments |
| 1c.3 | `6e3796f` | Guarded corpus regeneration and principal-relation harness check |
| 1c.4 | `068f6f4` | Four constructed `gv5-009` `state()` checks and frozen-provenance `--update-notes` skip |
| 1c.5 | `cb985d6` | Clarified Phase-6 lock-gate record; countersignature remains unchecked |
| 1c.6 | `0b6d100` | Phase-6 evidence archive, excluding the tarball and comparison-side expectations |
| 1c.7 | `c6f9535` | Phase-6 record, G-map, commit map, and prior-CD-exception closure |

### Prior CD exceptions closed

- `gv5-009`: the Rust test now constructs receipts for all four certificate permutations from the JSON inputs, calls `state()` for each, and compares each result with the JSON expectation.
- Frozen/copied provenance: `--update-notes` detects the provenance record, prints `SKIPPED notes v4h-v3-wire: frozen/copied provenance`, and leaves that vector byte-identical.

The implementation fragments `not a mktd02-v5 receipt` and `unrecognised protocol_version` were confirmed verbatim before 1c.2. Phase 1c changes documentation, corpus metadata/expectations, the spec-only harness, tests, and evidence only. It makes no protocol/runtime change, begins no Phase 7 activity, and adds no countersignature.

### Phase 1c unanticipated

- The completed bundle, its manifest, and both spec-deletion records remained available locally. The clean-room session's standalone report and exact `derive.py` file were not present in the workspace; the evidence directory therefore records the supplied clean-room result and the standard-library derivation primitives without claiming that the absent comparison-side file was clean-room input.


### Phase 1c corrective commit — 13 Sep 2026

Commit: this corrective commit, `docs(test): correct Phase 1c corpus names and archive exact Phase 6 evidence`, directly following pushed tip `c6f9535b2928f870c12aada63e4cea41f495fcba`. The earlier commits and their implementation history remain intact.

The first Phase-1c implementation used the wrong V1 names/layer and reconstructed evidence artefacts. Its §7 incorrectly published `V1 receipt_id mismatch` / `V1 deletion_event_hash mismatch` and mixed `verifier` / `verify_v1` into the corpus layer vocabulary. The correction adopts the authoritative `v1:receipt-id-mismatch` and `v1:event-hash-mismatch`, both at `verify`, with receipt-id comparison first and event-hash comparison only after it passes. The vocabulary is exactly `decode | serialise | decode_and_serialise | verify`; `verify_v1` remains only neutral input-operation metadata. Rust JSON-driven assertions now require those exact names and layers.

Regeneration used the guarded path:

```sh
python3 scripts/rederive-v5-vectors.py --force-regenerate --reason 'Phase 1c corrective ruling: v1:receipt-id-mismatch and v1:event-hash-mismatch; output layer verify'
```

A recursive parsed-JSON comparison of all 30 tracked corpus JSON files against `c6f9535` found exactly these four changed leaves:

| JSON path | Before | After |
|---|---|---|
| `v5/nv5-009.json/expected/error` | `V1 receipt_id mismatch` | `v1:receipt-id-mismatch` |
| `v5/nv5-009.json/expected/layer` | `verifier` | `verify` |
| `v5/nv5-010.json/expected/error` | `V1 deletion_event_hash mismatch` | `v1:event-hash-mismatch` |
| `v5/nv5-010.json/expected/layer` | `verifier` | `verify` |

Thus `gv5-001..012`, all historical expectations, `nv5-001..008`, and `nv5-011a/b/c` are unchanged. All digest, presented, recomputed, and input values are unchanged, including the remaining `nv5-009/010` fields.

The actual report and actual `derive.py` were located in `/mnt/c/Users/steph/Downloads/` and copied verbatim to `docs/dev/phase6/`. Byte comparisons confirmed identity. Their SHA-256 hashes are:

- Report: `655234a1c07ccf120a75e719485b416acde5b1bf290d8cf08ab95ec7bc5276fd`.
- Script: `4dbc1f7dba17a2b8825ae8d7bc6f054485681fdf26148bb1df6c369e76a40796`.

The exact manifest was read from the bundle whose SHA-256 is `5dc6e2b2a356c0d780538adeba373514c527e99578fd87dc775c49c72a33468a`; both deletion records were copied byte-for-byte from `/tmp/cleanroom/`. The old reconstructed report/script remain explicitly marked superseded and non-original. `expected_3a3e01d.json` is comparison-side material and was not a clean-room input. Neither it nor the tarball is committed.

Phase 1c.1 now cites the Internet Computer Interface Specification section “Textual representation of principals”. The cited CRC-32 / Base32 convention agrees with the existing algorithm, which is unchanged.

Implementation gates passed: `python3 scripts/rederive-v5-vectors.py` (28 derivable vectors; frozen v3 wire skipped), `cargo test --test v5_corpus` (8), `cargo test` (134 unit, 8 corpus, 2 doc), `cargo test --doc` (2), `cargo +stable fmt --check`, and `cargo +stable clippy --all-targets --all-features -- -D warnings`. Formatting and clippy use the established installed-stable fallback. `cargo audit --no-fetch` passed against the cached advisory database, with the established allowed `paste` unmaintained warning and crates.io index-lock warning. `git diff --check c6f9535..HEAD` is the final commit gate.

There are no changes to `src/`, `Cargo.toml`, or `Cargo.lock`. The manifest remains `pending_countersignature`, with no countersignature block. The independent-rederivation checkbox remains checked on the corrected documentary record and original archived Phase-6 evidence; countersignature remains unchecked. This is an implementation correction only: no narrow clean-room pass, Phase 7, countersignature, or CD verdict was performed.

The verbatim original script has trailing whitespace at line 184. `docs/dev/phase6/.gitattributes` disables only `blank-at-eol` checking for that archived file, preserving its original bytes while allowing the diff gate.

## Phase 7 — CD Gate G closure (14 Sep 2026)

Base: pushed `26a344f`. CD Gate G reported three test-coverage findings in `tests/v5_corpus.rs` (G1 nv5-008, G2 nv5-007, G3 nv5-009/010) and one stale corpus-spec line (G4). Under §4.6 every negative assertion must compare the JSON value with a string the implementation produced, never a Rust literal.

Before any change, a read-only probe found three items that could not close as briefed: the v5 serialise refusal for near-miss labels lacked the frozen fragment (B1); `AnyDeletionReceipt` routes a v4 label to `DeletionReceiptV4`, so it never produces `not a mktd02-v5 receipt` (B2); and nv5-010's `receipt_id` (`33…33`, no canister or record id) cannot pass V1 step 1, so `verify_v1` could never return the event-hash error for it (B3). Rulings (C, 14 Sep 2026):

- **B1 — serialise refusal aligned to the §7 fragment freeze (Gate G / B1).** `DeletionReceiptV5` serialisation classifies the label like decode: unrecognised → `DeletionReceiptV5: unrecognised protocol_version "…"; refusing to serialise`; wrong-line (v2–v4) → unchanged `… is not mktd02-v5; refusing to serialise`. Message text only; recorded in `RELEASES.md` v0.5.0 DRAFT.
- **B2 —** the `AnyDeletionReceipt` leg is dropped from nv5-008 `v4_label_to_v5_type`; its routing is §8.4.
- **B3 —** `verify_v1_receipt_id` and `verify_v1_event_hash` are public; `verify_v1` runs them in order. nv5-009 calls `verify_v1`; nv5-010 calls `verify_v1_event_hash` as a §3.4 single-step vector. The unit tests prove the order.

### Gate G item-to-commit map

| Item | Commit | Closure |
|---|---|---|
| B1 | `55e8b6b` | v5 serialise refusal classified like decode; unit test for the three near-miss labels (with fragment) and `mktd02-v4` (without); RELEASES line |
| G3 helpers | `36782a0` | `verify_v1`, `verify_v1_receipt_id`, `verify_v1_event_hash`, `ERR_V1_RECEIPT_ID_MISMATCH`, `ERR_V1_EVENT_HASH_MISMATCH` at the crate root; unit tests (consistent → `Ok`; both tampered → receipt-id error wins; event hash alone → event-hash error); spec §7 "Reference implementation: zombie_core::verify_v1." |
| G1 + B2, G2, G3 + B3 | `a088e9c` | nv5-008: v5 label decoded into `DeletionReceiptV4` (JSON, CBOR), error starts with the JSON prefix; v4 label decoded into `DeletionReceiptV5` (JSON, CBOR), error contains the JSON fragment. nv5-007: each JSON label refused with the JSON fragment on decode (v5 type and `AnyDeletionReceipt`, JSON and CBOR) and on serialise (JSON and CBOR). nv5-009/010: receipt built from the JSON inputs; returned error equals `expected.error`; recomputed-value and `matches: false` assertions kept |
| G4 | `7dcf953` | Corpus spec §4.1 `deletion_event_hash` row: `MKTD02_EVENT_V2` six-part, "(amended 13 Sep 2026, Slice 3a)" |
| Notes | this commit | This section |

CBOR messages are taken out of ciborium's `Semantic(_, msg)` / `Value(msg)` wrappers; the extracted text is still the implementation's string (ruled acceptable). Fields outside a vector's inputs (nv5-009 event fields; nv5-010 canister, record and certificates) come from the canonical `gv5-012` fixture and do not affect the checked step.

Mutation checks, all reverted before commit: altering the JSON nv5-007 fragment, nv5-008 prefix, nv5-008 fragment, nv5-009 error or nv5-010 error each failed the corresponding corpus test. Restoring the pre-B1 serialise wording failed the nv5-007 serialise assertion.

Gate: `python3 scripts/rederive-v5-vectors.py` check mode green (28 OK, frozen v3 wire skipped); `cargo test --test v5_corpus` (8); `cargo test` (139 unit, 8 corpus, 2 doc); `cargo +stable fmt --check`; `cargo +stable clippy --all-targets --all-features -- -D warnings`; `cargo audit --no-fetch` (allowed `paste` warning only); `git diff --check 26a344f..HEAD`. `git diff --stat 26a344f..HEAD -- docs/test-vectors` is empty: no vector file changed.

Out of scope and unchanged: the `historical_vectors_remain_frozen_and_tolerant` tail still checks the v4 serialise refusal against a Rust literal. That is a unit-style historical check, not one of the Gate G vectors.

### Archived clean-room report — counting error (not edited)

`docs/dev/phase6/mktd02-v5-cleanroom-rederivation.md` is kept byte-identical as archived evidence. Its counts are internally inconsistent with its own table and with `docs/dev/phase6/MANIFEST.txt`:

- §1 says "Files received: 30 (spec.md, MANIFEST.txt, 28 vectors)" and "all 29 listed hashes". The manifest lists 30 files (spec.md plus 29 vectors), so 31 files were received including MANIFEST.txt.
- §4 says "Vectors received: 30 (12 gv5, 14 nv5, 3 historical, 1 frozen v3 wire)" and "DERIVED: 29". There are 13 nv5 vectors (`nv5-001`…`nv5-010`, `nv5-011a/b/c`), so there are 29 vectors: 28 derived and 1 underivable (`v4h-v3-wire`).

The per-vector sections cover all 29 vectors, and the value-level result recorded above (47/47 derivable values matched, 0 mismatches) is unaffected. Only the summary tallies are wrong.
