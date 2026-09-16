# MKTd02 v5 Slice 3 — Spec-Derived Corpus: Specification

**Status:** normative authority for Slice 3 (zombie-core, branch `v5`), 12 Sep 2026; **amended 12 Sep 2026 on G's pre-ratification review** (harness write policy; byte-exact wire freeze; countersignature commit identity; clean-room independence; three historical unknown-key controls). Ratification: pending G. Rulings: SR-04 phase 2 order; MKTd01 §7 standard (spec-derived, encoder-free, independently rederived before countersignature); Slice 1 deferrals U-6 (genesis golden) and U-19 (unknown-key negative vector).
**Base:** zombie-core `v5` @ `8fa8f91` (Slice 1 CLOSED / CD CONFORMANT). ICP-Delete-Leaf `v5` @ `b64abbd` (Slice 2 CLOSED) consumes the result by re-pin only; no Leaf code changes in this slice.
**Authority hierarchy:** this spec > the normative formula text it mandates (once ratified) > implementer notes > commentary.
**Roles:** CC implements phases 2–5 from this document. Stef and G ratify the formula text (phase 1 gate). C performs the independent rederivation (phase 6). CD verifies against §7. Stef countersigns.

---

## 1. Purpose and the standard

Slice 1 replaced the construction and retired the golden pins that no longer apply. Slice 2 fixed what verification *claims*. Neither proved that the v5 protocol is internally coherent — that every value a verifier recomputes is derivable from published text by someone who has never read the encoder. That is what a corpus is for, and it is the countersignature's only honest basis.

The standard is the one ratified for MKTd01 §7 and applied there in September:

1. **Spec-derived.** Every expected value is derived from the normative formula text, not dumped from the implementation.
2. **Encoder-free harness.** The rederivation harness has no dependency on `zombie-core` (or any crate containing its hashing/serialisation code), in any form — no cargo dependency, no FFI, no subprocess. Standard library only.
3. **Independent rederivation before countersignature.** A party who has not read the encoder (C) derives every digest vector from the formula text and reports matches, mismatches, and — the finding that matters — vectors that *cannot* be derived from the text alone.
4. **No self-referential provenance.** Any in-tree dump path is diagnostic-only and marked so; a vector's `notes` never claims independence it does not have.

## 2. The circularity hazard, and how this slice avoids it

zombie-core's current goldens are inline Rust constants whose comments say they were computed independently via Python `hashlib`. Whether a normative formula document exists that those constants were derived *from* is the first thing this slice establishes (§4, phase 1). Two cases:

- **A normative text exists** (in-repo or in a suite document) → it is the derivation source, subject to phase-1 review for completeness.
- **No normative text exists** → one must be written, and *it must not be written by transcribing the code*. It is written from the White Paper v5 (Figure 4, §2.2), the SHARED context-pack formula sections, the Slice 1 ratification record, and the rulings — with the code consulted only to confirm what the text predicts, never to supply what the text omits. Where the text and the code disagree, that is a **finding**, recorded as such, and ruled on by Stef/G before any vector is derived. A formula text that silently adopts the code's behaviour where the text was silent is code-derived by proxy and fails the standard.

The phase-1 gate exists to enforce this. No vector work starts until Stef/G have ratified the formula text and C has reviewed it against the White Paper and rulings.

## 3. Scope

**In scope (zombie-core):**
- The normative formula text for every hash and encoding a v5 verifier recomputes (§4.1).
- A published corpus directory `docs/test-vectors/v5/` with positive digest vectors, byte-exact receipt fixtures, and negative vectors (§4.2–4.4).
- A stdlib-only Python rederivation harness `scripts/rederive-v5-vectors.py` (§4.5), wired into CI.
- Rust tests that load the JSON vectors and compare against the implementation (implementation ↔ JSON cross-check), distinct from the harness (§4.6).
- Provenance discipline: `notes`, `manifest.json` status, the dump-path rule (§4.7).
- The `v4_historical` reference values retained and documented as historical (§4.8).

**Out of scope:**
- Any change to a construction, tag, preimage, wire shape, or named error. If deriving a vector reveals a defect, it is a finding for ruling, not a fix in this slice.
- CVDR-Verify (slice 4) and DaffyDefs (slice 5). The corpus is *consumed* by them later; nothing here touches them.
- ICP-Delete-Leaf code. Leaf re-pins to the countersigned corpus commit at the end of this slice (one commit, no code).
- Exact-matching the frozen v2–v4 label arms (slice 6, ruled safe).

## 4. Normative deliverables

### 4.1 Formula text — `docs/spec/mktd02-v5-serialization.md`

One document, one version, containing for **each** value a v5 verifier recomputes:

| Value | Must specify |
|---|---|
| `state_hash` | input bytes (the adapter-encoded state), tag if any, exact construction |
| `tombstone_hash` | tag (`MKTD02_TOMBSTONE_HASH_V1`), preimage parts and their encodings, the `TOMBSTONE_CONSTANT` derivation from `MKTD_TOMBSTONE_V1` |
| `deletion_event_hash` | tag (`MKTD02_EVENT_V2`), the exact ordered six-part preimage (pre_state_hash, post_state_hash, receipt_id, timestamp, module_hash, deletion_seq), integer encodings (width and endianness), and the explicit statement that `manifest_hash` is **not** in the preimage (amended 13 Sep 2026, Slice 3a) |
| `receipt_id` | tag (`MKTD02_RECEIPT_V3`), the length-prefixed encoding of `canister_id` and `record_id`, the `deletion_seq` encoding |
| `genesis_certified_data` | tag (`MKTD02_GENESIS_V1`), preimage = raw principal bytes, **no length prefix** (ruled 11 Sep 2026) |
| `certified_data` (v5) | `= deletion_event_hash` after a deletion; `= genesis` before (WP Fig 4) |
| `hash_with_tag` | `SHA-256(tag ‖ part₀ ‖ part₁ …)`, tag as exact ASCII bytes, no separator, no length framing between parts |
| Receipt wire (v5) — **byte-exact freeze** | Everything needed for *reader + this text → exact bytes*. **CBOR:** map vs array representation; definite lengths; map length; key encoding (text) and **order**; byte-string representation for `[u8;32]` and `Vec<u8>` fields; `canister_id` (principal) representation; integer widths and minimal-length encoding; representation of optional fields when absent and when present. **JSON:** compact vs pretty (choose one as normative for vectors; state the other is non-normative); whitespace/indentation and newline policy; escaping; field ordering; hex case for byte fields; `canister_id` textual form; representation of optional fields when absent/present. Plus: `protocol_version = "mktd02-v5"` exact match; **unknown keys rejected**; `certified_commitment` key rejected by name. *Expectation:* most wire-encoding details will have no origin in the White Paper or SHARED text and will therefore carry `[ORIGIN: implementation — needs ratification]`. That is correct and expected: ratification turns an implementation fact into a **normative decision**, which is legitimate; silently transcribing it is not. |
| Receipt state rule | Pending / FinalizedCandidate / InvalidIncompleteFinalization over the two certificate fields, for v5 |
| Named rejections | `retired-field:certified_commitment`, `invalid-event-hash:zero`, `no-deletion-certified`, unknown-label, unknown-key — exact strings and where each is raised (decode / serialise / verifier) |
| Tag registry | every active tag's exact ASCII bytes; the retired list with dates and rulings; the rule that retired tags are never reused and that `hash_historical` is the only sanctioned historical path |

Rules for the text:
- It is **normative and self-contained**: a reader with SHA-256, CBOR, and this document can compute every value. No "see the code".
- Each formula cites its origin: White Paper v5 section, SHARED pack section, or ruling (date). A formula whose only origin is "the code does this" is flagged `[ORIGIN: implementation — needs ratification]` and is a phase-1 finding.
- Historical constructions (`certified_commitment`, `MKTD02_RECEIPT_V1`, v2/v3 wire differences) appear in a clearly separated **Historical** section, marked retired with date and ruling, so v2–v4 receipts remain explainable without polluting the v5 normative set.
- It carries a **lock-gate** section like MKTd01's §11: one checkbox per item, including "Countersignature on v5 vectors".

### 4.2 Positive digest vectors — `docs/test-vectors/v5/gv5-*.json`

Minimum set, each with `inputs`, `expected`, `normative` (section ref), `notes`, `status`:

| id | Exercises |
|---|---|
| gv5-001 | `hash_with_tag` discipline: fixed tag + two parts; and the tag-first ordering (swap parts → different digest) |
| gv5-002 | `tombstone_hash` from fixed inputs |
| gv5-003 | `deletion_event_hash` from fixed inputs; a second case with a different `deletion_seq` only |
| gv5-004 | `receipt_id` (v3 tag) with length-prefixed canister/record ids; a second case with a different-length `record_id` to pin the prefix |
| gv5-005 | `genesis_certified_data` for two distinct canister ids (pins raw-bytes, no-prefix encoding — U-6) |
| gv5-006 | genesis ≠ `deletion_event_hash` over the same principal bytes and over a full event preimage (domain separation) |
| gv5-007 | A complete **finalized** `DeletionReceiptV5`: the CBOR bytes (hex) and the JSON text, byte-exact, with `receipt_id` and `deletion_event_hash` recomputed from the fixture's own fields and shown to match |
| gv5-008 | The same receipt **pending** (both certificates `None`): byte-exact CBOR and JSON; `state() == Pending` |
| gv5-009 | Receipt-state rule: the four permutations of the two certificate fields → the three states |
| gv5-010 | Every active tag's per-tag golden (`hash_with_tag(TAG, b"test")`), one entry per tag, including `MKTD02_GENESIS_V1` |

### 4.3 Negative vectors — `docs/test-vectors/v5/nv5-*.json`

Each carries the malformed input, the **expected named error** (exact string or a stated prefix), and the layer that raises it (decode / serialise / verifier / dispatch):

| id | Case | Expected |
|---|---|---|
| nv5-001 | v5-labelled receipt carrying `certified_commitment` (value: valid hex; null; garbage — three sub-cases) | `retired-field:certified_commitment` |
| nv5-002 | v5 receipt with an unknown key (`nonce`; `subnet_id`; `extra`) — JSON and CBOR | `unknown field` (structural) — U-19 |
| nv5-003 | v5 receipt with both `certified_commitment` and an unknown key | `unknown field` first (documented precedence) |
| nv5-004 | v5 receipt with all-zero `deletion_event_hash` — decode | `invalid-event-hash:zero` |
| nv5-005 | v5 receipt with all-zero `deletion_event_hash` — serialise | `invalid-event-hash:zero` |
| nv5-006 | `certified_data` equal to genesis for the canister | `no-deletion-certified` |
| nv5-007 | labels `mktd02-v5-x`, `mktd02-v50`, `mktd02-v5 ` on the v5 type and via `AnyDeletionReceipt` | unrecognised protocol_version |
| nv5-008 | v4-labelled receipt presented to the v5 type; v5-labelled receipt presented to the v4 type | each refused with its own named error |
| nv5-009 | v5 receipt with `receipt_id` not matching recomputation from its fields | V1 failure (the verifier's check; recorded here as a corpus entry for slice 4 to consume) |
| nv5-010 | v5 receipt with `deletion_event_hash` not matching recomputation | V1 failure (as above) |
| nv5-011a/b/c | frozen receipt with an unknown key — **three explicit cases: v2-labelled, v3-labelled, v4-labelled** | each **accepted** (tolerance preserved for every historical label, not merely the shared `DeletionReceiptV4` representation) — positive controls in the negative set |

### 4.4 Historical reference vectors — `docs/test-vectors/v4-historical/`

Moved, not deleted: the retained `certified_commitment` deletion-path golden and the `MKTD02_CERTIFIED_V1` per-tag golden, plus the v3 CBOR/JSON byte goldens. Each marked `"status": "historical — retired construction; verifiable via RetiredTag::hash_historical only"`. The harness rederives them **only** to prove `hash_historical`'s definition; it never treats them as v5.

### 4.5 Rederivation harness — `scripts/rederive-v5-vectors.py`

- Python 3, standard library only (`hashlib`, `json`, `sys`, `pathlib`, `argparse`). A minimal canonical-CBOR encoder written **from the formula text's description**, sufficient for the receipt wire shape; no third-party CBOR library.
- Docstring states: authority is `docs/spec/mktd02-v5-serialization.md`; MUST NOT import, link, or invoke `zombie-core`, `ciborium`, or any Rust artefact.
- **Two modes, explicit and asymmetric.** Default (no flag) is **check mode**: read-only; reads each vector's `inputs`, computes the value from the formula text, compares with `expected`, exits non-zero on mismatch. **`--generate`** populates `expected` fields that are **empty** (absent or null) from the formula text, writes them once, and refuses to touch any non-empty `expected`. Overwriting a non-empty `expected` requires a separate, deliberate `--force-regenerate --reason "<ruling ref>"` and is never used after countersignature. **CI runs check mode only.** `--update-notes` (provenance string) is gated on a clean check run.
- For gv5-007/008 it re-encodes the receipt from the fixture's field values and compares the CBOR bytes and JSON text byte-for-byte — this is the test that catches key-order and encoding drift.
- Exit non-zero on any mismatch; prints per-vector `OK`/`FAIL`.
- Wired into CI (`.github/workflows/ci.yml`) as a required step.

### 4.6 Implementation ↔ JSON cross-check — `tests/v5_corpus.rs`

A Rust integration test in zombie-core that loads every `gv5-*`/`nv5-*` JSON and asserts the implementation produces the same digests, the same bytes, and the same named errors. This is the *other* leg of the triangle: harness proves text→values; this proves code→values; agreement of both proves text↔code. It is not the harness and must not be described as spec-derived.

### 4.7 Provenance discipline

- Every vector's `notes` states its derivation truthfully: `"Spec-derived via scripts/rederive-v5-vectors.py from docs/spec/mktd02-v5-serialization.md; encoder not consulted. Pending Stef/G countersignature."` — and **only once that is true**.
- `manifest.json`: `spec_version`, `protocol_version: "mktd02-v5"`, `harness`, `status: "pending_countersignature"`, the vector list with categories, the historical list with reasons.
- Any in-tree dump helper (if one exists or is added for convenience) is named `*_diagnostic_dump*`, documented "NOT a vector authority", and never invoked by CI or by the harness.
- The corpus README opens with the coverage list — which vectors the harness rederives, which the Rust cross-check covers, which are historical — and **never** says "every" unless it is every.

### 4.8 What "countersigned" means here

Countersignature is a **recorded human countersignature** — not a cryptographic signature; no signing key or algorithm is defined in this slice, and introducing one would be a separate ruling. It is a `countersignature` block in `manifest.json` containing: signer name(s), date, `corpus_commit_sha`, the SHA-256 of each vector file at that commit, and the basis ("spec-only harness check-mode green; clean-room rederivation of gv5-001…010: N matches, 0 mismatches, 0 underivable"). It is scoped to the listed vectors.

**Commit identity, without circularity:** `corpus_commit_sha` is the **CD-verified phase-7 commit** — the last commit whose content the corpus files had when CD passed. Phase 8 then creates a *later, administrative* countersignature commit that adds the block to `manifest.json` and changes nothing else; that commit attests the earlier, immutable corpus commit. **Leaf pins the phase-8 commit** (so its pin carries the countersignature); the vector files at the phase-8 commit are byte-identical to `corpus_commit_sha` (CD item 20 checks this).

## 5. Phases and gates

| Phase | Who | Deliverable | Gate |
|---|---|---|---|
| **1 — Formula text** | CC drafts per §4.1 and §2; C reviews against WP v5 / SHARED / rulings; Stef+G ratify | `docs/spec/mktd02-v5-serialization.md`, with every `[ORIGIN: implementation]` flag resolved by ruling | **Hard gate.** No vector work until ratified. Findings (text vs code disagreements) go to Stef/G as a list, not resolved by CC. |
| 2 — Vectors | CC | §4.2–4.4 JSON files with `inputs` only and `expected` **empty** | — |
| 3 — Harness | CC | §4.5; run **`--generate` once** to populate the empty `expected` fields from the formula text, then **check mode** green; `notes` records that values were produced by the harness from the text | Check mode green; no `subprocess`/FFI; CI wired to check mode only |
| 4 — Cross-check | CC | §4.6 Rust test green against the harness-produced values | Any disagreement = a finding (text vs code), escalated; **not** fixed by editing the vector |
| 5 — Notes | CC | `slice3_notes.md`: item→commit map; findings; every text-vs-code disagreement and its ruling; "unanticipated" list | — |
| **6 — Clean-room rederivation** | C, in a **fresh session** | Input isolation is the evidence, not recollection. CC prepares an **inputs-only bundle**: the ratified formula text, and every gv5/nv5 JSON with `expected` **stripped**, plus a bundle manifest (file list + SHA-256). The clean-room session receives **only that bundle** — no repository, no Rust tests, no expected values, no CC notes, no prior implementation discussion. It derives every value from the text and reports: matches / mismatches / underivable, and records exactly what it received (the bundle manifest) as the isolation evidence. | **Hard gate.** Zero mismatches, zero underivable. Any underivable = the text is incomplete → back to phase 1 for that item. |
| 7 — CD | CD | §7 checklist | CONFORMANT; the verified commit is `corpus_commit_sha` |
| 8 — Countersign | Stef (+G) | Administrative commit adding the §4.8 block to `manifest.json`; nothing else changes; no tag | Corpus is normative |
| 9 — Leaf re-pin | CC | One commit in Leaf pinning the **phase-8** zombie-core commit; suites green | Slice 3 closed |

## 6. Rules CC must follow

- Read before every edit; one commit per item; fmt / clippy `-D warnings` / test / audit clean; no new dependencies (the harness is stdlib Python; `tests/v5_corpus.rs` uses only what is already in the dev-dependency graph).
- **Never edit an `expected` value to make a test pass.** A disagreement is a finding.
- **Never consult the encoder to fill a gap in the formula text.** Flag the gap.
- The formula text and the corpus README use the reader's vocabulary: define `CVDR`, `certified data`, `tag`, `preimage` on first use. No internal slice/gate names in either.
- Report, don't resolve: `slice3_notes.md` lists everything this spec did not anticipate.

## 7. CD verification checklist

Each item PASS / FAIL / NOT VERIFIABLE with file:line evidence. CD reads §1–§6 first; notes only after.

**Formula text**
1. `docs/spec/mktd02-v5-serialization.md` exists, is self-contained (§4.1 rules), and every formula cites an origin; no unresolved `[ORIGIN: implementation]` flag remains; the ratification line (Stef/G, date) is present.
2. Historical constructions are in a separated section, marked retired with date and ruling.
3. The lock-gate section exists; the countersignature box is unchecked until phase 8.

**Harness independence**
4. `scripts/rederive-v5-vectors.py` imports only standard-library modules; contains no `subprocess`, `ctypes`, `cffi`, or reference to any Rust artefact; its CBOR encoder is self-contained.
5. CI runs it as a required step.
6. Harness write policy: default invocation is read-only (no write site reachable without a flag); `--generate` writes only empty `expected` fields and refuses non-empty ones (test or demonstrate); `--force-regenerate` requires `--reason`; CI invokes check mode only (quote the workflow line); `--update-notes` is gated on a clean check run.

**Corpus content**
7. Every gv5 vector in §4.2 exists with `inputs`, `expected`, `normative`, `notes`, `status`; harness reports `OK` for each.
8. Every nv5 vector in §4.3 exists with the expected named error and layer; `tests/v5_corpus.rs` asserts each; nv5-011 asserts *acceptance*.
9. gv5-007 and gv5-008 pin CBOR bytes and JSON text; the harness re-encodes from field values and matches byte-for-byte; the Rust cross-check matches the same bytes.
9a. The formula text's wire-freeze section (§4.1) specifies every item in the CBOR and JSON lists — CD ticks each: representation, lengths, key order, byte strings, principal, integer encoding, optional-field handling; JSON compact/pretty choice, whitespace, escaping, ordering, hex case, principal text, optional handling. Any item absent = FAIL (the byte-exact vectors would not be derivable from the text).
10. gv5-005 pins genesis with raw principal bytes and no length prefix (compare against a hand-computed value in the report).
11. gv5-010 covers every tag in the active registry, none missing, none retired.
12. `v4-historical/` vectors are present, marked historical, and referenced only through `hash_historical`.

**Provenance**
13. Every `notes` string is true as of the verified commit (no "independent" claim before phase 6; no "every" in the README unless it is every).
14. `manifest.json` status is `pending_countersignature` (before phase 8) with the correct vector list and harness path; no `countersignature` block is present before phase 8.
15. No dump helper is invoked by CI or the harness; if present, it is named and documented as diagnostic-only.

**Cross-check**
16. `tests/v5_corpus.rs` passes; it loads the JSON rather than embedding values; any disagreement with the harness values is absent (or, if present, recorded as an open finding with a ruling reference).

**Hygiene and scope**
17. fmt / clippy `-D warnings` / audit clean; no new crates; no change to any construction, tag, preimage, wire shape or named error (diff `src/` against `8fa8f91`: tests and the loader only).
18. No CVDR-Verify, DaffyDefs or Leaf code change; Leaf touched only by the phase-9 re-pin commit.
19. nv5-011a/b/c exist as three explicit cases (v2, v3, v4 labels), each asserting acceptance.
20. *(post-countersignature check, run at phase 9)* The vector files at the phase-8 commit are byte-identical to those at `corpus_commit_sha`; the phase-8 commit changes `manifest.json` only; Leaf pins the phase-8 commit.

**Then** read `slice3_notes.md`: (a) findings and unanticipated items with assessment; (b) anything CC missed; (c) notes-vs-spec disagreements (spec governs).

## 8. What this unlocks

On countersignature: the v5 corpus is normative. Slice 4 (CVDR-Verify) consumes it — the verifier must pass every gv5 and reject every nv5 by name, and it inherits nv5-009/010 as its V1 corpus. Slice 5 (DaffyDefs) rebuilds against the countersigned zombie-core commit. Neither starts before phase 8.
