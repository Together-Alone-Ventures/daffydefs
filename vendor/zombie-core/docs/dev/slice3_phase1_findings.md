# MKTd02 v5 Slice 3 — phase 1 findings

Companion to `docs/spec/mktd02-v5-serialization.md` (draft, unratified). Nothing here is resolved: every item is for Stef/G ruling before phase 2.

Repo `zombie-core`, branch `v5`. Authority: the corpus specification as amended at `ac5c32d` (G's pre-ratification review, 12 Sep 2026), which landed during this phase; the draft was begun against its predecessor `4f32eb8` and re-checked against `ac5c32d`. Cross-repo references are to `ICP-Delete-Leaf` at `b64abbd` (engine) unless stated.

---

## A. Source availability — read this first

**A-1. The White Paper v5 is not available to this session.** The corpus specification §2 names "the White Paper v5 (Figure 4, §2.2)" as the primary derivation source. No such document exists anywhere under `/home/stef` in any searched form (`*white*paper*`, `*WP*`, `.md`/`.txt`/`.docx`/`.pdf`). The only file matching "white paper"/"Figure 4" is `/home/stef/tav/antoine-review/v5.txt`, which is an **MKTd01** build assessment whose "v5" is that document's own revision number; it contains no MKTd02 formulas, no Figure 4 and no §2.2. Consequence: §3.7 of the formula text cites Figure 4 second-hand, via the corpus specification, and **no formula in this draft was derived from the White Paper**.

**A-2. The SHARED context-pack formula sections are not available to this session.** No context pack, `SHARED*` document, or clone of the shared documentation repository exists locally. The shared docs are referenced elsewhere in the suite only as a remote pinned ref. Consequence: the second named source contributed nothing.

**A-3. What the draft was actually derived from.** The ratification record (`docs/dev/MKTd02_v5_Slice1_Direct_Certification_Spec_AMENDED_Sep2026.docx`), the rulings (SR-06, 1b.1, 1b.4, 1b.5, 1b.7, 1c, 1d; `docs/dev/slice1_notes.md` §6, and the MKTd02 repository's `docs/dev/slice1_notes.md`), `RELEASES.md` v0.4.0/v0.5.0, the corpus specification §4.1 itself, and the MKTd02 integration README's published `receipt_id` line. The ratified MKTd01 document `docs/spec/serialization-v1.md` (MKTd01 repository) was used as a structural precedent only, not as a source of MKTd02 formulas.

**A-4. Where the two missing sources actually bite.** Under the amendment, phase 6 is a clean-room rederivation from an inputs-only bundle — the ratified formula text plus vectors with `expected` stripped — so the absent White Paper does not block phase 6. It blocks **phase 1 itself**: the phase-1 row still reads "C reviews against WP v5 / SHARED / rulings", and that review cannot be performed against documents no one in this session can open. Either the White Paper and the shared pack are supplied to the reviewer, or the ratification records that this text's origins are the rulings, the ratification record and the release notes, and that the WP/SHARED reconciliation is outstanding (it is carried as an unchecked lock-gate item in the draft §9).

---

## B. Pre-existing normative formula text: **NOT FOUND** (in this repository)

- `zombie-core` has no `docs/spec/` directory prior to this phase and no normative formula document. The only in-repo formula statements are release-note prose (`RELEASES.md:24`, `:35`–`:42`, `:106`, `:136`–`:138`) and code comments.
- Nearest equivalents found elsewhere, none of which is an MKTd02-v5 normative formula text:
  - `MKTd01/docs/spec/serialization-v1.md` — ratified, but a **different product**. Used as structural precedent (its §1 and §11 shape §1.1 and §9 of the draft).
  - `ICP-Delete-Leaf/README.md:18` — the published `receipt_id` formula. This is the **only** v5 hash formula found in published product text, and the draft cites it.
  - `ICP-Delete-Leaf/docs/sections/11-deterministic-encoding.md` — adapter state-encoding rules (determinism, no floats, field order). Relevant to §3.2's `state_bytes` but states no hash formula.
  - `CVDR-Verify` — no formula document; `docs/spec` does not exist there.

The circularity hazard of corpus specification §2 therefore applies in its second form: **no normative text existed**, so one had to be written, and it must not be a transcription of the encoder. Section C is the honest accounting of where that rule bit.

---

## C. `[ORIGIN: implementation — needs ratification]` flags

Each is a place where the available text was silent and only the code supplied an answer. The amendment states the expectation directly for the wire rows: "ratification turns an implementation fact into a **normative decision**, which is legitimate; silently transcribing it is not." Every item below is presented for that decision.

| # | Item | Draft § | Code |
|---|---|---|---|
| F-1 | `sha256_concat` (untagged hashing) exists at all as a v5 primitive | 1.2 | `src/hashing.rs:167` |
| F-2 | Active-registry membership of `MKTD02_SALT_V1`, `MKTD02_MANIFEST_V1`, `MKTD02_RECEIPT_V1` | 2.1 | `src/hashing.rs:61`–`:70` |
| F-3 | **`state_hash` in full** — salt derivation, untagged outer hash, operand order | 3.2 | `mktd02/src/state.rs:15`–`:27` (MKTd02 repo) |
| F-4 | `tombstone_hash` preimage parts and their order | 3.3 | `mktd02/src/engine.rs:124`–`:133` (MKTd02 repo) |
| F-5 | Integer encoding (`u64_be`) of `timestamp` and `deletion_seq` in `tombstone_hash` and `deletion_event_hash` | 3.3, 3.4 | `mktd02/src/engine.rs:139`–`:147`; `src/hashing.rs:398` |
| F-6 | Receipt field list **and order** (14 fields) | 4.1 | `receipt.rs:1024`–`:1048`, pinned `:2198` |
| F-7 | CBOR: definite-length map, text keys, declaration order | 4.2 | `receipt.rs:1023`; golden `:1633` |
| F-8 | CBOR: 32-byte fields and `record_id` encode as **arrays of uints**, not byte strings | 4.2 | `receipt.rs:106`–`:136`; golden `:1633` |
| F-9 | CBOR: `canister_id` is a byte string of raw principal bytes | 4.2 | golden `:1633` (`0x44 01020304`) |
| F-10 | CBOR/JSON: absent optional certificate is emitted as `null` with the key present | 4.2, 4.3 | `receipt.rs:145`–`:160`; **not pinned by any test** — see D-5 |
| F-11 | JSON: lowercase hex, no `0x`; `canister_id` as textual principal; numbers for the two integers | 4.3 | `receipt.rs:106`–`:136`; golden `:1646` |
| F-12 | Decode tolerance: `0x`/uppercase hex accepted; byte-array forms accepted; 32-byte length enforced | 4.4 | `receipt.rs:97`–`:125` |
| F-13 | `record_id`/`deletion_seq` structurally optional, semantically required; `trust_root_key_id` defaults to `""` | 4.4 | `receipt.rs:1066`–`:1086`, `:1140`–`:1151` |
| F-14 | Error precedence **below** the ruled unknown-key rule (protocol → retired-field → zero-hash → missing fields) | 4.6 | `receipt.rs:1117`–`:1151` |
| F-15 | Exact expected text of the structural `unknown field` error | 7 | serde-generated |
| F-16 | `mktd02-v2` historical `receipt_id` formula | 8.2 | `receipt.rs:521` |
| F-17 | JSON compact form as normative (pretty non-normative); no-whitespace and no-trailing-newline policy; escaping policy; plain-decimal numbers | 4.3 | `receipt.rs:1646` (v3 golden string); serialiser behaviour |

F-3 and F-6 are the two that matter most: the first is an entire recomputed value with no textual origin, the second is the object the corpus must freeze byte-exactly. F-17 exists only because the amendment requires the JSON policy items to be stated; none of them has any textual origin.

---

## D. Disagreements and unstated conflicts (recorded verbatim, not resolved)

**D-1. Genesis ruling date: 11 vs 12 September 2026.**
- Corpus specification §4.1 says: "`genesis_certified_data` | tag (`MKTD02_GENESIS_V1`), preimage = raw principal bytes, **no length prefix** (ruled 11 Sep 2026)".
- The ratification record says: "Genesis (ruled 12 Sep 2026): before the first deletion, certified_data = hash_with_tag("MKTD02_GENESIS_V1", canister_id.as_slice()) — tag followed by raw principal bytes, no length prefix."
- Code says (`src/receipt.rs:929`): "Preimage (ruled 11 Sep 2026): tag ‖ raw principal bytes (`Principal::as_slice()`), with **no length prefix**."
- The formula is identical in all three; only the ruling date differs. The draft records both dates.

**D-2. `state_hash` and `tombstone_hash` are not produced by this repository.** The corpus specification §3 puts "the normative formula text for every hash … a v5 verifier recomputes" in `zombie-core`, and §4.2 requires `gv5-002` (`tombstone_hash`) here. Both values are computed in the **MKTd02 engine repository**, which this crate does not depend on and cannot test against. `state_hash` additionally depends on the canister's own principal at runtime (`ic_cdk::api::canister_self()`), so a verifier must obtain that principal independently. No text states either construction.

**D-3. `MKTD02_MANIFEST_V1` and `MKTD02_RECEIPT_V1` are "active" but unused by v5.** Corpus specification §4.2 requires `gv5-010` to cover "every active tag", and §7 item 11 requires "every tag in the active registry, none missing, none retired". Taken literally this pins a per-tag golden for a manifest tag whose value (`manifest_hash`) was removed from the receipt at v0.2.0, and for the v2-only receipt tag. Whether "active" means "not retired" or "used by v5" changes what `gv5-010` must contain.

**D-4. `certified_data` is never set by this crate.** The draft §3.7 states the rule that certified data equals `deletion_event_hash`. `zombie-core` only provides `genesis_certified_data` and `check_certified_data_not_genesis`, both verifier-side (`receipt.rs:933`, `:939`); publication happens in the engine. A vector for §3.7 can only assert the *equality rule*, not observe the platform behaviour.

**D-5. The pending-receipt wire shape is unpinned by any existing test.** Every v5 wire test uses a fixture with **both** certificates present (`receipt.rs:2179`–`:2256`). Nothing currently pins what a pending v5 receipt looks like on the wire. The draft states, from the code path only (F-10), that both keys are emitted as `null`. This is exactly what `gv5-008` will freeze, so it should be ruled before that vector is written. Note the contrast the corpus will record: the frozen v3 shape **omits** `module_hash_certificate` entirely (`receipt.rs:1656`), while v5 emits it as `null`.

**D-6. JSON key order is pinned for v3 but not for v5.** `v3_json_byte_identical_to_head_golden` (`receipt.rs:1645`) pins the full v3 JSON string. The v5 equivalent test sorts the key list before comparing (`receipt.rs:2218`–`:2222`), so v5 JSON key order is currently asserted only as a *set*. The draft §4.3 freezes the order; `gv5-007`/`008` will be the first artefacts to pin it.

**D-7. `hash_with_tag`'s retired-tag guard is debug-only, and `DomainTag.0` is public.** `src/hashing.rs:150` debug-asserts against retired tags; release builds do not. A retired tag can be rebuilt as `DomainTag(b"MKTD02_CERTIFIED_V1")` in a release build. Already filed as a later-review candidate; restated here because the draft §1.3 asserts `hash_historical` is "the only sanctioned way", which is a discipline, not an enforced property.

**D-8. Frozen-line label matching remains prefix-based.** `"mktd02-v4-rc1"`, `"mktd02-v20"` and `"mktd02-v3junk"` classify as frozen lines (`receipt.rs:255`–`:260`). The draft records this in §8.3. It is already a known open item; it matters here because `nv5-007`/`nv5-008` sit next to it, and the amendment's `nv5-011a/b/c` now exercise all three historical labels, so a reader of the corpus will ask why v5 is exact and v2–v4 are not.

**D-9. The frozen v4 type's error strings still say `DeletionReceipt:`.** `receipt.rs:902` and the v4 arms report `"DeletionReceipt: unrecognised protocol_version …"`. This was ruled kept verbatim. It is recorded because `nv5-008` must state an exact expected string for the v4-type-refuses-v5 direction, and that string names a type that no longer exists.

---

## E. Items the corpus specification asks for that this draft could not fully supply

- **§4.1 row `state_hash` ("input bytes, tag if any, exact construction")** — supplied only from the implementation (F-3). A reader with SHA-256 and this document can compute it *only* if they also accept the unratified salt construction.
- **§4.1 row "Receipt wire (v5) — byte-exact freeze"** — every CBOR and JSON item on the amended checklist is stated in draft §4.1–§4.6, and almost all of it is implementation-origin (F-6…F-14, F-17), as the amendment anticipates. CD item 9a can be ticked item by item against those sections.
- **§4.1 row "Tag registry … every active tag's exact ASCII bytes"** — supplied; membership question open (D-3).
- **§4.1 "Each formula cites its origin: White Paper v5 section, SHARED pack section, or ruling (date)"** — no formula could cite a White Paper or shared-pack section (A-1, A-2). Every citation is a ruling, the ratification record, release notes, or the published README line.

---

## F. Unanticipated

- The draft avoids internal slice and gate names per the corpus specification's vocabulary rule, so rulings are cited by identifier and date and the corpus specification is cited as "the corpus specification". If the ratified text should instead name the slice documents, that is a wording ruling.
- The lock gate (§9) marks ratified items checked and every implementation-origin item unchecked, including "Countersignature on v5 vectors". Fifteen items are unchecked; that is the honest state, not an omission.
- The authority moved during this phase: `4f32eb8` → `ac5c32d` (amended on G's pre-ratification review). The draft and this list were re-checked against the amended text. The amendment's other changes — harness `--generate`/check-mode asymmetry, countersignature commit identity, the clean-room bundle, `nv5-011a/b/c` — are phase 2+ and change nothing in phase 1 beyond A-4 and the JSON items (F-17).
- No vectors, harness, tests or `src/` files were touched in this phase, and nothing was committed.

---

## Dispositions

Stef and G ruled these findings on 12 Sep 2026. The authoritative dispositions, rationale, and source reconciliation are in `docs/dev/slice3_phase1_rulings.md`; this section points to them without rewriting the original findings.

### F-items

| Finding | Disposition pointer |
|---|---|
| F-1 | Rulings §C, F-1 — ratified as v5 design; future tagged-outer-hash candidate recorded. |
| F-2 | Rulings §C, F-2 — active means not retired; registry regrouped into v5-used and other-line tags. |
| F-3 | Rulings §C, F-3 — salt re-cited to SHARED 289; outer hash/order ratified; gv5-011 added. |
| F-4 | Rulings §C, F-4 — re-cited to SHARED 290; tag-case typo noted; diagnostic-only statement added. |
| F-5 | Rulings §C, F-5 — 8-byte big-endian integers ratified as design. |
| F-6 | Rulings §C, F-6 and decision A-1(a) — field list/order ratified; v5 event preimage binds existing `receipt_id`. |
| F-7 | Rulings §C, F-7 — definite CBOR map, text keys, and declaration order ratified. |
| F-8 | Rulings §C, F-8/F-9 and decision A-2(b) — corrected before freeze to CBOR byte strings. |
| F-9 | Rulings §C, F-8/F-9 and decision A-2(b) — `canister_id` remains a CBOR byte string and all other byte fields now match it. |
| F-10 | Rulings §C, F-10 — absent optional fields remain present as `null`; gv5-008 will pin the rule. |
| F-11 | Rulings §C, F-11 — JSON hex, principal, and integer representations ratified. |
| F-12 | Rulings §C, F-12 — tolerant decode ratified; gv5-012 added. |
| F-13 | Rulings §C, F-13 — structural/semantic optionality and default ratified. |
| F-14 | Rulings §C, F-14 — error precedence ratified beneath the unknown-key ruling. |
| F-15 | Rulings §C, F-15 — `unknown field` is a required prefix, not an exact framework-owned full string. |
| F-16 | Rulings §C, F-16 — ratified as historical record only. |
| F-17 | Rulings §C, F-17 — compact JSON and byte policy ratified. |

### D-items

| Finding | Disposition pointer |
|---|---|
| D-1 | Rulings §C, D-1 — genesis was ruled 11 Sep 2026; corrected consistently. |
| D-2 | Rulings §C, D-2 with F-3/F-4 — formulas stay normative here; phase 9 adds the Leaf cross-check. |
| D-3 | Rulings §C, D-3 with F-2 — resolved by explicit active-tag groupings. |
| D-4 | Rulings §C, D-4 — accepted; corpus asserts the equality/rejection rules while Leaf T6/T7 cover platform behavior. |
| D-5 | Rulings §C, D-5 with F-10 — gv5-008 pins the pending shape. |
| D-6 | Rulings §C, D-6 — gv5-007/008 pin v5 JSON key order. |
| D-7 | Rulings §C, D-7 — known and deferred to Slice 6; no v5 change. |
| D-8 | Rulings §C, D-8 — known and deferred to Slice 6; historical wording stands. |
| D-9 | Rulings §C, D-9 — frozen verbatim; nv5-008 records it. |

Decisions A-1(a) and A-2(b) were implemented and independently verified in Slice 3a; CD reported CONFORMANT on 13 Sep 2026. Source-availability items A-1 through A-4 are reconciled by the ratification list itself, as stated in its §C `A-1…A-4` row.
