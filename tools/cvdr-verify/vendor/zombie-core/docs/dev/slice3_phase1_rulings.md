# MKTd02 v5 Slice 3 — Phase 1 Ratification List

**Status:** C's review of `docs/spec/mktd02-v5-serialization.md` (draft) and `docs/dev/slice3_phase1_findings.md` against White Paper v5 (Table 3, Figure 4, §2.2 narrative) and the July SHARED context pack (MKTd02 formula lines 287–293). For Stef + G ratification, 12 Sep 2026. On ratification this file is committed alongside the formula text, and the formula text's citations and lock gate are updated accordingly (phase 1b, CC, one commit).

**Framing (Stef, 12 Sep):** the White Paper defines what is delivered as read by a general readership; it is not a technical specification. Flags therefore fall into two bins — **claims-bearing** (must match the WP) and **design detail** (the WP is silent by design; ratification makes the implementation choice normative). Only the first bin can produce a defect.

---

## A. Two decisions required (claims-bearing)

### A-1. `deletion_event_hash` does not bind `receipt_id`, but the White Paper says it does — DECISION

**WP text.** Table 3, `deletion_event_hash`: "A single commitment binding the pre-state, post-state, **receipt identity**, event time and deletion sequence." `receipt_id` row: "This is the mechanism that binds the external target identifier (record_id) into the certified chain." Narrative: "record_id is bound into the certified deletion event via receipt_id."

**Construction (draft §3.4, SHARED line 291, code).** `deletion_event_hash = H(MKTD02_EVENT_V1, [pre_state_hash, post_state_hash, u64_be(timestamp), module_hash, u64_be(deletion_seq)])`. No `receipt_id`; `module_hash` present (the WP row omits it).

**Consequence.** `record_id` is not bound into the certified value. A receipt carrying a different `record_id` with `receipt_id` recomputed passes V1 (internal consistency) and V2 (certified_data equals the unchanged `deletion_event_hash`). In Leaf mode the exposure is bounded by one-canister-one-subject and by `canister_id` being certified; it is not bounded in Tree mode, and the WP claims the binding without that qualification.

**Options.**
- **(a) Amend the construction now:** add `receipt_id` to the preimage — `[pre_state_hash, post_state_hash, receipt_id, u64_be(timestamp), module_hash, u64_be(deletion_seq)]`. Cost: one 32-byte part; the engine already computes `receipt_id` from values available before the event hash (reorder two statements); the Slice 1 statement "deletion_event_hash preimage unchanged" was a Slice-1 scope boundary, not a v5 freeze — v5 is not frozen until countersignature, and this is the last cheap moment. The WP row then gains "module identity" to match. **C recommends (a).**
- **(b) Amend the White Paper instead:** state that target binding is by `canister_id` (certified) plus the Leaf one-subject property, and that `receipt_id` is checked in V1 only. Weaker claim; Tree mode inherits the gap.

Either way the WP row must list `module_hash` ("module identity"), which it currently omits — a WP edit-list item.

### A-2. CBOR byte fields are encoded as arrays of integers, not byte strings — DECISION

**Finding (F-8, F-9).** Every 32-byte field, `record_id` and both certificates encode as a CBOR **array of unsigned integers, one per byte** (a serialisation-framework default for fixed arrays), while `canister_id` encodes as a CBOR **byte string**. Effects: a 32-byte hash costs 33–65 bytes on the wire depending on values; the receipt's own encoding is inconsistent; and every non-Rust verifier must reproduce a framework idiom rather than "bytes are byte strings".

**Options.**
- **(a) Ratify as-is for v5.** Zero code change; the freeze records it; CVDR-Verify and any future verifier implement the idiom.
- **(b) Rule a wire correction before the freeze:** all byte-valued fields (`receipt_id`, the four hashes, `module_hash`, `record_id`, both certificates) become CBOR byte strings (major type 2), matching `canister_id`. One attribute-level change in zombie-core plus tests; JSON unaffected (already hex); frozen v2–v4 wire untouched; CVDR-Verify has not implemented v5 yet so nothing downstream breaks. **C recommends (b)** — it is the last moment this costs nothing, and the corpus will then freeze a representation a reader would expect.

If (b): it is a small pre-phase-2 zombie-core change with its own CD delta, and gv5-007/008 pin the corrected form.

---

## B. Claims-bearing items that reconcile (no action)

| Item | WP says | Construction | Verdict |
|---|---|---|---|
| Certified value | V2: `certified_data = deletion_event_hash`; Figure 4 | §3.7 | **Matches.** Origin: WP Figure 4 + SR-06. Cite the WP. |
| `receipt_id` inputs | "derived from canister_id, record_id and deletion_seq" | §3.5 (SHARED 288 verbatim) | **Matches.** Tag and length prefixes are design detail with SHARED origin. |
| `post_state_hash` recomputable | "Recomputed from the defined tombstone state and checked against the CVDR value" | §3.2 | **Matches only if the construction is published.** See C-1: `state_hash` cannot be "out of scope" — the WP promises verifiers can recompute it. |
| `pre_state_hash` not recomputable by independent verifier | stated | §3.2 | **Matches** (needs the private state bytes). |
| `tombstone_hash` | "SHA-256(canister_id, canonical null value, timestamp, deletion_seq)"; **diagnostic only, not in the verification chain** | §3.3 (SHARED 290) | **Matches** in parts and order; tag and widths are design detail. The text should carry the WP's "diagnostic only" statement. |
| V3A / V3B; V4 retired | stated | Slice 2 docs | **Matches.** |
| Genesis | not in WP (design detail below the WP's level) | §3.6 | No conflict; WP silent by design. |
| "This guarantees the code that was executed" | WP narrative | — | Already on the WP edit list (retired construction); not a formula matter. |

---

## C. Rulings on the flags (F-1 … F-17) and disagreements (D-1 … D-9)

| # | Disposition |
|---|---|
| **F-1** `sha256_concat` as a v5 primitive | **Ratify as design** — used only for the `state_hash` outer hash (§3.2). Record as a candidate for a tagged construction in a future line; not changed in v5. |
| **F-2** active-registry membership | **Ratify with definitions:** *active* = not retired. `MKTD02_SALT_V1` is active and v5-used (SHARED 287, 289). `MKTD02_MANIFEST_V1` and `MKTD02_RECEIPT_V1` are active but **not v5-used**: `RECEIPT_V1` is used only by the frozen v2 line; `MANIFEST_V1` is reserved for a configuration with a manifest (not Leaf). gv5-010 covers the **v5-used** set (`TOMBSTONE_HASH`, `EVENT`, `RECEIPT_V3`, `GENESIS`, `SALT`); the other two get per-tag goldens in a separately labelled "active, other lines" group. Resolves D-3. |
| **F-3** `state_hash` | **Split.** Salt derivation `mktd_salt = H(MKTD02_SALT_V1, [canister_id_bytes])` has **SHARED origin (289)** — re-cite. Outer untagged hash and operand order: **ratify as design** for v5; record "tag the outer hash" as a future-line candidate. **Normative home:** the formula stays in this text (§3.2) and is cross-referenced from the Leaf state-encoding document, because the WP promises `post_state_hash` is recomputable (B row 3). Add **gv5-011**: a fixture `state_bytes` (the tombstone state for a fixed schema) → `mktd_salt` → `state_hash`, so the recomputation the WP promises is exercised. Resolves D-2 for `state_hash`. |
| **F-4** `tombstone_hash` parts/order | **SHARED origin (290)** — re-cite; ratify. Add the WP's "diagnostic only; not part of the verification chain" sentence. Note the SHARED pack's mixed-case tag spelling (`MKTd02_…`) is a documentation typo; the ASCII bytes are `MKTD02_TOMBSTONE_HASH_V1` (code). Resolves D-2 for `tombstone_hash` (pure function of inputs; corpus-computable). |
| **F-5** `u64_be` widths | **Ratify as design.** SHARED gives order without widths; 8-byte big-endian is the decision. |
| **F-6** field list and order | **Ratify as design** (subject to A-1: if (a), no field change — `receipt_id` is already a field; only the preimage changes). |
| **F-7** CBOR map, definite, text keys, declaration order | **Ratify as design.** |
| **F-8, F-9** byte representation | **Decision A-2.** |
| **F-10** absent optional = `null`, key present | **Ratify as design.** Resolves D-5; gv5-008 pins it. |
| **F-11** JSON hex/principal/numbers | **Ratify as design.** |
| **F-12** decode tolerance (`0x`, uppercase, byte-array form) | **Ratify as design**, with one addition: the corpus includes a positive vector (gv5-012) showing that tolerant inputs decode to the same receipt as canonical inputs, so tolerance is pinned rather than incidental. |
| **F-13** structurally optional / semantically required | **Ratify as design.** |
| **F-14** error precedence below the unknown-key rule | **Ratify as design.** |
| **F-15** exact `unknown field` text | **Ratify as a stated prefix**, not an exact string: the corpus asserts `unknown field` as a prefix; the remainder is framework-owned. |
| **F-16** v2 `receipt_id` formula | **Ratify as historical record** (§8.2). Not v5. |
| **F-17** JSON compact/whitespace/escaping | **Ratify as design.** Compact normative; pretty non-normative; no trailing newline; escaping as drafted. |
| **D-1** genesis date | **11 Sep 2026** (the Q8 ruling). 12 Sep is when corrections landed. Fix the ratification record's line in the same phase-1b commit. |
| **D-2** engine-computed values | Resolved under F-3/F-4. Phase 9 adds a small Leaf test loading gv5-002 and gv5-011 (engine ↔ JSON cross-check for the two engine-side values). |
| **D-3** tag membership | Resolved under F-2. |
| **D-4** `certified_data` never set by this crate | Accepted: the vector asserts the equality rule and the genesis rejection; platform behaviour is Leaf's T6/T7. |
| **D-5** pending wire unpinned | Resolved under F-10. |
| **D-6** v5 JSON key order asserted as a set | gv5-007/008 pin the order; the existing sorted-key test stays. |
| **D-7** debug-only guard | Known; slice 6. No change. |
| **D-8** prefix matching, frozen lines | Known; slice 6 (ruled safe). The text's §8.3 wording stands. |
| **D-9** frozen error strings say `DeletionReceipt:` | Frozen is frozen; nv5-008 records the string verbatim. |
| **A-1…A-4** (source availability) | The WP and SHARED reconciliation is **this document**; the lock-gate item ticks on ratification. Origins in the formula text are updated: WP Figure 4 for §3.7; SHARED lines for §3.2 (salt), §3.3, §3.4, §3.5; the remainder stays ruling/design. |

---

## D. Phase 1b — what CC does on ratification (one commit set, before phase 2)

1. Apply decisions A-1 and A-2 as ruled (if A-1(a) and/or A-2(b) are chosen, the corresponding zombie-core / Leaf changes land as their own small slice-3a with a CD delta *before* phase 2; the formula text is amended to match).
2. Update the formula text's origin citations per C (SHARED lines; WP Figure 4); add the WP's "diagnostic only" sentence to §3.3; add the F-2 tag groupings; add gv5-011 and gv5-012 to the corpus plan; fix the D-1 date.
3. Add the ratification line to the formula text and tick the lock-gate items ruled here; leave "independent rederivation" and "countersignature" unchecked.
4. Commit the formula text, this ratification list, and the findings file together: `docs(spec): mktd02-v5 serialization — ratified (Stef/G, <date>); phase 1 findings and rulings`.

Phase 2 (vectors, `expected` empty) begins on that commit.
