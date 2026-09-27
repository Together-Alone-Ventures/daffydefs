# mktd02-v5.1 independent vector derivation

**Status:** independently rederived, **pending countersignature**. This corpus is a proposal for the three-way comparison required by the amendment §14 (amendment / White Paper ↔ normative specification ↔ independent vectors). It is not countersigned here.

**Rederiver:** CC (not the author of the normative v5.1 specification). Base: `v5.1-correction` @ `48d3eeaa00559fa7622065fccd056e25b779b476`.

## Derivation inputs

| # | Input | Used for |
|---|---|---|
| A | `docs/rulings/2026-09-25-mktd02-v5.1-amendment.md`, SHA-256 `7fe9b0fa4cdb4055f0c44cac0fce47475356d4df30371311fb16dbf1096fc12a` (checked by the harness on every run) | Every v5.1-specific rule: exact `protocol_version = "mktd02-v5.1"` (§3), the EVENT_V3 formula (§4), `module_hash` separation (§5), pending structural absence (§6), the finalisation set and state rule (§9), exact dispatch (§3), the frozen historical EVENT_V2 line (§2) |
| B | The Stef/G-ratified `mktd02-v5` serialization text as frozen at zombie-core commit `2237238` (`git show 2237238:docs/spec/mktd02-v5-serialization.md`, SHA-256 `1f1f1c61d8e8625f6333de61bcc29b9ae4eaa5ef4df00f99fe147219b69b5825`) | **Only** byte rules the amendment carries forward unchanged under §3: `hash_with_tag` (§1.1), `TOMBSTONE_CONSTANT` and `tombstone_hash` (§3.1, §3.3), `receipt_id` (§3.5), field order, CBOR and JSON (§4.1–§4.3, applied to the fields present), principal text form (§4.3), V1 rejection names and order (§7) |
| — | White Paper v5.2 | Consulted for carried-forward rules; it states the receipt inputs and "SHA-256" but not byte-level tags, framing or encodings, so input B was authorised (by Stef, 27 Sep 2026) for those carried-forward byte rules only |

**Not used as a derivation source:** the normative v5.1 specification (`docs/spec/mktd02-v5-serialization.md` at the `v5.1-correction` head), the v5.1 conformance matrix, any zombie-core / ICP-Delete-Leaf / CVDR-Verify source, and any expected value supplied by the specification author. There is no v5.1 implementation.

**Historical v5 vectors** are read only in `--check` mode to prove the historical freeze. No v5 expected value is copied into a v5.1 expected value. gv51-001 and gv51-003 reuse the gv5-003 **operand** values so the EVENT_V2/EVENT_V3 contrast is direct. Their expected values are computed fresh.

## Formulas as written fresh from the amendment

```text
receipt_id          = ReceiptId(canister_id, record_id, deletion_seq)          (A §4; bytes per B §3.5)
deletion_event_hash = H_tag("MKTD02_EVENT_V3",
                            pre_state_hash, post_state_hash, receipt_id,
                            u64_be(timestamp), u64_be(deletion_seq))          (A §4)
H_tag(tag, parts)   = SHA-256(tag ‖ part_0 ‖ …), tag as exact ASCII, no framing (B §1.1)
```

Relative to the historical EVENT_V2 line (A §2):

- **Added:** the tag `MKTD02_EVENT_V3` and the protocol string `mktd02-v5.1`.
- **Removed:** the `module_hash` operand.
- **Unchanged:** the operand order of the remaining five parts, the explicit `deletion_seq`, and the exclusion of `manifest_hash`.

## Corpus

| ID | Proposition | Governing |
|---|---|---|
| gv51-001 | EVENT_V3 golden over fixed operands (seq 7 and 8), with the full preimage bytes | A §4 |
| gv51-002 | `receipt_id` then EVENT_V3 over a derived identity | A §4, B §3.5 |
| gv51-003 | `module_hash` is not an operand: EVENT_V3 is equal for two `module_hash` values, the historical EVENT_V2 differs, and both finalized receipts pass V1 | A §4, §5, §2 |
| gv51-004 | `receipt_id` is load-bearing: changing it directly, or through `record_id`, changes EVENT_V3 | A §4 |
| gv51-005 | Positive finalized v5.1 receipt: 14 keys, CBOR, compact JSON, `FinalizedCandidate`, V1 pass | A §3, §4, §9; B §4 |
| gv51-006 | Positive pending v5.1 receipt: 10 keys, with the four finalisation fields structurally absent (no `null`, `""` or zero); `Pending`; same event hash as gv51-005 | A §6, §9; B §4 |
| gv51-007 | Version/tag registry and exact dispatch (v5 → EVENT_V2, v5.1 → EVENT_V3) | A §2, §3, §19 |
| nv51-001 | 13 near-match protocol strings refused on decode and serialise | A §3 |
| nv51-002 | Cross-line dispatch: v5.1 label with an EVENT_V2 value, and v5 label with an EVENT_V3 value → `v1:event-hash-mismatch` | A §2–§4, B §7 |
| nv51-003 | Each single missing finalisation field (4 cases), and each single present field on a pending receipt (4 cases) → `InvalidIncompleteFinalization` | A §6, §9 |
| nv51-004 | Placeholders (`null`, `""`, all-zero) on a pending receipt are not structural absence → refused | A §6 |
| nv51-005 | V1 mutations of gv51-005 (`record_id`, `record_id`+`receipt_id`, `timestamp`, `deletion_seq`, and `module_hash` only, which passes V1 by design) | A §4, §5, B §7 |
| nv51-006 | Retired `certified_commitment` present on a finalized (gv51-005) or pending (gv51-006) v5.1 receipt, with a 32-byte value or `null` → refused on decode; outcome only | A §3, B §4.4, §4.6, §7 (carried forward) |

Certificate fields carry **opaque** bytes. These vectors fix wire shape, state and V1 only. V2, V3A and PR-7 extraction need real certificate trees and are outside this corpus.

## Not fixed by the governing inputs (recorded, not invented)

- **v5.1 rejection message fragments.** nv51-001, nv51-004 and nv51-006 assert the outcome (refused) only. A fixes the rule but not a message. B §7 names the v5 retired-field rejection; that string is not asserted for v5.1.
- **Layer for placeholder refusal (nv51-004).** A §6 forbids the representation but does not fix the layer.

## Reproduce

```text
python3 docs/test-vectors/v5.1/rederive_v5_1_independent.py --check
```

The check regenerates every v5.1 file in memory and compares it byte-for-byte. It verifies the amendment SHA-256 and the countersigned v5 file pins (`docs/test-vectors/manifest.json`, which is unchanged). It then reproduces, independently, the historical gv5-003 EVENT_V2 values and the gv5-007 `receipt_id`, EVENT_V2, CBOR and JSON. `--write` regenerates the files. The harness uses the standard library only and imports nothing from zombie-core.

As an additional cross-check, the gv51-001 seq-7 value `02b161e2…0bb42ba7` was reproduced with `sha256sum` over a hand-built preimage.
