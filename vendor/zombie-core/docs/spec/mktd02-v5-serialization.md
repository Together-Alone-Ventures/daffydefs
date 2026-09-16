# MKTd02-v5 — Serialization and Hash Formulas

**Status:** RATIFIED.

**Ratification:** Ratified by Stef and G, 12 Sep 2026 (phase 1 rulings); amended 13 Sep 2026 for the Slice 3a corrections (A-1(a) EVENT_V2, A-2(b) byte strings), CD CONFORMANT.

**Scope:** every value a verifier of a `mktd02-v5` CVDR recomputes, and the byte-exact wire encoding of the receipt. Historical constructions (`mktd02-v2`…`mktd02-v4`) are in §8, separated from the normative v5 set.

**Authority:** this document, once ratified, is the derivation source for the published v5 test vectors. If the implementation and this document disagree on a formula or an encoding, that disagreement is a finding for ruling — neither side is silently adopted.

---

## 0. How to read this document

**Vocabulary, on first use:**

- **CVDR** — Cryptographically Verifiable Deletion Receipt: the record a canister emits when it deletes a data subject's fields, containing hashes (never plaintext) that an independent party can recompute.
- **Certified data** — the 32 bytes a canister publishes into the Internet Computer's certified state, which the subnet's signature authenticates. A verifier obtains it from a data certificate, not from the receipt.
- **Domain tag** (or **tag**) — a fixed ASCII byte string placed at the front of a hash input so that two different kinds of value can never collide, even with identical remaining bytes.
- **Preimage** — the exact ordered byte sequence fed to SHA-256 to produce a value.

**Origin citations.** Every formula cites where it comes from. A formula whose only source is the running code carries:

`[ORIGIN: implementation — ratified 12 Sep 2026]`

This retained flag identifies a design detail that originated in the implementation and was made normative by the phase 1 ruling; it is not deleted after disposition. See `docs/dev/slice3_phase1_findings.md` and `docs/dev/slice3_phase1_rulings.md` for the complete record.

**Conventions.**

- `u32_be(n)` — `n` as a 4-byte unsigned big-endian integer. `u64_be(n)` — 8-byte unsigned big-endian.
- `‖` — concatenation with no separator, no length framing, and no padding.
- `canister_id_bytes` / `record_id_bytes` — the raw bytes of an Internet Computer principal (its binary form, not its textual form).
- All digests are SHA-256 and are exactly 32 bytes.

---

## 1. Primitives

### 1.1 Domain-separated hash

```text
hash_with_tag(tag, [part_0, part_1, ...]) = SHA-256( tag ‖ part_0 ‖ part_1 ‖ ... )
```

- The tag is its exact ASCII bytes: no null terminator, no length prefix, no separator.
- Parts follow in the order given, concatenated exactly as supplied. There is no length framing *between* parts; where a length is needed it is an explicit part of the preimage (see §4.5).
- Output: 32 bytes.

*Origin:* corpus specification §4.1 (12 Sep 2026); identical discipline to the ratified MKTd01 rule (`docs/spec/serialization-v1.md` §1, MKTd01 repository). Confirmed at `src/hashing.rs:149`.

### 1.2 Untagged concatenation

```text
sha256_concat([part_0, part_1, ...]) = SHA-256( part_0 ‖ part_1 ‖ ... )
```

Used only where the leading part is itself a derived value rather than a tag (§3.2).

*Origin:* `[ORIGIN: implementation — ratified 12 Sep 2026]` (`src/hashing.rs:167`); ruling F-1. In v5 this primitive is used only for the `state_hash` outer hash. A tagged outer construction is a candidate for a future protocol line.

### 1.3 Retired-tag hashing

A retired tag may never be used to produce a new value. Recomputing a value issued under a retired construction uses the same tag-first discipline as §1.1 and is the only sanctioned use:

```text
hash_historical(retired_tag, [parts...]) = SHA-256( retired_tag ‖ part_0 ‖ ... )
```

*Origin:* ruling 1b.1 (12 Sep 2026). Confirmed at `src/hashing.rs:102`.

---

## 2. Tag registry

### 2.1 Active tags

“Active” means not retired. Active tags are grouped by whether the v5 line uses them.

**Active — used by v5**

| Tag (exact ASCII bytes) | Length | Used for |
|---|---|---|
| `MKTD02_TOMBSTONE_HASH_V1` | 24 | `tombstone_hash` (§3.3) |
| `MKTD02_EVENT_V2` | 15 | `deletion_event_hash` (§3.4) |
| `MKTD02_RECEIPT_V3` | 17 | `receipt_id` (§3.5) |
| `MKTD02_GENESIS_V1` | 17 | `genesis_certified_data` (§3.6) |
| `MKTD02_SALT_V1` | 14 | per-canister salt (§3.2) |

**Active — other lines**

| Tag (exact ASCII bytes) | Length | Used for |
|---|---|---|
| `MKTD02_EVENT_V1` | 15 | historical v2–v4 `deletion_event_hash` (§8.2) |
| `MKTD02_MANIFEST_V1` | 18 | `manifest_hash` — **not** part of any v5 receipt value |
| `MKTD02_RECEIPT_V1` | 17 | `receipt_id` of the frozen `mktd02-v2` line only (§8.3) |

`MKTD02_GENESIS_V1` was added by ruling SR-06 (11 Sep 2026). The grouping and active-registry membership are `[ORIGIN: implementation — ratified 12 Sep 2026]` (`src/hashing.rs:55`–`:84`); ruling F-2. `MKTD02_MANIFEST_V1` remains reserved for configurations that carry a manifest (not Leaf), and `MKTD02_RECEIPT_V1` remains active only for the frozen v2 line.

`MKTD_TOMBSTONE_V1` is **not** a tag. It is a constant seed (§3.1). A tag prefixes a hash; the tombstone constant is a value written into storage. They must never be interchanged.

### 2.2 Retired tags

| Tag | Retired | Ruling | Formerly |
|---|---|---|---|
| `MKTD02_CERTIFIED_V1` | 2026-09-11 | SR-06 | `certified_commitment` (`mktd02-v2`…`v4`) — see §8.1 |

A retired tag is never deleted from this registry and its bytes are never reused. It cannot be used to produce a new value; recomputation of historical values goes through §1.3.

*Origin:* ruling SR-06 (11 Sep 2026); ratification record 3.1 and 3.7; release notes v0.5.0 "Tag registry".

---

## 3. Recomputed values

### 3.1 `TOMBSTONE_CONSTANT`

The 32 bytes written into every PII field on deletion:

```text
TOMBSTONE_CONSTANT = SHA-256( "MKTD_TOMBSTONE_V1" )
```

The seed is hashed as its exact ASCII bytes (17 bytes, no terminator). Any verifier can recompute the constant from the published seed and so recognise a tombstoned field.

*Origin:* corpus specification §4.1 (12 Sep 2026). Confirmed at `src/tombstone.rs:22`.

### 3.2 `state_hash` (`pre_state_hash`, `post_state_hash`)

```text
mktd_salt  = hash_with_tag( "MKTD02_SALT_V1", [canister_id_bytes] )
state_hash = sha256_concat( [mktd_salt, state_bytes] )
```

- `state_bytes` are the adapter-encoded PII state: the deterministic CBOR encoding produced by the single sanctioned encoding entry point, with the field set and field order fixed by the integration's published State Encoding Specification. This encoding is deterministic under the library's encoder; it is **not** RFC 8949 canonical CBOR.
- The outer hash is **untagged**: the salt occupies the leading position, not a tag.
- `pre_state_hash` is computed over the state before the tombstone writes, `post_state_hash` over the state after them.

The exact `state_bytes` schema and field order are defined by the Leaf State Encoding Specification (`ICP-Delete-Leaf/docs/sections/11-deterministic-encoding.md`); this document defines the hashing construction applied to those bytes. The outer hash remains untagged in v5. Tagging that outer hash is recorded as a candidate for a future protocol line.

*Origin:* salt derivation: SHARED context pack line 289. Outer untagged hash and operand order: `[ORIGIN: implementation — ratified 12 Sep 2026]` (`mktd02/src/state.rs:15`–`:27`, MKTd02 repository); rulings F-1 and F-3. The salt binds the canister's own principal, which a verifier must obtain independently.

### 3.3 `tombstone_hash`

```text
tombstone_hash = hash_with_tag(
  "MKTD02_TOMBSTONE_HASH_V1",
  [ canister_id_bytes,
    TOMBSTONE_CONSTANT,
    u64_be(timestamp),
    u64_be(deletion_seq) ]
)
```

This value is **diagnostic only; it is not part of the verification chain**.

*Origin:* SHARED context pack line 290 for the preimage parts and order. The pack's mixed-case spelling `MKTd02_TOMBSTONE_HASH_V1` is a documentation typo; the exact ASCII tag bytes are `MKTD02_TOMBSTONE_HASH_V1`. Integer widths and endianness are `[ORIGIN: implementation — ratified 12 Sep 2026]` (`mktd02/src/engine.rs:124`–`:133`, MKTd02 repository); rulings F-4 and F-5.

### 3.4 `deletion_event_hash`

```text
deletion_event_hash = hash_with_tag(
  "MKTD02_EVENT_V2",
  [ pre_state_hash,
    post_state_hash,
    receipt_id,
    u64_be(timestamp),
    module_hash,
    u64_be(deletion_seq) ]
)
```

The v5 V1 consistency check first recomputes `receipt_id` from §3.5 and equality-checks it against the receipt. It then recomputes this event hash using that checked `receipt_id` and equality-checks the result. `deletion_seq` deliberately appears in both preimages: this redundancy binds it directly in both identities and is intentional.

`manifest_hash` is **not** in this preimage and must never be added to it.

An all-zero `deletion_event_hash` is not a legitimate value; it is refused on both decode and serialisation (§7).

*Origin:* ruling A-1(a), 12 Sep 2026, as amended by Slice 3a; White Paper v5 Table 3 and Figure 4 (receipt-identity binding); SHARED context pack line 291 (construction lineage). Field order, redundant `deletion_seq`, `module_hash` inclusion, `manifest_hash` exclusion, and 8-byte big-endian integer encodings are `[ORIGIN: implementation — ratified 12 Sep 2026]`; implemented by `deletion_event_hash_v5` (`src/receipt.rs`) and used by the MKTd02 engine.

### 3.5 `receipt_id`

```text
receipt_id = hash_with_tag(
  "MKTD02_RECEIPT_V3",
  [ u32_be(len(canister_id_bytes)), canister_id_bytes,
    u32_be(len(record_id_bytes)),   record_id_bytes,
    u64_be(deletion_seq) ]
)
```

Each identifier is length-delimited so that no two distinct `(canister_id, record_id)` pairs can produce the same preimage by concatenation.

*Origin:* SHARED context pack line 288; published in the MKTd02 integration README ("Key Invariants"). The tag, length-prefix widths, field order, and 8-byte big-endian sequence encoding are `[ORIGIN: implementation — ratified 12 Sep 2026]`; confirmed at `src/receipt.rs:496`–`:516`.

### 3.6 `genesis_certified_data`

```text
genesis_certified_data(canister_id) = hash_with_tag(
  "MKTD02_GENESIS_V1",
  [ canister_id_bytes ]
)
```

The principal is hashed as **raw bytes with no length prefix** — deliberately unlike §3.5.

A verifier that finds a certificate whose certified data equals this value has been shown a canister that has certified **no deletion**, and must reject it by name (§7).

*Origin:* ruling 1b.5, **11 Sep 2026**. Confirmed at `src/receipt.rs:933`.

### 3.7 `certified_data` under `mktd02-v5`

```text
certified_data = deletion_event_hash        (after a deletion)
certified_data = genesis_certified_data(canister_id)   (before any deletion)
```

There is no intermediate commitment: the certified value **is** the deletion event hash. A verifier matches the certified data it authenticates from the data certificate against the receipt's `deletion_event_hash` field, exactly.

Only the deletion path may publish a new certified value; lifecycle handling re-publishes the recorded value, or the genesis value if none has been recorded, and never advances it.

*Origin:* White Paper v5 Figure 4 and ruling SR-06 (11 Sep 2026), “Direct Certification”; ratification record §2; release notes v0.5.0 “Construction change”.

---

## 4. Receipt wire format — byte-exact freeze

This section fixes the exact bytes of a `mktd02-v5` receipt in both encodings. Unless stated otherwise, **every design-detail rule in §4 is `[ORIGIN: implementation — ratified 12 Sep 2026]`** under rulings F-6 through F-17. The flags are retained to record their origin and disposition. Code references are to `src/receipt.rs`.

### 4.1 Field list and order

Exactly fourteen fields, in this order, in both encodings:

| # | Field | Type |
|---|---|---|
| 1 | `protocol_version` | text, exactly `"mktd02-v5"` |
| 2 | `receipt_id` | 32 bytes |
| 3 | `canister_id` | principal |
| 4 | `record_id` | byte string, variable length |
| 5 | `pre_state_hash` | 32 bytes |
| 6 | `post_state_hash` | 32 bytes |
| 7 | `tombstone_hash` | 32 bytes |
| 8 | `deletion_event_hash` | 32 bytes |
| 9 | `module_hash` | 32 bytes |
| 10 | `timestamp` | unsigned integer (nanoseconds) |
| 11 | `deletion_seq` | unsigned integer |
| 12 | `bls_certificate` | optional byte string |
| 13 | `trust_root_key_id` | text |
| 14 | `module_hash_certificate` | optional byte string |

There is no `certified_commitment` field and no replacement for it. The key order above is pinned for CBOR by `receipt.rs:2198`–`:2237`.

*Origin:* `[ORIGIN: implementation — ratified 12 Sep 2026]`; ruling F-6 (field list and order).

### 4.2 CBOR encoding

- The receipt is a **definite-length map** with 14 pairs (major type 5, `0xae`), never an array and never indefinite-length.
- Keys are **text strings**, spelled exactly as in §4.1, emitted in the order of §4.1.
- Every byte-valued field is a **CBOR byte string (major type 2)**: the nine receipt byte fields (`receipt_id`, `record_id`, `pre_state_hash`, `post_state_hash`, `tombstone_hash`, `deletion_event_hash`, `module_hash`, `bls_certificate`, and `module_hash_certificate`) plus `canister_id`.
- Each byte string uses the definite length form required by its payload length: direct additional-information lengths where possible, then `0x58`, `0x59`, or the wider definite-length forms as they arise. The declared length equals the payload length and the payload is the field value.
- `canister_id` holds the raw principal bytes.
- `timestamp` and `deletion_seq` are unsigned integers in shortest-form encoding.
- `protocol_version` and `trust_root_key_id` are text strings.
- An optional certificate field present is a byte string; **absent, it is CBOR `null` (`0xf6`) and the key is still emitted.** A pending receipt therefore carries all fourteen keys.

*Origin of byte-string rule:* ruling A-2(b), 12 Sep 2026, as amended by Slice 3a. All other CBOR shape details are `[ORIGIN: implementation — ratified 12 Sep 2026]` under F-7, F-9, and F-10.

### 4.3 JSON encoding

- **The compact form is normative.** A JSON object with the fourteen keys of §4.1, emitted in that order. Any pretty-printed or re-indented rendering is **non-normative** and must never be used for a byte comparison.
- **Whitespace and newlines:** no whitespace anywhere outside string values — no space after `:` or `,`, no indentation, no line breaks. The artefact has **no trailing newline**; where a vector file stores the JSON as text, the stored value is the exact byte string without one.
- **Escaping:** conforming field values are ASCII and require no escaping, so a conforming receipt's JSON contains no escape sequence. Should any string value ever require escaping, the canonical form is the minimal JSON escaping of `"`, `\` and control characters; non-ASCII is emitted as raw UTF-8 and never `\u`-escaped.
- `receipt_id`, the four hashes, `module_hash` and `record_id` are **lowercase hexadecimal strings** with no `0x` prefix and no separators.
- `canister_id` is the **textual principal form** (for example `"wy6px-tibai-bqi"`), not hex.
- The textual/raw principal relation is fixed as follows. Let `p` be the raw
  principal bytes. Compute the IEEE CRC-32 checksum of `p`, encode that
  checksum as four bytes in big-endian order, prepend those four bytes to
  `p`, Base32-encode the result using the RFC 4648 alphabet without padding,
  lowercase the encoded text, and insert `-` after each group of five
  characters. Decoding reverses those steps and accepts the text only when
  the decoded four-byte prefix equals the recomputed CRC-32 of the remaining
  raw principal bytes. Thus raw bytes `01020304` have textual form
  `wy6px-tibai-bqi`.
- `timestamp` and `deletion_seq` are JSON numbers, written in plain decimal with no exponent, no fraction and no leading `+`.
- An optional certificate field present is a lowercase hex string; **absent, it is JSON `null` and the key is still emitted.**

*Origin:* `[ORIGIN: implementation — ratified 12 Sep 2026]`; rulings F-10, F-11, and F-17. The authority for the principal textual/raw-byte relation (Phase 1c.1, clean-room finding G-3) is the [Internet Computer Interface Specification, “Textual representation of principals”](https://docs.internetcomputer.org/references/ic-interface-spec/#textual-representation-of-principals).

### 4.4 Decode acceptance

- Any key outside §4.1 is a hard error (`unknown field` …), with one exception: `certified_commitment` is a declared probe key so that its presence is refused **by name** rather than as a generic unknown key (§7).
- A hex field accepts an optional `0x`/`0X` prefix and uppercase digits; canonical output is always lowercase and unprefixed. A byte-array form is also accepted on decode.
- A 32-byte field whose decoded length is not exactly 32 is refused.
- `record_id` and `deletion_seq` are structurally optional but semantically required: a receipt lacking either is refused after the protocol, retired-field and zero-hash checks.
- `trust_root_key_id` defaults to the empty string when absent; `bls_certificate` and `module_hash_certificate` default to absent.

*Origin:* `[ORIGIN: implementation — ratified 12 Sep 2026]`; rulings F-12 and F-13. The tolerant-input equivalence is pinned by corpus item gv5-012 (§10).

### 4.5 Serialisation refusals

Serialisation refuses, rather than reshaping:

- a `protocol_version` other than exactly `"mktd02-v5"` — no fallback to another line's wire shape;
- an all-zero `deletion_event_hash`, symmetric with decode (*Origin:* ruling 1b.4, 12 Sep 2026).

### 4.6 Error precedence

When more than one fault is present, the first applicable is reported:

1. structural decoding errors — unknown key, malformed hex, wrong byte length, missing required structural field;
2. unrecognised or wrong-line `protocol_version`;
3. `certified_commitment` present;
4. all-zero `deletion_event_hash`;
5. missing `record_id`, then missing `deletion_seq`.

*Origin:* ruling 1d (12 Sep 2026) fixes that a structural unknown-key error precedes the named retired-field error. The remainder of the ordering is `[ORIGIN: implementation — ratified 12 Sep 2026]` (`receipt.rs:1113`–`:1169`); ruling F-14.

---

## 5. Receipt state rule

Classification by certificate completeness, for `mktd02-v5`:

| `bls_certificate` | `module_hash_certificate` | State |
|---|---|---|
| absent | absent | `Pending` |
| present | present | `FinalizedCandidate` |
| present | absent | `InvalidIncompleteFinalization` |
| absent | present | `InvalidIncompleteFinalization` |

Exactly one certificate is a malformed finalisation: it is not `Pending`, and must never be treated as verifiable-finalized. A receipt whose `protocol_version` is not `"mktd02-v5"` classifies as `InvalidIncompleteFinalization`.

*Origin:* release notes v0.5.0 "Receipt-state rule"; ratification record 3.4. Confirmed at `receipt.rs:1008`–`:1019`.

---

## 6. Protocol version matching

`"mktd02-v5"` is matched **exactly**. `"mktd02-v5-x"`, `"mktd02-v50"` and `"mktd02-v5 "` are unrecognised and hard-error on decode and on serialisation. (The frozen earlier lines match by prefix — §8.4.)

*Origin:* ruling 1b.7 (12 Sep 2026); release notes v0.5.0 "Protocol version". Confirmed at `receipt.rs:252`–`:264`.

---

## 7. Named rejections

| Exact string | Raised at | Condition |
|---|---|---|
| `retired-field:certified_commitment` | decode | a `mktd02-v5` receipt carries the `certified_commitment` key, with any value including null |
| `invalid-event-hash:zero` | decode_and_serialise | `deletion_event_hash` is all-zero |
| `no-deletion-certified` | verify | certified data equals `genesis_certified_data(canister_id)` — no deletion has been certified |
| `unknown field` … | decode | any key outside §4.1 on a `mktd02-v5` receipt |
| `v1:receipt-id-mismatch` | verify | recomputed `receipt_id` under §3.5 != presented `receipt_id`; first V1 step |
| `v1:event-hash-mismatch` | verify | recomputed `deletion_event_hash` under §3.4 != presented `deletion_event_hash`; evaluated only after `receipt_id` passes |

Reference implementation: zombie_core::verify_v1.

Unrecognised or wrong-line `protocol_version` is also a hard error on both decode and serialisation. The corpus freezes the message fragment `unrecognised protocol_version` for v5 near-miss dispatch and the fragment `not a mktd02-v5 receipt` when a frozen-line label is presented to the v5 type. These are fragment assertions, not complete framework error strings. The historical opposite-direction prefix is fixed separately by §8.4.

Corpus `layer` strings use exactly this ratified vocabulary: `decode | serialise | decode_and_serialise | verify`.

- `decode`: receipt decoding or type-specific input validation;
- `serialise`: receipt serialisation;
- `decode_and_serialise`: the same candidate is required to be refused on both paths;
- `verify`: verifier checks, including both V1 failures above.

`verify_v1` may appear only as neutral test/input operation metadata, never as a normative corpus output layer. The layer vocabulary describes where a corpus outcome arises; it is not a protocol field or error construction.

*Origin:* ratification record 3.6; release notes v0.5.0 "Named rejections"; rulings 1b.4 and 1d (12 Sep 2026). The `unknown field` text is the serialisation framework's own and is `[ORIGIN: implementation — ratified 12 Sep 2026]` as a required prefix, not an exact full string; ruling F-15. The V1 names, layer vocabulary, and protocol-message fragments incorporate the Phase-6 G-1/G-2 documentary closure in Phase 1c; they freeze existing corpus/implementation behaviour and introduce no new runtime rule.

---

## 8. Historical constructions (retired — not part of v5)

Retained so that receipts already issued under `mktd02-v2`, `mktd02-v3` and `mktd02-v4` remain explainable and verifiable. Nothing in this section applies to a v5 receipt.

### 8.1 `certified_commitment` — retired 2026-09-11 (SR-06)

```text
certified_commitment = SHA-256( "MKTD02_CERTIFIED_V1" ‖ post_state_hash ‖ deletion_event_hash )
```

Computed only through the retired-tag path of §1.3. `mktd02-v5` computes no such value and carries no such field.

*Origin:* release notes v0.5.0 "Construction change"; ruling SR-06.

### 8.2 `deletion_event_hash` for `mktd02-v2`…`mktd02-v4` — historical

```text
deletion_event_hash = hash_with_tag(
  "MKTD02_EVENT_V1",
  [ pre_state_hash,
    post_state_hash,
    u64_be(timestamp),
    module_hash,
    u64_be(deletion_seq) ]
)
```

This frozen five-part construction is recomputed through `deletion_event_hash_v1`. It does not bind `receipt_id` and must not be used for v5.

*Origin:* SHARED context pack line 291 (historical lineage); frozen v2–v4 implementation and release history.

### 8.3 `mktd02-v2` receipt identity — historical

```text
receipt_id = hash_with_tag( "MKTD02_RECEIPT_V1", [ canister_id_bytes, u64_be(nonce) ] )
```

No length prefixes; `nonce` is the v2 name of the field later called `deletion_seq`.

*Origin:* `[ORIGIN: implementation — ratified 12 Sep 2026]` (`receipt.rs:521`), retained as a historical record; ruling F-16.

### 8.4 Wire differences and label matching

- `mktd02-v2`, `-v3` and `-v4` receipts decode through their own frozen type and **tolerate unknown keys**; v5 does not.
- The frozen v4 type's refusal of a v5-labelled receipt begins with
  `DeletionReceipt: unrecognised protocol_version`. This incorporates the
  already-ratified historical fact in
  `docs/dev/slice3_phase1_rulings.md` D-9; it is not a new construction or
  ruling.
- The v3 wire shape carries no `module_hash_certificate` field at all; v4 adds it. v5 always emits it, `null` when absent (§4.2, §4.3).
- Labels for the frozen lines match by **prefix**, so a suffixed label such as `"mktd02-v4-rc1"` still classifies as that line. This is inherited behaviour, not a designed convention, and is recorded as an open item for a later review.

*Origin:* release notes v0.4.0 and v0.5.0; ruling 1b.7 (12 Sep 2026) and its recorded finding.

---

## 9. Lock gate

- [x] `hash_with_tag` discipline (§1.1)
- [x] Tag registry membership and v5/other-line grouping (§2)
- [x] `deletion_event_hash` ordered preimage and `manifest_hash` exclusion (§3.4)
- [x] `receipt_id` length-delimited preimage (§3.5)
- [x] `genesis_certified_data` raw-bytes preimage, no length prefix (§3.6)
- [x] `certified_data` = `deletion_event_hash`; genesis before any deletion (§3.7)
- [x] Receipt state rule (§5)
- [x] Named rejections and their layers (§7)
- [x] `state_hash` construction ratified (§3.2)
- [x] `tombstone_hash` preimage ratified (§3.3)
- [x] Integer encodings in hash preimages ratified (§3.3, §3.4)
- [x] Receipt wire byte-exact freeze ratified (§4)
- [x] Error precedence beyond the unknown-key rule ratified (§4.6)
- [x] Active-registry membership and grouping ratified (§2.1)
- [x] White Paper v5 (Figure 4, §2.2) and SHARED context-pack formula sections reconciled against this document
- [x] Independent rederivation complete — zero underivable values among the derivable corpus; `v4h-v3-wire` excluded by design as a copied frozen historical implementation-regression artefact. Phase 6, 13 Sep 2026, bundle SHA-256 `5dc6e2b2a356c0d780538adeba373514c527e99578fd87dc775c49c72a33468a`. 47/47 compared values matched; 0 mismatches. G-1/G-2/G-3 documentary gaps closed by Phase 1c and its corrective commit; exact original evidence is archived in [docs/dev/phase6](../dev/phase6/README.md), superseding the reconstructed report/script. G-4 recorded as the intentional exclusion.
- [ ] Countersignature on v5 vectors

---

## 10. Corpus-plan additions

The corpus lock includes these phase-1-ruling additions:

- **gv5-011 — state-hash derivation.** A fixed `state_bytes` tombstone fixture, identified by the Leaf State Encoding Specification and its schema, derives `mktd_salt` from the fixture canister principal and then derives `state_hash` in accordance with §3.2. The vector records the schema/version used so the state bytes are independently reproducible.
- **gv5-012 — tolerant-input equivalence.** Uppercase and/or `0x`-prefixed hexadecimal and accepted byte-array inputs decode to the same receipt value as the canonical lowercase, unprefixed representation. Re-encoding produces the canonical wire form.
