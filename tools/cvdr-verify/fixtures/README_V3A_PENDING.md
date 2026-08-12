# V3-A fixtures — provenance record (route (a))

> Note: 'V3-A' throughout this document = V3 (attested code identity) under the
> ratified renumbering; the wholesale V3-A→V3 rename is a tracked backlog item.

**Authority:** operator decision 15 Jul 2026 (route (a)); G flags-memo response
(types accepted; exit semantics confirmed with the Pending-vs-incomplete
qualification; 0.6.0 ratified). **Prime rule:** a fake mainnet certificate is
never synthesised. Under route (a): the **certificates** are real mainnet
artifacts; a **receipt** wrapping them (for the composite) is test scaffolding,
explicitly labelled.

Status: fixture 1 **landed and validated**; fixture 2 (composite) **constrained
— cannot be built honestly at this time** (see §2). Corpus cases 1 and 3 are
un-ignored and green; `positive_subnet_attested_pass` remains `#[ignore]`d with
the reason below.

---

## 1. `v4_module_hash_cert.json` — LANDED

REAL mainnet `read_state` certificate over `/canister/<id>/module_hash`.

| field | value |
|---|---|
| source tool | `zd-finalize-helper fetch-cert` (standalone helper) |
| capture date | 15 Jul 2026 (operator) |
| source file | `~/projects/zd-finalize-helper/daffy_factory_module_hash_cert.cbor` |
| size | **1,926 bytes** (differs from the 13-Jul 2,025 B capture; expected — delegation contents vary, validity is structural) |
| sha256 (cbor) | `5f901e36668cf926af9992711b42ace63b5c53d586294f91f909266a54bb2642` |
| `canister_id` | `5g26e-liaaa-aaaaj-qp4tq-cai` (DaffyDefs profile factory, live mainnet) |
| `certified_module_hash` | `08cb8ff504fab08a694d6b2c4337da90cf1389a302255d50953dd5b9dc5ba59a` |
| `certificate_time_ns` | `1784099068522023339` (= 2026-07-15T07:04:28Z) |

Capture command (operator, 15 Jul 2026):

```
zd-finalize-helper fetch-cert \
  --canister-id 5g26e-liaaa-aaaaj-qp4tq-cai \
  --out daffy_factory_module_hash_cert.cbor
```

**Validation (not by inspection):** `v3a_tests::case1_value_mismatch_is_failed`
loads the pinned bytes and runs the full certificate machinery
(`verify_certificate_over_module_hash`): BLS signature → NNS delegation → the
delegation's canister range covering 5g26e → the **exact**
`/canister/5g26e.../module_hash` path. It asserts the subnet-certified value and
`/time` equal the pinned `certified_module_hash` / `certificate_time_ns` above.
The test passing IS the byte-level validation against the recorded time/hash.

**Unblocks:**
- **Case 1** (`case1_value_mismatch_is_failed`) — certified value vs a wrong
  `receipt.module_hash`: the check-4 comparison the full `verify_v3a` feeds.
- **Case 3** (`case3_delegation_range_excludes_canister`) — the same real cert
  presented for an NNS/root-subnet canister (`rdmx6-jaaaa-aaaaa-aaadq-cai`,
  outside 5g26e's app-subnet range) is rejected by the delegation range check
  ("not authorized for this canister") before any path lookup.

---

## 2. `v4_finalized_mainnet.json` — LANDED (genuine mainnet, Gate 2 + remediation)

**The deferral is discharged.** This is a GENUINE end-to-end finalized `mktd02-v4`
receipt from the DaffyDefs Gate 2 mainnet ceremony (21 Jul 2026), carrying **both**
real mainnet certificates over the ceremony profile canister, exported and pinned
here. `positive_subnet_attested_pass` is un-ignored against it (§ below).

| field | value |
|---|---|
| receipt_id | `0eceff7de5785e5d50bedca0cb3553409ba6ef6c5e2929715f903b48ff6abf70` |
| profile canister | `y5izv-byaaa-aaaaj-qsdfq-cai` (owner `zd-ceremony-test` = `bnei3-…-7ae`, publication-approved G-5) |
| protocol_version | `mktd02-v4` · trust_root_key_id `mainnet` · deletion_seq `1` |
| certified module hash (**attested anchor**) | `85a326cda94bff9e56e0c6f0b72d6412c6a76d71f4329c43f1f651c23ebe5cea` — the **deletion-time** profile code the receipt certifies |
| bls (certified_data) cert | 1701 bytes, embedded, real mainnet |
| module_hash cert | 1698 bytes, embedded (receipt-authoritative), real mainnet |
| capture (UTC) | ceremony finalize 2026-07-21T08:34:31Z |
| provenance SHAs | ceremony go-live `25f199f`; remediation `5ca421f` (see below) |
| fixture file | `fixtures/v4_finalized_mainnet.json` |
| fixture size | 8,898 bytes |
| fixture sha256 (**durable pin**) | `d958ee3a958b70af0f197f5402e772cd009280b2e16e2471cf795063207a95d1` |
| fixture build date (UTC) | 2026-07-22 |

**Validation (not by inspection):** `mktd02-verify --receipt-file
fixtures/v4_finalized_mainnet.json` → V1 PASS · V2 PASS · **V3-A SUBNET-ATTESTED**
(delay 0.9s, under `MAX_FINALIZATION_DELAY_NS`) · V4 PASS; both certs verify under
the built-in IC root. `positive_subnet_attested_pass` runs the same `verify_v3a`
offline and asserts `FinalizedCandidate` + `SUBNET-ATTESTED` + delay-under-threshold,
**and** (uniquely for the genuine artifact) V1's full recomputation.

**Attested-anchor note (important).** The certified module hash is `85a326cd…`, the
profile code **at deletion time** — NOT the current live `y5izv` hash. The canister
was legitimately upgraded to `07421692…` **after** finalization (Gate 2 R-b
remediation), so a *live* V3 read shows `MISMATCH-EXPECTED with provenance
(upgraded-since-deletion)`; the archival V3-A verdict against the frozen receipt is
unaffected. This is the archival-verification point: a receipt attests the code
identity at the moment of deletion, independent of later upgrades.

### Remediation provenance (why two SHAs)

The 21 Jul ceremony finalized this receipt, but the §5.1 live verifier run V3-A
false-failed: DaffyDefs' `mktd_get_receipt` export struct predated v4 and silently
dropped `module_hash_certificate`, so network-fetch saw only one cert (the on-chain
receipt was complete — proven at R-b). Remediation **R-a** (SHA `5ca421f`) exported
the field additively; **R-b** re-upgraded factory `5g26e` and profile `y5izv` on
mainnet. Only then could the genuine receipt be fully read back and pinned here.

### Historical record — route (a), superseded (retained per stand-pat ruling)

Before the ceremony, the plan was a **composite** receipt wrapping two independently
captured certs. It was ruled **cannot be built honestly** and abandoned (operator
stand-pat), because the commitment cert was pinned to factory `5g26e`:

1. `/canister/<id>/certified_data` is not externally readable via anonymous
   `read_state` (IC spec) — only the canister surfaces its `data_certificate`.
2. The factory `5g26e` exposes no certificate query (`get_cycle_balance`, `resolve`,
   `list_all_profiles`, `version` only).
3. Only a `profile_canister` produces a commitment cert (`mktd_get_state_hash` /
   `mktd_get_certificate`), but profile IDs are per-user, dynamic, not enumerable,
   and minting mutates state.

No composite was fabricated and no non-DaffyDefs canister was substituted. The
genuine Gate 2 ceremony (a real deletion driving a profile through Phase A→B→C)
supersedes the composite entirely — which is why this fixture exists.

### Honesty boundary — resolved by the genuine artifact

That boundary applied to the *synthetic composite*: its preimages were unknown, so
it could not satisfy V1's recomputation while simultaneously binding V2/V3-A. The
**genuine** Gate 2 receipt carries the real preimages, so V1 passes end to end
alongside V2/V3-A. `positive_subnet_attested_pass` therefore asserts the V3-A
positive path (six checks green → SUBNET-ATTESTED, cross-cert consistency, the
three-state `FinalizedCandidate` classification) **and** V1's full recomputation —
the composite's V1 restriction no longer applies to the real artifact.

### Supersession plan (Gate 2) — DISCHARGED

Executed as planned: the DaffyDefs Gate 2 ceremony drove a real deletion through
Phase A→B→C, producing the finalized `mktd02-v4` receipt now pinned as
`v4_finalized_mainnet.json` with both real certs; `positive_subnet_attested_pass`
is un-ignored against it. (§2 records the R-a/R-b remediation that made the second
certificate readable back after finalization.)

### Honest alternatives (pre-ceremony options — now moot, retained as record)

Before the ceremony, if a positive fixture were wanted early, either was honest but
needed operator direction (each deviating from the pinned `5g26e`). Neither was
taken — the Gate 2 ceremony supersedes both:
- **(A)** Provide a live mainnet **profile_canister** ID (mktd02-integrated,
  `certified_data` set). Then: capture its commitment cert via
  `mktd_get_state_hash()` (t1), then its module-hash cert via `read_state` (t2,
  seconds later, t2 ≥ t1 ≪ 1 h). Composite over that canister.
- **(B)** Authorize a profile-canister creation (`get_or_create_profile_canister`)
  — a mutating mainnet update call — then capture as in (A).

---

## Corpus coverage snapshot

Offline / real-cert cases green: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 + the v2/v3
regression + the `classify_timing` boundary + the **positive subnet-attested path**
(`positive_subnet_attested_pass`, fixture 2, now landed and un-ignored). Suite:
**58 passed / 0 failed / 0 ignored**.
