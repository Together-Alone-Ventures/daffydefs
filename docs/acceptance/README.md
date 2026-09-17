# DaffyDefs — Acceptance Evidence

## Current acceptance — 16 September 2026

See the [ceremony record](ceremony-2026-09-16.md) and [current release identity](../../RELEASES.md). The dated records below describe earlier tools and releases.

## Historical demo release acceptance — 15 Aug 2026

A fresh profile was minted through the live DaffyDefs application after the factory had been upgraded to embed the reproducibly built profile WASM.

| Field | Value |
|---|---|
| Profile canister | `5ff4g-7qaaa-aaaaj-qsehq-cai` |
| Receipt | `050f152899a866cd16cf3b7b9f3d49f17ae6d58499ac27d3fb7793dabc0963e6` |
| Receipt file | `receipts/deletion-receipt-050f1528.json` |
| Receipt-file SHA-256 | `add5a6c5f3a996fa6e24184823e74ea1ff1bef0949fb86dff91b1cf04d2bf3e2` |
| V3-attested profile hash | `cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9` |
| Product/build provenance anchor | `14fb08c40f42419a4ca767982c8f797351025ff1` |
| Live factory hash | `837a44b3ece8b901ad1af305a1252f6bd53d93819e81ea288584e547e970699a` |

The exact downloaded JSON passed the packaged DaffyDefs reference verifier:

- V1 PASS;
- V2 PASS in receipt-contained mode;
- V3 SUBNET-ATTESTED;
- V4 deliberately reported NOT EVALUATED by the tool;
- live module corroboration MATCH;
- tombstone persistence PASS as a non-gating diagnostic;
- process exit 0.

The release-record profile hash matched the receipt. An independent live ICP module-hash read matched the receipt. An independent exact-source rebuild then produced the same `cb16ee...` post-shrink profile hash, completing the published V4 procedure.

This acceptance does not claim reproduction on physically distinct hardware.

---

## Historical browser-finalisation acceptance — 1 Aug 2026

Date of historical record: 2026-08-02. Runs performed 2026-08-01.

## What was run

Two mainnet deletion ceremonies, performed by Stef against the browser
finalisation client on live mainnet canisters. Real Internet Identity
authentication, two fresh identities — one per run, so each run created its own
profile canister via the factory `5g26e-liaaa-aaaaj-qp4tq-cai`.

| | Run A | Run B |
|---|---|---|
| Receipt | `aeecedb178c1f5b16f0e7964d685f7ff6b27175ad987627ccb1556d8fdc6dbe5` | `a6e1c895519a6419ceee4e03eaa4ab34b69d8a3fa0631430c863342870c99fd1` |
| Profile canister | `7oi2b-viaaa-aaaaj-qsdwq-cai` | `7hlr5-daaaa-aaaaj-qsdxa-cai` |
| Scenario | Uninterrupted: Phase A → B → read_state → G1–G5b → Phase C in one session | Tab closed mid-flight; finalisation completed by lazy repair on the return session |
| Deleted at | 2026-08-01T16:54:55.525Z | 2026-08-01T17:09:37.333Z |
| `module_hash_certificate` | 1386 bytes | 1424 bytes |
| `bls_certificate` | 1389 bytes | 1427 bytes |

Receipts as downloaded from the browser, byte-for-byte unmodified:
`receipts/deletion-receipt-aeecedb1.json`, `receipts/deletion-receipt-a6e1c895.json`.

## Verification

Binary: `mktd02-verify 0.6.1` (CVDR-Verify, tag `v0.6.1`), run against each
downloaded file with no edits.

```
mktd02-verify --receipt-file <file> --network https://icp-api.io \
  --wasm-hash 07421692872c49b1d44d700ab3c30d37d0f9ef53345de0b5de1328a012dd1af8
```

`--wasm-hash` supplies the published profile-canister module hash for the
three-way comparison (on-chain == receipt == published). Source of that value:
`RELEASES.md` line 51, "Profile canister Module Hash (current deployed)" — an
independent published record, not read back from the receipt under test.

### Run A — verbatim output

```
============================================================
 CVDR-Verify: MKTd02 Full Verification (V1-V4)
 Canister : 7oi2b-viaaa-aaaaj-qsdwq-cai
 Receipt  : aeecedb178c1f5b16f0e7964d685f7ff6b27175ad987627ccb1556d8fdc6dbe5
 Source   : file:docs/acceptance/receipts/deletion-receipt-aeecedb1.json
 Network  : https://icp-api.io
============================================================

[1/6] Receipt load...
  protocol_version : mktd02-v4
  deletion_seq     : 1
  record_id        : 29 bytes (fc6bb61ae77c07e7c9d81ef5744e86f0add2f9b60f5caedcac20e56d02)
  module_hash_cert : 1386 bytes (present)
  Receipt loaded successfully.

[2/6] V1: State transition verification...
  V1: PASS — all 4 hashes independently recomputed and match

[3/6] V2: Certificate verification path...
  V2: PASS (receipt-contained mode) — embedded certificate valid, certified_data matches receipt commitment
    V2 timestamp: certificate_time_ns=1785603298985071496 receipt_time_ns=1785603295525319767 delta_secs=3.460

[4/6] V3: Module hash verification (live)...
  V3: FULL MATCH — code provenance confirmed end-to-end (on-chain == receipt == published)

[5/6] V3-A: Attested code identity (archival, offline)...
  V3-A: SUBNET-ATTESTED — code identity certified by the subnet (finalization delay 1.9s)

[6/6] V4: Tombstone persistence check...
  V4: PASS — tombstone intact, state hash matches

============================================================
 CVDR Verification Summary
============================================================
 V1 (hashes)      : V1: PASS — all 4 hashes independently recomputed and match
 V2 (cert path)   : V2: PASS (receipt-contained mode) — embedded certificate valid, certified_data matches receipt commitment
 V3 (module)      : V3: FULL MATCH — code provenance confirmed end-to-end (on-chain == receipt == published)
 V3-A (attested)  : V3-A: SUBNET-ATTESTED — code identity certified by the subnet (finalization delay 1.9s)
 V4 (tombstone)   : V4: PASS — tombstone intact, state hash matches
============================================================
```

### Run B — verbatim output

```
============================================================
 CVDR-Verify: MKTd02 Full Verification (V1-V4)
 Canister : 7hlr5-daaaa-aaaaj-qsdxa-cai
 Receipt  : a6e1c895519a6419ceee4e03eaa4ab34b69d8a3fa0631430c863342870c99fd1
 Source   : file:docs/acceptance/receipts/deletion-receipt-a6e1c895.json
 Network  : https://icp-api.io
============================================================

[1/6] Receipt load...
  protocol_version : mktd02-v4
  deletion_seq     : 1
  record_id        : 29 bytes (fd8168f22c95afcbb4f1075da4102bff7326df534df047616dbb9f3e02)
  module_hash_cert : 1424 bytes (present)
  Receipt loaded successfully.

[2/6] V1: State transition verification...
  V1: PASS — all 4 hashes independently recomputed and match

[3/6] V2: Certificate verification path...
  V2: PASS (receipt-contained mode) — embedded certificate valid, certified_data matches receipt commitment
    V2 timestamp: certificate_time_ns=1785604286803026411 receipt_time_ns=1785604177333105249 delta_secs=109.470

[4/6] V3: Module hash verification (live)...
  V3: FULL MATCH — code provenance confirmed end-to-end (on-chain == receipt == published)

[5/6] V3-A: Attested code identity (archival, offline)...
  V3-A: SUBNET-ATTESTED — code identity certified by the subnet (finalization delay 1.3s)

[6/6] V4: Tombstone persistence check...
  V4: PASS — tombstone intact, state hash matches

============================================================
 CVDR Verification Summary
============================================================
 V1 (hashes)      : V1: PASS — all 4 hashes independently recomputed and match
 V2 (cert path)   : V2: PASS (receipt-contained mode) — embedded certificate valid, certified_data matches receipt commitment
 V3 (module)      : V3: FULL MATCH — code provenance confirmed end-to-end (on-chain == receipt == published)
 V3-A (attested)  : V3-A: SUBNET-ATTESTED — code identity certified by the subnet (finalization delay 1.3s)
 V4 (tombstone)   : V4: PASS — tombstone intact, state hash matches
============================================================
```

## Historical check-label translation

The following table preserves the terminology used in the August record; “Current” in that table refers to that historical record, not the present v5 model. See the current verification procedure for V1/V2/V3A/V3B.

`mktd02-verify 0.6.1` predates that renumbering:

| v0.6.1 label | Current meaning |
|---|---|
| `V3-A` (attested) | Current **V3** — attested code identity |
| `V3` (module, live) | Current **V4** — provenance leg |
| `V4` (tombstone) | **Retired.** Passing, but not a current claim |
| `V1`, `V2` | Unchanged |

The retired tombstone check passes on both receipts. It is recorded here because
it appears in the output, not as an assertion that it carries current weight.

## 15-field completeness trace

Both receipts carry all 15 receipt fields, none null or empty, both certificate
blobs populated:

```
protocol_version  receipt_id  canister_id  record_id  pre_state_hash
post_state_hash  tombstone_hash  deletion_event_hash  certified_commitment
module_hash  timestamp  deletion_seq  bls_certificate  trust_root_key_id
module_hash_certificate
```

Result: **15/15 present on both**, no empty or null values. The only key beyond
the 15 is `timestamp_iso`, a derived convenience field; the verifier ignores
unknown keys.

Historical v0.6.1 behaviour only. The current v5 verifier uses strict receipt intake and rejects unknown wire fields; `timestamp_iso` is therefore no longer emitted by the DaffyDefs CVDR exporter.

`module_hash_certificate` is the field the attested-code-identity check depends
on. Both receipts reach SUBNET-ATTESTED, which is only reachable because that
field survives into the downloaded file.

## Run B — structural first-classness

Run B's receipt is not a degraded or partial artefact. Checked against Run A:

| Property | Result |
|---|---|
| Identical key set | yes |
| `protocol_version` | `mktd02-v4`, same as Run A |
| Both certificates populated | yes (1427 B / 1424 B) |
| Distinct canister and receipt id | yes |
| `module_hash` | identical to Run A, `07421692…` |
| Hash fields 64 hex chars | yes |
| Certificate ordering | valid — positive finalisation delay on both |

Two figures in Run B's output are worth stating plainly, because read cold they
could be mistaken for a defect:

- **V2 delta 109.470s** is the tab-closed gap. It is the interval between Phase A
  (deletion recorded, receipt timestamp) and the return session's Phase B
  certificate fetch — that is, how long the window was shut. Run A's equivalent
  is 3.460s because nothing interrupted it.
- **Finalisation delay 1.3s** — *shorter* than Run A's 1.9s — is the gap between
  the commitment certificate and the module-hash certificate. Lazy repair fetches
  both together on resume, so the two certificates are acquired closer in time
  than in the uninterrupted run, where they are separated by the live flow.

Both are evidence that the repair path works as designed. The abandoned receipt
was resumed on the next authenticated visit and finalised to a receipt
structurally indistinguishable from the uninterrupted one.
