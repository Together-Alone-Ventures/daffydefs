This DaffyDefs convenience copy tracks the authoritative mktd02-verify subtree at
CVDR-Verify commit `67cbe4bf3878a1853a1839dfe96a76281ce3feea` (branch v5.1). It is version
`0.8.0` with no invented release tag. Build the binary with Rust `1.97.1` using
`cargo build --release --locked`.

## Verifier's Guide — OpenChatZD deletion receipts (suite v5)

### What you are verifying

A **PortablePackageV3** is the self-contained artifact OpenChatZD serves at `GET /cvdr/<receipt_id>`
once a deletion is finalised and its Index code-identity evidence is stored. It verifies **offline**
from the package's certificate material and a trust root **you configure** — no access to OpenChat,
no live canister, and no trust in whoever handed you the file. Exact field names are the contract
(`package.rs`); the outer document has exactly these keys and **any other key is malformed**:

```
schema                        — "openchatzd.cvdr.portable_package"
version                       — exactly 3
encoding                      — "hex"
trust_root_key_id             — SELECTOR of a verifier-configured root: "mainnet" | "non-production-test-root"
frozen                        — hex of the exact FrozenWire JSON bytes (below)
index_code_identity_evidence  — { certificate_bytes, index_module_hash }
```

`frozen` decodes to the FrozenWire (`schema "openchatzd.cvdr.frozen_package"`, `version 1`):
`receipt_body` (**RECEIPT_BODY_V2**), `receipt_hash`, `tree_root`, `witness_bytes`,
`certificate_bytes`, `certificate_time`. A bare FrozenWire (no evidence) and a historical
`PortablePackageV2` are still decoded; V2 is never produced any more.

**Package version and body tag are dispatched together**: a V3 package must carry
`RECEIPT_BODY_V2`, a V2 package `RECEIPT_BODY_V1`; any other pairing is `validity: FAIL`
(`v1:version-tag-mismatch`).

Reveal packages (`RevealWire` v2): `schema · version · encoding · salt · record_salt · targets`.

### Quick start

```
mktd02-verify --package package.json
mktd02-verify --package package.json --reveal reveal.json
```

The grade uses the suite vocabulary:

- **`validity: PASS`** — V1, V2 and V3A all pass: the receipt is intact, it was included in the
  certified state of the `index_canister_id` named in the body, and the Index's module identity is
  subnet-attested for the deletion.
- **`validity: INCOMPLETE`** — V1 and V2 pass but V3A is `V3A_PENDING_IN_PROTECTED_WINDOW` (no
  evidence yet; the Index may still capture it) or `V3A_PERMANENTLY_UNAVAILABLE` (no evidence and the
  24 h window has lapsed; no later evidence can be valid). Never a pass, never a fail; the reason names
  which. Code identity is **not** established.
- **`validity: FAIL`** — a named check failed. A failed package proves nothing.

`V3A_PENDING_IN_PROTECTED_WINDOW` and `V3A_PERMANENTLY_UNAVAILABLE` are **as-of-verification-time
classifications, not cryptographic verdicts**: they depend on the verifier clock (`--now-ns`, else the
system clock) measured against the receipt's `uninstall_completed_at + 24 h`. The same package can
be PENDING at hour 3 and PERMANENTLY_UNAVAILABLE at hour 25; both remain `validity: INCOMPLETE`
(exit 4). Whenever either is emitted the report prints the evaluation time and its source
(`evaluated at … (source: --now-ns | system clock)`) together with that statement. A `V3A_PASS`,
`INDEX_ATTESTATION_INVALID` or `INDEX_HASH_MISMATCH` does not depend on the clock.

Exit codes: `0` PASS, `1` FAIL, `2` usage error (no verdict), `4` INCOMPLETE.

### The trust root — a selector, never evidence

`trust_root_key_id` in the package **selects** which root *you* have configured; it proves nothing by
itself. The certificate must then authenticate (BLS threshold signature → NNS delegation → canister
range) under that root. Unknown selectors fail closed.

- `mainnet` selects the built-in IC (NNS) root key. For any real verification corroborate that
  constant independently (DFINITY's interface specification; the official agent libraries).
- `non-production-test-root` selects a **fixture** root and is honoured **only** with
  `--allow-fixture-root-key`, the root supplied out of band with `--fixture-root-key-hex <hex DER>`
  (or, for a bare FrozenWire fixture, its `root_key_hex`). The verdict then says
  `NON-PRODUCTION root … TEST VERDICT ONLY`. A V3 package never carries root material.

**Never accept a root key supplied by the package itself.** Without the flag a non-production
selector is refused before anything is verified.

### What verification actually does

- **V1** — exact version/tag dispatch; parse `receipt_body`; recompute
  `receipt_id = SHA256(RECEIPT_ID_TAG ‖ record_id ‖ deletion_seq ‖ nonce)` from the displayed fields;
  recompute the leaf `SHA256(RECEIPT_LEAF_TAG ‖ receipt_body)` and require it to equal `receipt_hash`.
  `record_id` is the **non-identifying** `SHA256(RECORD_ID_TAG_V2 ‖ record_salt ‖ user principal)`:
  it cannot be joined to a public identity without the user's RevealWire `record_salt`. With
  `--reveal`, both `TARGETS_COMMITMENT_V1` and `record_id` are re-derived.
- **V2** — decode `witness_bytes` as an IC HashTree; require its root to equal `tree_root` and the
  leaf at `["receipts", receipt_id]` (receipt_id from the body, never a caller argument) to equal
  `receipt_hash`; verify the certificate under the selected root — signature, delegation and, **do not
  skip this**, the delegation's canister range covering `index_canister_id`; require
  `certified_data == tree_root` and `certificate_time == /time`.
- **V3A — subnet-attested Index code identity.** Authenticate `index_code_identity_evidence.certificate_bytes`
  (a `read_state` certificate for `/canister/<index>/module_hash`) under the selected root; require its
  `/time` to fall inside the protected interval `[uninstall_completed_at, uninstall_completed_at + 24 h]`
  (both hash-bound in the body); require the displayed `index_module_hash` to equal the certified value.
  V3A has exactly three outcomes — `V3A_PASS`, `V3A_PENDING_IN_PROTECTED_WINDOW`,
  `V3A_PERMANENTLY_UNAVAILABLE`; `INDEX_ATTESTATION_INVALID` and `INDEX_HASH_MISMATCH` are named
  failures. **Evidence-binding rule:** Index module-hash evidence is bound by (index_canister_id, certified /time within the receipt's window), not by receipt identity; one certificate may serve every receipt it qualifies for; a different Index canister, subnet, path or root fails. Where evidence is present and passes, it attests the
  identity of the deployed module at certification time; the OpenChatZD Index upgrade interlock
  bounds that window from uninstall to evidence capture.
- **Non-gating facts** — the finalization-window tier (`certificate_time − receipt_committed_at`
  vs `--window-hours`, default 24) and the five-value timing axis are reported and never grade.

### Optional: operator expectation (`--expect-module-hash <64-hex>`)

Gating when supplied: on a `RECEIPT_BODY_V2` package the hash must equal the **V3A-certified** module
hash (a V3A that is not PASS makes the assertion impossible → FAIL); on a historical V1 body it must
reproduce `h_index`. Supply nothing and no expectation is compared — the report says so.

### Optional: live diagnostic (`--corroborate-h-index`)

Fetches the Index's current `module_hash` via `read_state` and prints it in its own block. It is a
**diagnostic only** and never enters validity: an Index legitimately upgraded after the deletion
differs here while its receipts remain valid.

### What a CVDR does NOT prove

- It does **not** certify the original user data or prove what PII existed before deletion.
  `h_user_pre` is an Index-recorded observation of the target canister's pre-uninstall module hash —
  integrity-bound by the certified receipt relation, not independently attested.
- It records which group/community targets were **captured and notified** — it does **not** certify
  that each group completed member removal.
- Absence of Index evidence proves nothing about the Index's code, in either direction.
- The grade is a **verifier** result. No live system honestly claims it about itself.

### Schema compatibility

CVDR-Verify treats the field names above as the **portable package contract**. Producers must serve
the package byte-for-byte; verifiers must not require live refetch or regeneration of any component.

## Verifier's Guide — MKTd02 deletion receipts

> **Output format: PROVISIONAL.** The result is a set of structured facts. The human
> rendering below, and the `--json` field names, stand until the shared output
> contract replaces them. The verification logic and the validity rule do not
> depend on the rendering.

### Quick start

```
mktd02-verify --receipt-file receipt.json --trust-root mainnet
mktd02-verify --receipt-file receipt.cbor --trust-root-pem pocketic_root.pem
mktd02-verify --canister <principal> --receipt-id <hex> --trust-root mainnet
```

Add `--json` to print the facts instead of the human rendering.

A trust root is **required**. `--trust-root mainnet` selects the built-in IC root key.
`--trust-root-pem <file>` takes a PEM `PUBLIC KEY` block holding the DER-encoded IC root
key (e.g. a PocketIC test network) and records it as `pem:<first 16 hex of SHA-256>`.
There is no implicit default. The receipt's own `trust_root_key_id` never selects a
key: it is recorded, and if it differs from the root used, `trust_root_mismatch` is
reported as a warning, never as a failure.

### What is verified

Every receipt is decoded by zombie-core (`AnyDeletionReceipt`). Named decode errors,
such as `retired-field:certified_commitment` or `unrecognised protocol_version`, are
reported verbatim as `validity: FAIL`.

- **V1 — internal consistency.** For `mktd02-v5`, zombie-core's normative `verify_v1`:
  `receipt_id` first, then `deletion_event_hash` over it. For the historical lines
  `mktd02-v2`…`v4`: `receipt_id` (per line), `deletion_event_hash` (v1 construction),
  `certified_commitment` (retired tag, historical use only) and `tombstone_hash` are
  recomputed.
- **V2 — direct certification, offline.** The embedded `bls_certificate` must validate
  against the trust root: BLS signature, NNS delegation, and the delegation's canister
  range covering the receipt's canister. Freshness at verification time is not checked
  for archived evidence. Its `certified_data` for the canister must equal the receipt's
  `deletion_event_hash` (v5) or `certified_commitment` (v2–v4). For v5, a
  `certified_data` equal to the canister's genesis value is refused as
  `no-deletion-certified`. The certificate time against the receipt timestamp is
  reported as an informational timing note (warning above `CVDR_V2_CERT_TIME_WARN_SECS`,
  default 300 s).
- **V3A — subnet-attested code identity (v4 and v5).** From the two embedded
  certificates alone, with no live access, all six checks must hold:
  1. both certificates validate against the trust root;
  2. the module-hash certificate's path is exactly `/canister/<canister_id>/module_hash`;
  3. the delegation's canister range covers the canister;
  4. the certified module hash equals the receipt's `module_hash`;
  5. `t(module_hash cert) ≥ t(bls cert)` — a negative delta is an ordering **failure**;
  6. a delta above `MAX_FINALIZATION_DELAY_NS` (zombie-core, 3,600 s) is
     **`DELAY_EXCEEDED`**: a downgrade shown in the timing note, not a rejection.

  The bls certificate is bound to the same value V2 compares. V3A **attests the
  identity of the deployed module at certification time**. It does not establish which
  code ran. v2/v3 receipts predate module-hash certification: V3A is `NOT_EVALUATED`
  for them.
- **V3B — build provenance.** `NOT_EVALUATED` unless a published module hash is supplied
  with `--wasm-hash`, in which case the receipt's `module_hash` is compared with it. No
  rebuild is performed, and V3B never affects validity.

### Validity

| Result | When |
|---|---|
| `validity: PASS` | v4/v5: V1, V2 and V3A all pass on a finalized receipt. v2/v3: V1 and V2 pass (V3A shown `NOT_EVALUATED — line predates module-hash certification`). |
| `validity: INCOMPLETE` | The receipt is **pending**: neither certificate is embedded yet. V1 is still checked; V2 and V3A are `NOT_EVALUATED`. INCOMPLETE is never a pass. |
| `validity: FAIL` | Intake refused the receipt, or V1 failed, or a required check failed (named error), or exactly one of the two certificates is present (`incomplete-finalisation`). |

The assurance block lists the protocol line (historical lines are marked
`(historical)`), the receipt state, the trust root used and any mismatch, the
attestation class (`subnet-attested` or `not-attested`), and every check as `PASS`,
`FAIL <named error>` or `NOT_EVALUATED — <reason>`. It also lists the timing sub-results
and what each passing check established. No line is a bare `PASS`.

Exit codes (both modes): `0` PASS, `1` FAIL, `2` usage error (no verdict), `4` INCOMPLETE.

Example pending-receipt output (abbreviated):

```text
validity: INCOMPLETE
assurance:
  protocol_line: mktd02-v5
  receipt_state: Pending
  V1: PASS
  V2: NOT_EVALUATED — pending
  V3A: NOT_EVALUATED — pending
  V3B: NOT_EVALUATED — no build provenance supplied
```

### Live diagnostics

Fetching a receipt from a canister (`--canister`/`--receipt-id`) is intake. Queries
about the canister *as it is now* — current `certified_data`, current module hash,
tombstone persistence — run only with `--diagnostic-live-check`. They are reported in a
separate block and never affect validity: a canister upgraded after deletion, or no
longer reachable, does not change the receipt's verdict.

### Receipt encoding

The ratified wire is canonical. JSON numbers for `timestamp` and `deletion_seq`
(`nonce` on v2), lowercase hex for hashes and certificates, or the equivalent CBOR.
`mktd02-v5` receipts are decoded strictly: unknown keys and the retired
`certified_commitment` are refused. For the historical lines `mktd02-v2`…`v4` the
verifier keeps intake tolerance: decimal-string numbers, byte-array or `0x`-prefixed
fields, and a v2 `subnet_id` that must be a valid principal. Decimal strings are
historical tolerance, not the canonical encoding.

### Reference fixture

The DaffyDefs v4 reference CVDR (`tests/fixtures/v4/v4_finalized_mainnet.json`, a
genuine mainnet receipt with both certificates) verifies offline as `validity: PASS`,
`protocol_line: mktd02-v4 (historical)`, `attestation_class: subnet-attested` under
`--trust-root mainnet`. Its certified module hash is the module identity **at
certification time**. A canister upgraded afterwards shows a different current hash
under `--diagnostic-live-check`, and the receipt's verdict is unchanged. Provenance:
`tests/fixtures/v4/PROVENANCE.md` and `tests/fixtures/README.md`.

### PocketIC v5 regression fixture

The capture in `tests/fixtures/v5/pocketic-11-p17/` is an
**implementation-derived regression fixture, not a corpus vector**. With its
captured `root.pem` supplied through `--trust-root-pem`, V1 and V2 pass using a
real PocketIC BLS certificate. Its dummy module-hash certificate intentionally
causes V3A to fail with `v3a:module-hash-certificate`, so overall validity is FAIL.
It is not a fully valid v5 CVDR. The receipt names `mainnet`, while verification
uses the captured PEM root; this is reported as a trust-root mismatch warning.
See [capture provenance](tests/fixtures/v5/pocketic-11-p17/PROVENANCE.md).

## Development checks

Run `./ci.sh` from this directory (or invoke it by path from elsewhere).
It requires Python 3, the pinned Rust toolchain, and `cargo-audit`, with access
to dependencies and the current advisory database. It runs formatting, Clippy
with warnings denied, locked tests, audit, and explicit corpus acceptance. Formatting
and Clippy must be clean for the whole crate (the earlier fixed OpenChatZD baseline is
retired). Test failures and audit vulnerabilities fail. The four documented
maintenance warnings are permitted. Baseline details are recorded in
[development notes](../../docs/dev/slice4_notes.md#12-exit-ruling-closure-16-sep-2026).

---

## Disclaimer

CVDR-Verify is a **reference implementation** provided for interoperability and
transparency. It is not legal advice. It is provided **without warranty of any kind**,
express or implied. A successful verification result does not replace the verifier's own
due diligence and **does not constitute a compliance certification** (GDPR or otherwise)
by Together Alone Ventures, OpenChat, or any other party. Verifiers are responsible for
independently obtaining the IC root key, for the provenance of any package they accept,
and for their own interpretation of results.
