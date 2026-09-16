## Verifier's Guide — OpenChatZD deletion receipts

This DaffyDefs convenience copy tracks the authoritative MKTd02-v5 subtree at
CVDR-Verify commit `560e483b047209ee83463dfab29da07acb422feb`. It is version
`0.8.0` DRAFT with no invented release tag. Build the binary with Rust
`1.97.1` using `cargo build --release --locked`.

### What you are verifying

A **CVDR package** is a self-contained artifact produced at account deletion. It verifies
**offline from the package's certificate material and an independently obtained IC root
key** — no access to OpenChat, no live canister, and no trust in whoever handed
you the file. The portable JSON schema is **six package fields, plus `version`, plus one
optional test-only field** (exact names from `FrozenWire` in `package.rs` — code is the
contract):

```
schema             — schema identifier `openchatzd.cvdr.frozen_package`
version            — schema version
encoding           — OPTIONAL, defaults to "hex"
receipt_body       — the receipt (fixed-width tag-concatenation, RECEIPT_BODY_V1)
receipt_hash       — SHA-256 leaf bound into the certified tree
tree_root          — certified receipt-tree root at capture
witness_bytes      — IC HashTree witness, byte-for-byte as captured
certificate_bytes  — IC certificate, byte-for-byte as captured
certificate_time   — nanoseconds, from the certificate's /time
root_key_hex       — OPTIONAL, test fixtures only; ignored unless --allow-fixture-root-key
```

Reveal packages (`RevealWire`): `schema · version · encoding · salt · targets`.

### Quick start

```
mktd02-verify --package receipt.json
```

The verdict is one of:

- **VerifiedFinal** — the receipt is internally intact, was included in the certified
  state of the `index_canister_id` named in the receipt body, and the
  certificate was captured within the allowed window of the committed deletion time.
- **LateFinalized** — everything above is cryptographically valid, but the certificate
  was captured outside the window. Weaker on *when*, not on *whether*: the certified
  deletion receipt still verifies; only the promptness claim is downgraded. Never treat
  this as VerifiedFinal.
- **Reject** — one or more checks failed. The reason names the failed check; a rejected
  package proves nothing.

### The trust anchor — obtain the IC root key independently

All verification chains to a single public constant: the **IC (NNS) root public key** —
the root CA of this system. The built-in default is the mainnet NNS root key, and for any
real verification you should corroborate it from multiple sources, preferably including:

- DFINITY's public documentation (the interface specification publishes the key);
- the constant embedded in the official agent libraries (`agent-rs` / `agent-js`).

As an additional operational check — not an equal trust anchor, since it rides your own
network and toolchain — `dfx ping ic` prints the root key of the network you ping.

**Never accept a root key supplied by the package itself** — a forger would helpfully
include their own. The `root_key_hex` field exists only so test fixtures (e.g. PocketIC
artifacts) can be verified end-to-end, and it is ignored unless you pass
`--allow-fixture-root-key`. That flag means: *this run does not verify against mainnet.*

### What verification actually does

1. **Body integrity** — parse `receipt_body` (versioned fixed-width tag-concatenation),
   recompute the leaf `SHA256(RECEIPT_LEAF_TAG ‖ receipt_body)`, require it to equal
   `receipt_hash`. The body binds the identities (both canister ids, the receipt id and
   its derivation), the deletion evidence (`h_user_pre`, `h_index`, `commitment` — each a
   tagged hash, none of them a bare module hash), the load-bearing timestamps, and the
   cleanup-target commitment.
2. **Inclusion** — decode `witness_bytes` as an IC HashTree, recompute its root, require
   it to equal `tree_root`, and require the leaf to sit at path
   `["receipts", receipt_id]` with `receipt_id` taken from the parsed body (never from
   a caller argument).
3. **Certification** — verify the certificate: subnet BLS threshold signature, NNS
   delegation chain to the root key, and — **do not skip this** — that the delegation's
   canister range covers the `index_canister_id` from the body. Skipping the range check
   is the classic verifier mistake: without it, any subnet could vouch for any canister.
   Then require the certificate's `certified_data` for that canister to equal
   `tree_root`, and the package's `certificate_time` to equal the certificate's `/time`.
4. **The window** — require `certificate_time ≥ receipt_committed_at` and
   `Δ ≤ allowed window` (default 24 h, configurable). The timestamp being compared is
   *inside* the hash-bound body and the certificate time is asserted by the subnet's
   threshold signature — which is what makes backdating infeasible.

Those four run on every `--package` invocation. Nothing else is checked unless you ask:
in particular, no module hash is compared against anything unless you pass
`--expect-module-hash`.

### Reveal-package mode (cleanup targets)

The public receipt carries only a **count and a salted-hash commitment** of the user's
group/community targets. The user (and only the user) holds the reveal package
`{version, salt, sorted target list}`. Given both:

```
mktd02-verify --package receipt.json --reveal reveal.json
```

recomputes `TARGETS_COMMITMENT_V1` and confirms the revealed list is exactly the one the
receipt committed to.

### Optional: bind the receipt to an expected module (`--expect-module-hash`)

The body's `h_index` is **not** itself a module hash. It is
`SHA256(H_INDEX_TAG ‖ index_canister_id ‖ module_hash)` — the index
canister's module hash, hash-bound into the receipt. So a module hash
you already trust can be checked *against* the receipt, offline:

```
mktd02-verify --package receipt.json --expect-module-hash <64-hex>
```

This recomputes `h_index` from the hash you supplied and the body's own
`index_canister_id`. If the result does not equal the body's `h_index`, the check **fails**,
the verdict is **Reject**, and the process exits non-zero with the distinct reason
`H_INDEX_MISMATCH`. No network is involved.

Supply nothing and **no module hash is checked at all.** The report says exactly that, and a
run without `--expect-module-hash` must never be read as having verified any hash.

### Optional: live corroboration (`--corroborate-h-index`)

This is a **different check from `--expect-module-hash` above**, answering a different
question. While the index canister is live, `--corroborate-h-index` fetches the
IC-certified `/canister/<id>/module_hash` via `read_state`.

`--corroborate-h-index` checks the current live `module_hash` of the canister. This is live
corroboration only; it may differ after upgrade and is **not proof of what code executed the
deletion.**

- **Alone, it verifies nothing.** It prints the live hash, labelled informational, and
  compares it to nothing.
- **With `--expect-module-hash`, it is required to match.** The live hash must equal the expected one.
  `LIVE_MODULE_HASH_MISMATCH` or `LIVE_MODULE_HASH_UNAVAILABLE` rejects and exits non-zero
  — the first when the live hash differs from the supplied expectation, the second when the
  network is unreachable and the assertion you asked for cannot be made. It fails closed
  rather than passing on silence.

So a canister legitimately upgraded after the deletion will mismatch here while its receipts
remain perfectly valid. That is why the receipt-binding claim is the offline
`--expect-module-hash` comparison above, and why a live mismatch carries its own distinct reason.

Deeper provenance (matching a module hash to a signed release record, rebuilding from
source) is release-attested: until reproducible builds are relied on, do not describe the
receipt as "independently verifiable from source."

### What a CVDR does NOT prove

- It does **not** certify the original user data or prove what PII existed before
  deletion, and it does not establish which code ran. It establishes that a deletion
  receipt naming the user canister was included in the index canister's certified state
  at the certificate time. Where INDEX code-identity evidence is present, it attests the
  identity of the deployed module at certification time.
- It records which group/community targets were **captured and notified** — it does
  **not** certify that each group completed member removal. Do not report
  "groups confirmed erased."
- `VerifiedFinal` / `LateFinalized` are **verifier** results. No live system honestly
  claims them about itself.

### Schema compatibility

CVDR-Verify treats the field names above as the **portable package contract**. Producers
must serve the frozen package byte-for-byte; verifiers must not require live refetch or
regeneration of any package component.

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

Exit codes (MKTd02 receipt mode): `0` PASS, `1` FAIL, `2` usage error (no verdict),
`4` INCOMPLETE. OpenChatZD package mode keeps its own codes (`0`/`1`/`3`).

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
with warnings denied, locked tests, audit, and explicit corpus acceptance.
The unchanged OpenChatZD formatting and Clippy diagnostics are reported and
accepted only on an exact fixed-baseline match; any changed diagnostic or count
fails. Test failures and audit vulnerabilities fail. The four documented
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
