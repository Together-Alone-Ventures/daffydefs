> **DaffyDefs users:** this file preserves the upstream verifier guide and includes OpenChatZD material and historical labels. For the DaffyDefs demo path, start with [`../../docs/REFERENCE_VERIFIER.md`](../../docs/REFERENCE_VERIFIER.md) and [`../../docs/VERIFICATION_PROCEDURE.md`](../../docs/VERIFICATION_PROCEDURE.md). The exact DaffyDefs delta is recorded in [`../../VENDORED_SOURCES.md`](../../VENDORED_SOURCES.md).

## Verifier's Guide — OpenChatZD deletion receipts

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
cvdr-verify --package receipt.json
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
cvdr-verify --package receipt.json --reveal reveal.json
```

recomputes `TARGETS_COMMITMENT_V1` and confirms the revealed list is exactly the one the
receipt committed to.

### Optional: bind the receipt to an expected module (`--expect-module-hash`)

The body's `h_index` is **not** itself a module hash. It is
`SHA256(H_INDEX_TAG ‖ index_canister_id ‖ module_hash)` — the index
canister's module hash, hash-bound into the receipt. So a module hash
you already trust can be checked *against* the receipt, offline:

```
cvdr-verify --package receipt.json --expect-module-hash <64-hex>
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
- **With `--expect-module-hash`, it gates.** The live hash must equal the expected one.
  `LIVE_MODULE_HASH_MISMATCH` or `LIVE_MODULE_HASH_UNAVAILABLE` rejects and exits non-zero
  — the first when the live hash differs from the supplied expectation, the second when the
  network is unreachable and the assertion you asked for cannot be made. It fails closed
  rather than passing on silence.

So a canister legitimately upgraded after the deletion will mismatch here while its receipts
remain perfectly valid. That is why the receipt-binding claim is the offline
`--expect-module-hash` gate above, and why a live mismatch carries its own distinct reason.

Deeper provenance (matching a module hash to a signed release record, rebuilding from
source) is release-attested: until reproducible builds are relied on, do not describe the
receipt as "independently verifiable from source."

### What a CVDR does NOT prove

- It does **not** certify the original user data or prove what PII existed before
  deletion — it proves the named user canister was torn down by the named code at the
  certified time.
- It records which group/community targets were **captured and notified** — it does
  **not** certify that each group completed member removal. Do not report
  "groups confirmed erased."
- `VerifiedFinal` / `LateFinalized` are **verifier** results. No live system honestly
  claims them about itself.

### Schema compatibility

CVDR-Verify treats the field names above as the **portable package contract**. Producers
must serve the frozen package byte-for-byte; verifiers must not require live refetch or
regeneration of any package component.

### V3-A — subnet-attested code identity (mktd02-v4)

> Note: 'V3-A' throughout this document = V3 (attested code identity) under the
> ratified renumbering; the wholesale V3-A→V3 rename is a tracked backlog item.

For `mktd02-v4` receipts, CVDR-Verify runs **V3-A**, an *archival* code-identity
check that works **offline from the exported receipt alone** — no live canister
access. It coexists with the live V3 module-hash corroboration (which needs the
canister to still exist). V3-A reads two certificates embedded in the finalized
receipt: the Phase B `bls_certificate` (over `certified_data`) and the
`module_hash_certificate` (a subnet `read_state` over
`/canister/<id>/module_hash`).

**The six normative checks** (all must hold for a pass):

1. Both certificates validate against the trusted IC root with full delegation
   checks (BLS signature → NNS delegation).
2. The module-hash certificate's certified path is **exactly**
   `/canister/<receipt.canister_id>/module_hash` — a certificate over any other
   path is rejected.
3. The delegation's canister range authorises `receipt.canister_id`.
4. The certified module-hash value equals the receipt's embedded `module_hash`.
5. Both certificates share the same canister identity and trust-root context, and
   `t(module_hash cert) ≥ t(bls cert)`. A **negative delta is an ordering
   failure**, never a delay verdict. The receipt's internal deletion timestamp is
   never the security bound — only certificate `/time` is.
6. If `t(module_hash) − t(bls)` exceeds the normative threshold
   `MAX_FINALIZATION_DELAY_NS` (from zombie-core; 3,600 s), the result is
   **`DELAY_EXCEEDED`** — a downgrade, **not** a rejection (LateFinalized-style).
   CVDR-Verify is the authoritative interpreter of this threshold.

**Receipt-state rule (three-state, protocol-aware, v4 only).** A v4 receipt is
classified by certificate presence: `Pending` (neither certificate) /
`FinalizedCandidate` (both) / `InvalidIncompleteFinalization` (exactly one). v2/v3
receipts predate this field and are **never** classified by the v4 states.

**Report vocabulary:**

- **Subnet-attested** — V3-A passed; the subnet certified the installed module
  hash at the certified time.
- **Deployer-declared** — no attested module-hash certificate (a v2/v3 receipt, or
  a v4 receipt without the certificate). Non-attested.
- **Pending** — receipt not finalized (neither certificate). Export is permitted
  and is labelled **non-attested**.

A **missing V3-A is reported as non-attested, never as a pass.** A certificate
that is present but fails any of checks 1–5 is a present-but-invalid **failure**
(a red flag), distinct from benign non-attestation.

The V3-A positive path is now exercised against a **genuine mainnet artifact**: the
DaffyDefs Gate 2 ceremony produced a real end-to-end finalized `mktd02-v4` receipt
(`fixtures/v4_finalized_mainnet.json`), and `positive_subnet_attested_pass` verifies
it offline to `SUBNET-ATTESTED` (both real certs under the built-in IC root, ordered
within the finalization delay) — plus V1's full recomputation, since the genuine
receipt carries the real preimages. Its certified module hash is the code identity
**at deletion**; if the canister is later upgraded, a *live* V3 read shows an
expected upgraded-since-deletion divergence while the archival V3-A verdict stands.

---

## Disclaimer

CVDR-Verify is a **reference implementation** provided for interoperability and
transparency. It is not legal advice. It is provided **without warranty of any kind**,
express or implied. A successful verification result does not replace the verifier's own
due diligence and **does not constitute a compliance certification** (GDPR or otherwise)
by Together Alone Ventures, OpenChat, or any other party. Verifiers are responsible for
independently obtaining the IC root key, for the provenance of any package they accept,
and for their own interpretation of results.
