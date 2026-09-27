# DaffyDefs CVDR Verification Procedure

This is the technical procedure for current DaffyDefs receipts. Current receipts are `mktd02-v5.1`; historical `mktd02-v5` receipts remain verifiable under their own frozen construction.

Supply the exact browser-exported JSON without removing fields, re-encoding, or manual transformation. The verifier uses strict receipt intake: presentation fields are not part of the wire schema.

Governing rulings:
- `vendor/zombie-core/docs/rulings/2026-09-25-mktd02-v5.1-amendment.md` (MKTd02 v5.1 correction and historical freeze);
- `docs/rulings/2026-09-27-dd2-non-identifying-record-id.md` (DaffyDefs record identity).

## Primary invocation

From the downloaded repository snapshot, on Linux x86_64:

```bash
tools/cvdr-verify/bin/linux-x86_64/mktd02-verify \
  --receipt-file /path/to/downloaded-receipt.json \
  --trust-root mainnet
```

Replace the receipt path with your unchanged download. The operator explicitly chooses the trust root; the receipt cannot select its own trusted root. The demo uses mainnet. The executable is convenience software, not a trust anchor. Its SHA-256 is `6460032695b1f9b8f31d6a435fcf46ebe883a5f1c67013af1a2f3915663c9f6b`; authoritative source is CVDR-Verify `67cbe4bf3878a1853a1839dfe96a76281ce3feea` (branch `v5.1`). See [REFERENCE_VERIFIER.md](REFERENCE_VERIFIER.md) for packaging details.

## Protocol versions

Version matching is exact. Each version selects its own frozen construction, and no prefix or near-match form is accepted.

| `protocol_version` (exact) | Status | Event-hash tag |
|---|---|---|
| `mktd02-v5.1` | current, corrected line | `MKTD02_EVENT_V3` |
| `mktd02-v5` | historical, frozen | `MKTD02_EVENT_V2` |

## Formulas

`H_tag(tag, p0, p1, …) = SHA-256(tag ‖ p0 ‖ p1 ‖ …)`. The tag is its exact ASCII bytes, with no terminator, length prefix or separator. `u32_be` and `u64_be` are 4- and 8-byte unsigned big-endian integers. `canister_id_bytes` are the raw principal bytes.

Receipt identity, unchanged between v5 and v5.1:

```text
receipt_id = H_tag("MKTD02_RECEIPT_V3",
                   u32_be(len(canister_id_bytes)), canister_id_bytes,
                   u32_be(len(record_id)),         record_id,
                   u64_be(deletion_seq))
```

Current `mktd02-v5.1` deletion event (five parts):

```text
deletion_event_hash = H_tag("MKTD02_EVENT_V3",
                            pre_state_hash,
                            post_state_hash,
                            receipt_id,
                            u64_be(timestamp),
                            u64_be(deletion_seq))
```

`module_hash` is **not** an operand. `deletion_seq` is deliberately explicit even though `receipt_id` also binds it. `manifest_hash` is excluded.

Historical `mktd02-v5` deletion event (six parts; frozen, used only for receipts labelled exactly `mktd02-v5`):

```text
deletion_event_hash = H_tag("MKTD02_EVENT_V2",
                            pre_state_hash,
                            post_state_hash,
                            receipt_id,
                            u64_be(timestamp),
                            module_hash,
                            u64_be(deletion_seq))
```

Certified data, under both lines: `certified_data = deletion_event_hash` after a deletion.

## Receipt state (mktd02-v5.1)

Four fields are set only at finalisation: `bls_certificate`, `module_hash_certificate`, `module_hash`, `trust_root_key_id`.

- **Pending.** All four are **structurally absent**: the keys are not present at all. Absence is never represented by `null`, `""`, an all-zero hash or any other placeholder.
- **FinalizedCandidate.** All four are present.
- **InvalidIncompleteFinalization.** Any partial or mixed set. It fails closed.

The historical `mktd02-v5` wire keeps its frozen fourteen-key form.

At finalisation (Phase C), `module_hash` is extracted from `module_hash_certificate`, from the certified leaf at exactly:

```text
/canister/<canister_id>/module_hash
```

A missing path, wrong path, malformed tree or value, wrong length, or any other extraction failure is an explicit finalisation error; no receipt is finalised after one. `trust_root_key_id` is stamped from trusted core configuration and is never chosen by the finalisation client.

## Applicable validity checks

### V1 — internal consistency

Recompute `receipt_id`, then `deletion_event_hash` using the formula selected by the exact `protocol_version`, and require equality with the receipt fields. Preserve exact integer values and protocol encodings. Internal consistency alone does not establish certificate validity.

### V2 — certified deletion-event evidence

Validate the embedded certificate against the operator-selected trust root, including delegation and canister-range checks. Require the certified data for `receipt.canister_id` to equal `receipt.deletion_event_hash`.

### V3A — attested code identity

Validate the archived `module_hash_certificate`, including its certificate/delegation path and canister range. Require the certified value at `/canister/<receipt.canister_id>/module_hash` to equal `receipt.module_hash`. Enforce the certificate ordering rule; a negative or otherwise invalid ordering fails V3A. The finalisation delay is reported as a timing classification, and `DELAY_EXCEEDED` is a non-gating downgrade.

This is archival evidence. A later canister upgrade may change the live module hash without invalidating the earlier receipt's attested code identity.

### Trust-root label

The receipt's `trust_root_key_id` never selects the verification root. The verifier reports the root it used, the receipt's label, and any disagreement between them. A label mismatch on its own is informational and non-gating.

Overall validity requires **V1 AND V2 AND V3A**. V3B and optional live-state diagnostics do not determine validity. The primary invocation above does not request live-state diagnostics or supply build provenance.

## V3B — supplementary/non-gating build provenance

Use the current source/build materials and profile-canister hash published in [RELEASES.md](../RELEASES.md). The implementation anchor is `84617bac4b00c9ec65a914c30eda74e73415680d`.

Required toolchain: Rust `1.97.1`, target `wasm32-unknown-unknown`, and `ic-wasm` `0.11.1`. The canonical recipe runs them in the pinned container. Public dependencies resolve under the committed `Cargo.lock`. The disclosed TAV snapshots are MKTd02 / Leaf `8e5024dc8d27be19dafc579b2ac955e45da28b0c` and zombie-core `8ac64df5d0110ec7ebbbe8382b7a826dda17085a`; `.cargo/config.toml` resolves their Git package identities from local `vendor/` sources.

From the repository root (Docker required):

```bash
bash scripts/build-capsule-container.sh
sha256sum releases/CANDIDATE/container-output-$(git rev-parse HEAD)/profile_canister.wasm
```

`scripts/build-profile-repro.sh` performs the same build outside the container if the exact toolchain is installed locally.

Compare the final post-shrink WASM SHA-256 with both `receipt.module_hash` and the current profile hash in `RELEASES.md`:

```text
a196de1dcbe13b6d7d84470aaaa8be236935de5db8503418777bae1f7a1a01d9
```

Equality establishes the supplementary source-to-profile-WASM comparison for that receipt. A receipt from an older release needs that release's source/build materials. Do not substitute a factory, frontend, bulletin-board or verifier-binary hash. Only profile-canister WASM is a byte-exact reproducibility target; no physically distinct-hardware reproduction is claimed.

## Accepted worked example — 27 September 2026 (mktd02-v5.1)

- Profile: `ju7jm-caaaa-aaaaj-qshsq-cai`.
- Receipt: `26c4721ce54ca65cd9940b371c9fcae040f96b23020bd3c00c994d85934bad12`.
- Exact browser JSON: `docs/acceptance/receipts/deletion-receipt-26c4721c.json`.
- JSON SHA-256: `e845e49ab4bae2488ca7da5f78243d29bd085ac9242e838183a1a7c632897051` (5560 bytes).
- Profile hash: `a196de1dcbe13b6d7d84470aaaa8be236935de5db8503418777bae1f7a1a01d9`.

```bash
tools/cvdr-verify/bin/linux-x86_64/mktd02-verify \
  --receipt-file docs/acceptance/receipts/deletion-receipt-26c4721c.json \
  --trust-root mainnet
```

The packaged verifier and a fresh build of CVDR-Verify `170c958cca9342ca3937c06f97edc0912de11dec` returned V1 PASS, V2 PASS, V3A PASS and overall PASS, exit 0. V3B was not evaluated in those invocations. Separately, the canonical capsule build reproduced the published and receipt-attested hash. The [ceremony record](acceptance/ceremony-2026-09-27-v5.1.md) records identities, timings and the mutation matrix.

## Historical example — 16 September 2026 (mktd02-v5)

Receipt `90347766510e664818831810d7c53091936192dae63db48bb194b96e00006149` (`docs/acceptance/receipts/deletion-receipt-90347766.json`, profile `petd6-ciaaa-aaaaj-qshha-cai`, profile hash `30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb`). It is a historical `mktd02-v5` receipt, verified with the frozen `MKTD02_EVENT_V2` construction. The current packaged verifier still returns V1/V2/V3A PASS for it under `--trust-root mainnet`. See its [ceremony record](acceptance/ceremony-2026-09-16.md).
