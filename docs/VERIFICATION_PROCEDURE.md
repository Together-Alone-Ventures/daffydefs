# DaffyDefs CVDR Verification Procedure

This is the technical procedure for current DaffyDefs v5 receipts. Supply the exact browser-exported JSON without removing fields, re-encoding, or manual transformation. The current verifier uses strict receipt intake; presentation fields such as `timestamp_iso` are not part of the wire schema.

## Primary invocation

From the downloaded repository snapshot, on Linux x86_64:

```bash
tools/cvdr-verify/bin/linux-x86_64/mktd02-verify \
  --receipt-file /path/to/downloaded-receipt.json \
  --trust-root mainnet
```

Replace the receipt path with your unchanged download. The operator explicitly chooses the trust root; the receipt cannot select its own trusted root. The demo uses mainnet. The executable is convenience software, not a trust anchor. Its SHA-256 is `b47e442b0f76331a14ff09bc70bd9f50682a635ebf2dfda90f15e4ed6b322a2c`; authoritative source is CVDR-Verify `560e483b047209ee83463dfab29da07acb422feb` (0.8.0 DRAFT, no release tag). See [REFERENCE_VERIFIER.md](REFERENCE_VERIFIER.md) for packaging details.

## Applicable validity checks

### V1 — internal consistency

Recompute `receipt_id` and `deletion_event_hash` using the normative v5 derivations and require equality with the corresponding receipt fields. Preserve exact integer values and protocol encodings. Internal consistency alone does not establish certificate validity.

### V2 — certified deletion-event evidence

Validate the embedded certificate against the operator-selected trust root, including delegation and canister-range checks. Require the certified data for `receipt.canister_id` to equal `receipt.deletion_event_hash`.

### V3A — attested code identity

Validate the archived `module_hash_certificate`, including its certificate/delegation path and canister range. Require the certified value at `/canister/<receipt.canister_id>/module_hash` to equal `receipt.module_hash`. Enforce the applicable certificate ordering and finalisation-delay rule; report its timing classification.

This is archival evidence. A later canister upgrade may change the live module hash without invalidating the earlier receipt's attested code identity.

Overall v5 validity requires **V1 AND V2 AND V3A**. V3B and optional live-state diagnostics do not determine validity. The primary invocation above does not request live-state diagnostics or supply build provenance.

## V3B — supplementary/non-gating build provenance

Use the current source/build materials and profile-canister hash published in [RELEASES.md](../RELEASES.md). The ceremony implementation anchor is `e2b073971aae5f1c97edee59875bec15628821c7`; the current release retains its profile source/build inputs.

Required toolchain: Rust `1.97.1`, target `wasm32-unknown-unknown`, and `ic-wasm` `0.11.1`. Public dependencies resolve under the committed `Cargo.lock`. The disclosed TAV snapshots are MKTd02 / Leaf `2a10bf3ee056d3ff53327ca23654609a6f430c5e` and zombie-core `223723885cfbb548d6b218aee8500b073fda4b58`; `.cargo/config.toml` resolves their Git package identities from local `vendor/` sources.

From the repository root:

```bash
bash scripts/build-profile-repro.sh
sha256sum wasm_out/profile_canister.wasm
```

Compare the final post-shrink WASM SHA-256 with both `receipt.module_hash` and the current profile hash in `RELEASES.md`:

```text
30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb
```

Equality establishes the supplementary source-to-profile-WASM comparison for that receipt. A receipt from an older release needs that release's source/build materials. Do not substitute a factory, frontend, bulletin-board or verifier-binary hash. Only profile-canister WASM is a byte-exact reproducibility target; no physically distinct-hardware reproduction is claimed.

## Accepted worked example — 16 September 2026

- Profile: `petd6-ciaaa-aaaaj-qshha-cai`.
- Receipt: `90347766510e664818831810d7c53091936192dae63db48bb194b96e00006149`.
- Exact browser JSON: `docs/acceptance/receipts/deletion-receipt-90347766.json`.
- JSON SHA-256: `1a12152b8869814ddd80ef11234864211fa7f5119e0b7eebf4e9e46d8a6b62d1` (5704 bytes).
- Profile hash: `30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb`.

```bash
tools/cvdr-verify/bin/linux-x86_64/mktd02-verify \
  --receipt-file docs/acceptance/receipts/deletion-receipt-90347766.json \
  --trust-root mainnet
```

The packaged and fresh source-built verifiers returned V1 PASS, V2 PASS, V3A PASS and overall PASS. V3B was not evaluated in those invocations. Separately, the canonical profile build reproduced the published and receipt-attested hash. The [ceremony record](acceptance/ceremony-2026-09-16.md) records identities and timings.
