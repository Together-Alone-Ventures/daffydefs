# DaffyDefs Reference Verifier

## Purpose

The reference verifier is supplied as a convenience for DaffyDefs CVDR verification.

For the DaffyDefs receipt path, it automates the V1/V2/V3A checks for current
`mktd02-v5.1` receipts and historical `mktd02-v5` receipts, dispatching on the
exact `protocol_version`, and reports build provenance separately.

## Source

Source location:

`tools/cvdr-verify/`

Baseline:

- upstream CVDR-Verify subtree: `mktd02/mktd02-verify` (branch `v5.1`)
- upstream commit: `67cbe4bf3878a1853a1839dfe96a76281ce3feea`
- version: `0.8.0` (no release tag)

## Binary

Packaged Linux target:

- OS: Linux
- architecture: x86_64
- executable: `tools/cvdr-verify/bin/linux-x86_64/mktd02-verify`
- reported verifier version: `0.8.0`
- identity: **CVDR-Verify at `67cbe4bf…`**, with standalone workspace packaging

**Binary SHA-256:** `6460032695b1f9b8f31d6a435fcf46ebe883a5f1c67013af1a2f3915663c9f6b`

Built with Rust 1.97.1 using `cargo build --release --locked` from `tools/cvdr-verify/`.
The binary is not a reproducibility target. A fresh build of CVDR-Verify
`170c958cca9342ca3937c06f97edc0912de11dec` has a different binary hash but produced
byte-identical `--json` output on the canonical receipt.

The DaffyDefs delta is limited to standalone workspace/source-isolation and
convenience packaging. Verifier semantics remain those of the authoritative
upstream source.

The executable is a convenience artifact, not a trust anchor.

## Basic DaffyDefs invocation

```bash
tools/cvdr-verify/bin/linux-x86_64/mktd02-verify \
  --receipt-file <downloaded-receipt.json> --trust-root mainnet
```

Default network endpoint in the DaffyDefs copy is `https://ic0.app`.

The downloaded DaffyDefs JSON is accepted directly.

## Current output model

The verifier reports two axes: protocol validity and supplementary diagnostics.
For v4/v5/v5.1, validity requires V1, V2 and V3A; for v2/v3 it requires V1 and V2.
V3B build provenance and live-state diagnostics are reported separately and are
non-gating. The receipt's explicit trust-root identifier is recorded, while the
operator must select the verification root explicitly with `--trust-root` or
`--trust-root-pem`. A label/root disagreement is reported and is non-gating.

## Trust posture

A verifier who distrusts this executable can inspect the source, compile it themselves, or independently implement the published procedure.
