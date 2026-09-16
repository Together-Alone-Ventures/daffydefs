# DaffyDefs Reference Verifier

## Purpose

The reference verifier is supplied as a convenience for DaffyDefs CVDR verification.

For the DaffyDefs receipt path, the v0.8.0 DRAFT automates the ratified v5
V1/V2/V3A checks and reports build provenance separately.

## Source

Source location:

`tools/cvdr-verify/`

Baseline:

- upstream CVDR-Verify subtree: `mktd02-v5`
- upstream commit: `560e483b047209ee83463dfab29da07acb422feb`
- version: `0.8.0` DRAFT (no release tag)

## Binary

Packaged Linux target:

- OS: Linux
- architecture: x86_64
- executable: `tools/cvdr-verify/bin/linux-x86_64/mktd02-verify`
- reported verifier version: `0.8.0` DRAFT
- identity: **CVDR-Verify at `560e483b…`**, with standalone workspace packaging

**Binary SHA-256:** `b47e442b0f76331a14ff09bc70bd9f50682a635ebf2dfda90f15e4ed6b322a2c`

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
For v4/v5, validity requires V1, V2 and V3A; for v2/v3 it requires V1 and V2.
V3B build provenance and live-state diagnostics are reported separately and are
non-gating. The receipt's explicit trust-root identifier is recorded, while the
operator must select the verification root explicitly with `--trust-root` or
`--trust-root-pem`.

## Trust posture

A verifier who distrusts this executable can inspect the source, compile it themselves, or independently implement the published procedure.
