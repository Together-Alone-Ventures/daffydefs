# DaffyDefs Reference Verifier

## Purpose

The reference verifier is supplied as a convenience for DaffyDefs CVDR verification.

For the DaffyDefs receipt path, it automates V1–V3 and reports V4 code provenance as **NOT EVALUATED**.

## Source

Source location:

`tools/cvdr-verify/`

Baseline:

- upstream CVDR-Verify release: `v0.6.1`
- upstream commit: `ad16f2a`
- exact DaffyDefs deltas: recorded in `VENDORED_SOURCES.md`

## Binary

Packaged Linux target:

- OS: Linux
- architecture: x86_64
- executable: `tools/cvdr-verify/bin/linux-x86_64/mktd02-verify`
- reported Cargo version: `0.6.1`
- identity: **CVDR-Verify 0.6.1 + DaffyDefs deltas** described in `VENDORED_SOURCES.md`

**Binary SHA-256:** `c355fe7e92a2c7db1862fb7dfa55822efc53659739abac69648cc741db7b037f`

This binary is intentionally not described as byte-identical to upstream v0.6.1: the DaffyDefs copy carries the ruled label/presentation/gating delta.

The executable is a convenience artifact, not a trust anchor.

## Basic DaffyDefs invocation

```bash
tools/cvdr-verify/bin/linux-x86_64/mktd02-verify \
  --receipt-file <downloaded-receipt.json>
```

Default network endpoint in the DaffyDefs copy is `https://ic0.app`.

The downloaded DaffyDefs JSON is accepted directly.

## Expected current presentation

- V1 — internal consistency
- V2 — certified commitment
- V3 — attested code identity
- V4 — code provenance: NOT EVALUATED
- INFO — live module corroboration
- INFO — tombstone persistence

The process exit for this path is gated by V1, V2 and V3. The two INFO checks are non-gating.

## Trust posture

A verifier who distrusts this executable can inspect the source, compile it themselves, or independently implement the published procedure.
