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

## Browser verifier (Quick Verify)

The Quick Verify page (`/verify`) loads the same verifier compiled to WebAssembly from `/cvdr-wasm/`. That path serves `src/frontend/public/cvdr-wasm/`, and receipts are verified in the browser only. The page accepts mainnet receipts only and does not run V3B.

| Stage | Artefact | SHA-256 |
|---|---|---|
| Source | DaffyDefs `1ff2149`, `tools/cvdr-verify/` = CVDR-Verify `67cbe4bf3878a1853a1839dfe96a76281ce3feea` (unchanged through branch `v5.1`) | — |
| Cargo output | `cargo build --locked --lib --target wasm32-unknown-unknown --release --no-default-features --features wasm` (Rust 1.97.1) → `mktd02_verify.wasm` | path-dependent, see below |
| Bindings | `wasm-bindgen 0.2.113 --target web` → `mktd02_verify_bg.wasm`, `mktd02_verify.js`, `mktd02_verify.d.ts`, `mktd02_verify_bg.wasm.d.ts` | — |
| **Served** | `mktd02_verify_bg.wasm` | **`1f8b4cd14280f2d384d530475ae195cff5d7fa2b7576b1f12ffe69194b3dc1d0`** |

The raw cargo output embeds absolute source paths, so its hash depends on the build directory.
- Built from a checkout at `~/tav/daffydefs`, it is `d925b72cebf781d212e0199ef47b64dfddef2b8880ccd3c25fb021d9e607c50f`. That is the value the page and Demo Pack displayed before 28 Sep 2026; it was the pre-`wasm-bindgen` build, not the served file.
- From another directory it differs; for example `/tmp/claude-1000/qv` gave `51a13521092dac8d28ce3a60bf344f02defaf303e3d615b48c019e2d179f7eed`.

`wasm-bindgen` output is path-independent. Both builds produce the served `1f8b4cd1…` and byte-identical JS and type files. Compare the **served** hash.

The page displays the served hash from `src/frontend/src/components/verifierBuild.ts`. The test `verifierBuild.test.ts` fails if that constant differs from the SHA-256 of the committed `mktd02_verify_bg.wasm`.
