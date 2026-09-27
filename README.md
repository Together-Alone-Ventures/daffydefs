# DaffyDefs — Demo Capsule

DaffyDefs is a public worked example of ICP-Delete (Leaf): one profile canister per user, a shared bulletin board, a profile factory, and a browser frontend.

## What an independent verifier can establish

Using this repository and ordinary public infrastructure, a technically competent verifier can:

1. create and download their own DaffyDefs CVDR JSON;
2. verify that exact JSON with the supplied reference verifier;
3. independently corroborate the relevant profile-canister module hash from ICP;
4. compare the receipt's V3A-attested code identity with the accepted hash below; and
5. perform the supplementary V3B build-provenance comparison by rebuilding the profile-canister WASM from the disclosed source/build materials and comparing its SHA-256 with the module hash attested in the receipt.

The reference verifier evaluates the applicable V1, V2 and V3A validity axes. V3B build provenance is supplementary/non-gating and is established separately by the published rebuild-and-compare procedure.

## Current live demo release

- Live frontend: `https://5b3yq-gqaaa-aaaaj-qp4ta-cai.icp0.io/`
- Protocol version: `mktd02-v5.1`
- Product/build provenance anchor: `84617bac4b00c9ec65a914c30eda74e73415680d` (branch `v5.1`)
- Released post-shrink profile-WASM SHA-256:
  `a196de1dcbe13b6d7d84470aaaa8be236935de5db8503418777bae1f7a1a01d9`
- Live factory module hash:
  `7eaa25e334c51f8cfba041ae8708147743d4f20b06d966ae2824ee4373f6a461`
- Fresh acceptance profile:
  `ju7jm-caaaa-aaaaj-qshsq-cai`
- Fresh acceptance receipt:
  `26c4721ce54ca65cd9940b371c9fcae040f96b23020bd3c00c994d85934bad12`
- Banked exact JSON:
  `docs/acceptance/receipts/deletion-receipt-26c4721c.json`
- Banked JSON SHA-256:
  `e845e49ab4bae2488ca7da5f78243d29bd085ac9242e838183a1a7c632897051`
- Packaged Linux reference-verifier SHA-256:
  `6460032695b1f9b8f31d6a435fcf46ebe883a5f1c67013af1a2f3915663c9f6b`

The 27 Sep 2026 untouched browser receipt passed V1 / V2 / V3A and overall validity. It was checked with both the packaged verifier (CVDR-Verify `67cbe4bf3878a1853a1839dfe96a76281ce3feea`) and a fresh build of CVDR-Verify `170c958cca9342ca3937c06f97edc0912de11dec`.
- V3B was not evaluated in those invocations; it is supplementary/non-gating build provenance.
- The canonical, deployed and receipt-attested profile hashes match.
- Two clean runs of the canonical container recipe reproduced that profile hash.

The earlier 16 Sep 2026 receipt `90347766…` is a historical `mktd02-v5` receipt (see [its record](docs/acceptance/ceremony-2026-09-16.md)).

Start with [the self-contained Demo Pack](docs/DEMO_PACK.md). The [current release record](RELEASES.md) and [verification procedure](docs/VERIFICATION_PROCEDURE.md) define the published identity and V3B comparison. Byte-exact reproducibility applies only to profile-canister WASM; no reproduction on physically distinct hardware is claimed.

## Repository map

- `src/profile_canister/` — per-user profile canister
- `src/profile_factory/` — factory that creates profile canisters and embeds the profile WASM
- `src/bulletin_board/` — shared non-profile application content
- `src/frontend/` — browser application
- `vendor/mktd02/` — exact TAV MKTd02 source snapshot required for the product build
- `vendor/zombie-core/` — exact TAV zombie-core source snapshot required for the product build
- `tools/cvdr-verify/` — DaffyDefs copy of the reference-verifier source
- `tools/cvdr-verify/bin/linux-x86_64/mktd02-verify` — packaged convenience executable
- `scripts/build-profile-repro.sh` — canonical profile-WASM reproducibility recipe
- `scripts/build-capsule-container.sh` — pinned-container reproduction wrapper
- `VENDORED_SOURCES.md` — exact upstream revisions/tree hashes and build-boundary notes
- `docs/VERIFICATION_PROCEDURE.md` — technical V1/V2/V3A/V3B verification procedure
- `docs/RESIDUAL_TRUST_STATEMENT.md` — what the receipt does and does not establish
- `docs/REFERENCE_VERIFIER.md` — reference-verifier packaging and trust posture
- `docs/acceptance/receipts/` — banked current and historical receipt evidence
- `RELEASES.md` — current release identity and profile build provenance

## Rebuilding the profile WASM

The code-provenance target is the **final post-`ic-wasm shrink` profile-canister WASM**, not the factory, bulletin board, frontend, or verifier.

Required pins:

- Rust: `1.97.1`
- target: `wasm32-unknown-unknown`
- `ic-wasm`: `0.11.1`
- Rust dependencies: exact resolution in `Cargo.lock`
- TAV source snapshots: exact revisions recorded in `VENDORED_SOURCES.md`
- public crates: fetched under the committed lockfile versions/checksums

Canonical command:

```bash
bash scripts/build-profile-repro.sh
```

Expected released output:

```text
30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb  wasm_out/profile_canister.wasm
```

## Application build

`scripts/build.sh` is the complete DaffyDefs application build pipeline: profile → factory → bulletin board → frontend. It is distinct from the narrower profile-WASM V3B reproducibility procedure.

## Scope

The CVDR code-identity/provenance claim is about the **profile canister identified by the receipt**. The factory, bulletin board, frontend and reference verifier are outside that profile-WASM provenance boundary.

Dated historical acceptance and deployment records under `docs/acceptance/` do not define the current release.
