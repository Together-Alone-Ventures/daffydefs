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
- Product/build provenance anchor: `e2b073971aae5f1c97edee59875bec15628821c7`
- Released post-shrink profile-WASM SHA-256:
  `30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb`
- Live factory module hash:
  `b476a41de6c36556262282f9e93aa9e35e2957b5cd2a953dddf32651f9fc001e`
- Fresh acceptance profile:
  `petd6-ciaaa-aaaaj-qshha-cai`
- Fresh acceptance receipt:
  `90347766510e664818831810d7c53091936192dae63db48bb194b96e00006149`
- Banked exact JSON:
  `docs/acceptance/receipts/deletion-receipt-90347766.json`
- Banked JSON SHA-256:
  `1a12152b8869814ddd80ef11234864211fa7f5119e0b7eebf4e9e46d8a6b62d1`
- Packaged Linux reference-verifier SHA-256:
  `b47e442b0f76331a14ff09bc70bd9f50682a635ebf2dfda90f15e4ed6b322a2c`

The 16 Sep 2026 untouched browser receipt passed V1 / V2 / V3A and overall validity under both the packaged verifier and a fresh verifier built from `560e483b047209ee83463dfab29da07acb422feb` (0.8.0 DRAFT, no release tag). V3B was not evaluated in those invocations; it is supplementary/non-gating build provenance. The canonical, deployed and receipt-attested profile hashes match. The canonical recipe reproduced that profile hash during this capsule freeze.

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
