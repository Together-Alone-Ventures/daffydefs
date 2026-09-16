# DaffyDefs — Demo Capsule

DaffyDefs is a public worked example of ICP-Delete (Leaf): one profile canister per user, a shared bulletin board, a profile factory, and a browser frontend.

## What an independent verifier can establish

Using this repository and ordinary public infrastructure, a technically competent verifier can:

1. create and download their own DaffyDefs CVDR JSON;
2. verify that exact JSON with the supplied reference verifier;
3. independently corroborate the relevant profile-canister module hash from ICP;
4. compare the receipt's V3-attested code identity with the DaffyDefs release record; and
5. perform the supplementary V3B build-provenance comparison by rebuilding the profile-canister WASM from the disclosed source/build materials and comparing its SHA-256 with the module hash attested in the receipt.

The reference verifier evaluates the applicable V1, V2 and V3A validity axes. V3B build provenance is established separately by the published rebuild-and-compare procedure.

## Current live demo release

- Live frontend: `https://5b3yq-gqaaa-aaaaj-qp4ta-cai.icp0.io/`
- Product/build provenance anchor: `14fb08c40f42419a4ca767982c8f797351025ff1`
- Released post-shrink profile-WASM SHA-256:
  `cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9`
- Live factory module hash:
  `837a44b3ece8b901ad1af305a1252f6bd53d93819e81ea288584e547e970699a`
- Fresh acceptance profile:
  `5ff4g-7qaaa-aaaaj-qsehq-cai`
- Fresh acceptance receipt:
  `050f152899a866cd16cf3b7b9f3d49f17ae6d58499ac27d3fb7793dabc0963e6`
- Banked exact JSON:
  `docs/acceptance/receipts/deletion-receipt-050f1528.json`
- Banked JSON SHA-256:
  `add5a6c5f3a996fa6e24184823e74ea1ff1bef0949fb86dff91b1cf04d2bf3e2`
- Packaged Linux reference-verifier SHA-256:
  `c355fe7e92a2c7db1862fb7dfa55822efc53659739abac69648cc741db7b037f`

The fresh mainnet receipt attests the released profile hash above. V1 PASS and V2 PASS were obtained against the exact downloaded JSON, and V3 was SUBNET-ATTESTED; the current live profile hash independently matched; and an independent rebuild from the exact public source anchor produced the same post-shrink profile hash.

The reproduction was performed in multiple clean same-host configurations and in a pinned Debian container built from a tracked-files-only source capsule with no TAV credentials. **No reproduction on physically distinct hardware is claimed.**

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
- `docs/acceptance/` — current and historical acceptance evidence
- `RELEASES.md` — release/deployment record

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
cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9  wasm_out/profile_canister.wasm
```

Pinned-container reproduction:

```bash
bash scripts/build-capsule-container.sh
```

## Application build

`scripts/build.sh` is the complete DaffyDefs application build pipeline: profile → factory → bulletin board → frontend. It is distinct from the narrower profile-WASM V3B reproducibility procedure.

## Scope

The CVDR code-identity/provenance claim is about the **profile canister identified by the receipt**. The factory, bulletin board, frontend and reference verifier are outside that profile-WASM provenance boundary.

Older acceptance and deployment records retained under `docs/acceptance/` and the historical sections of `RELEASES.md` are explicitly historical evidence. They do not define the current release.
