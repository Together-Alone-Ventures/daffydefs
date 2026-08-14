# DaffyDefs — Demo Capsule (private candidate)

DaffyDefs is a worked example of ICP-Delete (Leaf): one profile canister per user, a shared bulletin board, a profile factory, and a browser frontend.

This branch is being prepared as a self-contained technical demo capsule. It remains **private** pending a separate publication ruling.

## What this repository is intended to let an independent verifier do

Using this repository and ordinary public software sources, a technically competent verifier can:

1. create and download their own DaffyDefs CVDR JSON;
2. verify that JSON with the supplied reference verifier;
3. independently obtain/corroborate the relevant canister module hash from ICP;
4. compare the receipt's attested code identity with the DaffyDefs release record; and
5. perform the strongest V4 check by rebuilding the profile-canister WASM and comparing its SHA-256 with the module hash attested in the receipt.

The reference verifier automates **V1–V3**. **V4 (code provenance) is a published procedure, not an automated PASS produced by the reference tool.**

## Current capsule status

- Capsule branch: `vnext-self-contained-baseline`
- Current private branch head at backup: `de7ca23f8787917daaac6018cdbdbacd6657f704`
- Profile reproducibility recipe introduced at: `273906206a0760ca88896524761809e260d996c8`
- Candidate post-shrink profile-WASM SHA-256:
  `cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9`
- The candidate hash is **not yet the final live-demo provenance claim**. The controller-window deployment/acceptance step must first ensure newly minted profiles actually run this profile WASM and that a fresh downloaded CVDR attests the same hash.
- The browser-finalisation frontend bundle also has a controller-gated deployment handoff. See `docs/acceptance/DEPLOY_HANDOFF.md`.

These candidate/PENDING statements are temporary preparation-state text. At demo-pack freeze they must be replaced by the final observed deployment state; the frozen pack must read as one current version, not as an evolution narrative.

## Repository map

- `src/profile_canister/` — per-user profile canister
- `src/profile_factory/` — factory that creates profile canisters and embeds the profile WASM
- `src/bulletin_board/` — shared non-profile application content
- `src/frontend/` — browser application
- `vendor/mktd02/` — exact TAV MKTd02 source snapshot required for the product build
- `vendor/zombie-core/` — exact TAV zombie-core source snapshot required for the product build
- `tools/cvdr-verify/` — DaffyDefs copy of the reference verifier source
- `tools/cvdr-verify/bin/linux-x86_64/mktd02-verify` — included private-demo convenience executable
- `scripts/build-profile-repro.sh` — canonical profile-WASM reproducibility recipe
- `releases/CANDIDATE/Dockerfile` — pinned container environment that invokes the same canonical recipe
- `VENDORED_SOURCES.md` — exact upstream revisions/tree hashes and build-boundary notes
- `docs/VERIFICATION_PROCEDURE.md` — technical V1–V4 verification procedure
- `docs/RESIDUAL_TRUST_STATEMENT.md` — what the receipt does and does not establish
- `docs/REFERENCE_VERIFIER.md` — reference verifier packaging and trust posture
- `RELEASES.md` — release/deployment record

## Rebuilding the profile WASM

The code-provenance target is the **final post-`ic-wasm shrink` profile canister WASM**, not the factory, bulletin board, frontend, or verifier.

Required pins for the reproducibility path:

- Rust: `1.97.1` (`rust-toolchain.toml`)
- target: `wasm32-unknown-unknown`
- `ic-wasm`: `0.11.1`
- Rust dependencies: exact resolution in `Cargo.lock`
- TAV source snapshots: exact revisions recorded in `VENDORED_SOURCES.md`
- public crates: fetched from crates.io under `Cargo.lock` versions/checksums

Canonical command:

```bash
bash scripts/build-profile-repro.sh
```

Expected candidate output:

```text
cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9  wasm_out/profile_canister.wasm
```

For the pinned Debian environment:

```bash
bash scripts/build-capsule-container.sh
```

The container is an environment wrapper only; it invokes the same `scripts/build-profile-repro.sh`.

## Application build

`scripts/build.sh` remains the DaffyDefs application build pipeline (profile → factory → bulletin board → frontend). It is distinct from the narrower profile-WASM reproducibility procedure above.

## Important scope note

The CVDR's code-identity/provenance claim is about the **profile canister identified by the receipt**. The factory, bulletin board, frontend, and reference verifier are outside that profile-WASM provenance boundary.

Historical acceptance material under `docs/acceptance/` records earlier deployments and verifier output. It is useful evidence, but current V1–V4 terminology and the current candidate reproducibility claim are defined by the current top-level documentation.
