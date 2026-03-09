# DaffyDefs

An ultralight social media dApp on the Internet Computer Protocol (ICP). Users post "nonsense" word challenges and others submit their best definitions.

Built as a test platform for [MKTd02](https://github.com/Together-Alone-Ventures) integration, deliberately mirroring OpenChat's per-customer canister architecture.

DaffyDefs is a worked example/template integration of MKTd02 in an application context.
It is not the canonical protocol or verification authority.

## Repository Boundaries

- MKTd02 repo: canonical generic protocol/integration truth
- CVDR-Verify repo: reference verification layer
- DaffyDefs repo: worked example/template integration

## Finalization Model (A→B→C)

The three-phase deletion/finalization sequence (A→B→C) reflects ICP platform constraints around certified query certificates and update-call finalization.
DaffyDefs demonstrates one integration pattern for that constraint (including a narrow Phase C proxy), but does not define the protocol.

## Architecture

- **Profile Canister** — one per user, stores PII (email, birthdate, gender, display name)
- **Profile Factory** — creates/tracks per-user profile canisters, maps principal → canister ID
- **Bulletin Board** — shared canister storing challenges, comments, and likes
- **Frontend** — React PWA served via ICP asset canister

## Requirements

| Tool | Minimum version |
|------|----------------|
| dfx (DFINITY SDK) | 0.24+ |
| Node.js | 20+ |
| Rust (stable) | any recent |
| wasm32-unknown-unknown target | installed via rustup |
| candid-extractor | any recent |
| ic-wasm | any recent |

## Internet Identity (Local)

Local development uses a **pinned II WASM** via `dfx deps`:

- Source: mainnet II canister `rdmx6-jaaaa-aaaaa-aaadq-cai`
- Pulled via `dfx deps pull` (version determined by dfx)
- Local II behaves slightly differently from mainnet (simpler identity creation flow, no WebAuthn hardware keys) — this is expected

## Build & Deploy (Local)

```bash
# Start local replica
dfx start --background

# Pull and deploy Internet Identity
dfx deps pull
dfx deps deploy

# Build everything (correct order, Candid verification, frontend)
bash scripts/build.sh

# Deploy canisters + frontend
dfx deploy
```

## Build Pipeline

`scripts/build.sh` is the **single source of truth** for all WASM artifacts:

1. Builds profile_canister WASM
2. Optimises with ic-wasm shrink
3. Copies for factory's `include_bytes!` embedding
4. Builds profile_factory (embeds profile_canister WASM)
5. Builds + optimises bulletin_board
6. Runs candid-extractor on **all final shipped WASMs** — build fails if extraction fails or Candid drifts
7. Generates JS IDL factory for frontend
8. Builds React frontend

`dfx.json` points to `wasm_out/` for all canister WASMs. `dfx deploy` does NOT rebuild — it uses the pre-built artifacts.

## Architecture Spec

See `DaffyDefs_GPT5_requirements_v2.0.docx` for the full architecture specification.

## Build Plan

See `DaffyDefs_Build_Plan_FINAL.md` for the complete implementation plan.

## Spec Version

This implementation is built against spec v2.0, tagged as `spec-v2-frozen`.
