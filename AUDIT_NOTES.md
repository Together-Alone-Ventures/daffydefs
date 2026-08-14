# DaffyDefs demo-capsule audit — 14 Aug 2026

## Confirmed good

- Private branch backed up on GitHub.
- Travel-laptop working tree cleaned after the accidental nested clone/install test.
- Canonical profile reproducibility script exists.
- Rust pinned by `rust-toolchain.toml`.
- `ic-wasm` pinned in the candidate container.
- TAV-private product source snapshots are local and recorded with exact revisions/tree hashes.
- Public Rust dependencies use `Cargo.lock`.
- Candidate profile hash is recorded by the build-machinery commit.
- DaffyDefs reference verifier source is in-repo and its semantic delta is recorded.

## Documentation changes prepared in this commit

1. Replace stale top-level README tool/build claims.
2. Add `docs/VERIFICATION_PROCEDURE.md`, including file/network invocation, Options A–D, runnable ICP corroboration, and two real worked examples.
3. Replace the stale RTS mapping and add the IC trust-root/subnet residual and off-canister-copy limitation.
4. Add `docs/REFERENCE_VERIFIER.md` with the Linux x86_64 target path, `0.6.1 + DaffyDefs deltas` identity, and binary SHA placeholder pending packaging.
5. Add the vNext release-record candidate section and distinguish the older July record as historical.

## Remaining items

- Linux x86_64 convenience verifier packaged and validated: 62/62 tests PASS, real mainnet receipt V1–V3 PASS, SHA-256 `c355fe7e92a2c7db1862fb7dfa55822efc53659739abac69648cc741db7b037f`.
- Controller-window frontend/factory deployment and fresh end-to-end acceptance receipt.
- Replace candidate/PENDING language at freeze with final observed deployment values.
- Final naive-verifier walkthrough using only the pack/repo.
- Publication gate: review GitHub dependency advisories (GitHub currently reports 13 on the default branch, including 7 high), plus secrets scan and final claims sweep. This is not a blocker for the private profile-WASM provenance work.
