# Vendored TAV source snapshots

This Slice-5 candidate is based on DaffyDefs commit
`d41043deb35ff2187ecce6dd2199eac74eb8729a`.

Only Together-Alone Ventures source snapshots are listed here. Registry crates
are fixed by the applicable `Cargo.lock` and Cargo vendor checksum metadata.

| Build boundary | Source snapshot | Origin | Exact revision | Upstream tree | Local location |
| --- | --- | --- | --- | --- | --- |
| Product | MKTd02 v5 (`mktd02/` subtree) | `https://github.com/Together-Alone-Ventures/ICP-Delete-Leaf.git` | `2a10bf3ee056d3ff53327ca23654609a6f430c5e` | exact vendored copy | `vendor/mktd02/` |
| Product | zombie-core v0.5.0 | `https://github.com/Together-Alone-Ventures/zombie-core` | `223723885cfbb548d6b218aee8500b073fda4b58` | exact vendored copy | `vendor/zombie-core/` |
| Verifier | CVDR-Verify v0.8.0 DRAFT | `https://github.com/Together-Alone-Ventures/CVDR-Verify.git` | `560e483b047209ee83463dfab29da07acb422feb` | exact subtree copy | `tools/cvdr-verify/` |
| Verifier | zombie-core v0.5.0 | `https://github.com/Together-Alone-Ventures/zombie-core` | `223723885cfbb548d6b218aee8500b073fda4b58` | exact vendored copy | `tools/cvdr-verify/vendor/zombie-core/` |

Each vendored TAV source snapshot differs from its stated upstream tree only by
Cargo vendor manifest normalization and an absent `.gitignore`.

Vendoring covers only TAV-private sources. Public dependencies are pinned by
version and checksum in the applicable `Cargo.lock` and fetched from crates.io;
Cargo enforces those checksums identically whether sources are fetched or
vendored. Crates.io availability is therefore a build dependency, while source
integrity remains lockfile-enforced.

## DaffyDefs baseline modifications

The CVDR-Verify snapshot has one source-tree isolation delta: the `[workspace]`
stanza in `tools/cvdr-verify/Cargo.toml`, which keeps the verifier outside the
parent product workspace. The baseline also adds `.cargo/` source replacement
for the TAV git sources and their minimal `vendor/` trees. Public crates continue
to resolve from crates.io under `--locked`. The verifier's lockfile and TAV
vendor directory are a separate build boundary and form no part of the
profile-WASM source identity.

## Current verifier semantics

The authoritative v0.8.0 DRAFT source at
`560e483b047209ee83463dfab29da07acb422feb` defines validity as V1 ∧ V2 ∧ V3A
for v4/v5 receipts, and V1 ∧ V2 for v2/v3 receipts. V3B build provenance and
live-state diagnostics are informational and non-gating. The DaffyDefs delta is
limited to standalone workspace/source replacement and packaging; no verifier
logic or verdict semantics are locally altered.

DaffyDefs contains the TAV-specific source required for independent rebuilding.
Standard public Rust dependencies are resolved from their normal public
distribution sources using the committed lockfile. Copying the complete public
dependency ecosystem into the application repository is neither required by
MKTd02 nor part of the reproducibility claim.

The capsule release commit identifies the repository state as a whole. The
profile-WASM provenance boundary is the profile source, its TAV dependencies,
lockfile, toolchain and build recipe. tools/cvdr-verify/ is outside that
boundary; verifier-only changes never alter profile-WASM source identity.
