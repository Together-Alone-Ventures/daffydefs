# Vendored TAV source snapshots

The DaffyDefs v5.1 line uses the following pinned TAV source snapshots. The
profile canister emits `mktd02-v5.1` receipts.

Only Together-Alone Ventures source snapshots are listed here. Registry crates
are fixed by the applicable `Cargo.lock` and Cargo vendor checksum metadata.

| Build boundary | Source snapshot | Origin | Exact revision | Upstream tree | Local location |
| --- | --- | --- | --- | --- | --- |
| Product | MKTd02 v5.1 (`mktd02/` subtree, branch `v5.1-correction`) | `https://github.com/Together-Alone-Ventures/ICP-Delete-Leaf.git` | `8e5024dc8d27be19dafc579b2ac955e45da28b0c` | `09160c04e13d5257fbe7ecb5f755cc3898f12eab` (`mktd02/`) | `vendor/mktd02/` |
| Product | zombie-core v0.5.0 (branch `v5.1-correction`) | `https://github.com/Together-Alone-Ventures/zombie-core` | `8ac64df5d0110ec7ebbbe8382b7a826dda17085a` | `c24ad9b2207c9cee4dca4d9873de86f6c72caecc` (root) | `vendor/zombie-core/` |
| Verifier | CVDR-Verify mktd02-verify 0.8.0 (branch `v5.1`) | `https://github.com/Together-Alone-Ventures/CVDR-Verify.git` | `67cbe4bf3878a1853a1839dfe96a76281ce3feea` | `8d2853fea1ad706d47ed15d0438f705d2565cb75` (`mktd02/mktd02-verify/`) | `tools/cvdr-verify/` |
| Verifier | zombie-core v0.5.0 (branch `v5.1-correction`) | `https://github.com/Together-Alone-Ventures/zombie-core` | `8ac64df5d0110ec7ebbbe8382b7a826dda17085a` | `c24ad9b2207c9cee4dca4d9873de86f6c72caecc` (root) | `tools/cvdr-verify/vendor/zombie-core/` |

Upstream tree hashes are `git rev-parse <revision>:<path>` in the origin
repository. Superseded v5 pins: MKTd02 `2a10bf3ee056d3ff53327ca23654609a6f430c5e`,
zombie-core `223723885cfbb548d6b218aee8500b073fda4b58`, CVDR-Verify
`560e483b047209ee83463dfab29da07acb422feb`.

Each vendored TAV source snapshot differs from its stated upstream tree only by
Cargo vendor manifest normalization, the `.cargo-checksum.json` file, and absent
`.gitignore`/`.gitattributes` files.

Vendoring covers only TAV-private sources. Public dependencies are pinned by
version and checksum in the applicable `Cargo.lock` and fetched from crates.io;
Cargo enforces those checksums identically whether sources are fetched or
vendored. Crates.io availability is therefore a build dependency, while source
integrity remains lockfile-enforced.

## DaffyDefs baseline modifications

The CVDR-Verify snapshot differs from its upstream subtree by: the `[workspace]`
stanza in `tools/cvdr-verify/Cargo.toml`, which keeps the verifier outside the
parent product workspace; a provenance preamble in `tools/cvdr-verify/README.md`;
`vendor` excluded from the source scan in `tests/retired_label.rs`; and the
packaged `bin/linux-x86_64/mktd02-verify` built with `cargo build --release --locked`. The baseline also adds `.cargo/` source replacement
for the TAV git sources and their minimal `vendor/` trees. Public crates continue
to resolve from crates.io under `--locked`. The verifier's lockfile and TAV
vendor directory are a separate build boundary and form no part of the
profile-WASM source identity.

## Current verifier semantics

The authoritative source at
`67cbe4bf3878a1853a1839dfe96a76281ce3feea` defines validity as V1 ∧ V2 ∧ V3A
for v4/v5/v5.1 receipts, and V1 ∧ V2 for v2/v3 receipts. V3B build provenance and
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
