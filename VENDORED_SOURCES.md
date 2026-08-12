# Vendored TAV source snapshots

This vNext baseline is based on DaffyDefs commit
`c0fbb14f885896ed9d34871b108252702dbf8e62`.

Only Together-Alone Ventures source snapshots are listed here. Registry crates
are fixed by the applicable `Cargo.lock` and Cargo vendor checksum metadata.

| Build boundary | Source snapshot | Origin | Exact revision | Upstream tree | Local location |
| --- | --- | --- | --- | --- | --- |
| Product | MKTd02 (`mktd02-v0.5.0`), `mktd02/` subtree | `https://github.com/Together-Alone-Ventures/ICP-Delete-Leaf.git` | `f0687ad23d1718aeb9231d32642089bd3cc01bc0` | `386e9ea13e1c0d907df32af10cabb0e21dc0a492` | `vendor/mktd02/` |
| Product | zombie-core (`zombie-core-v0.4.0`) | `https://github.com/Together-Alone-Ventures/zombie-core` | `f3ab186fd091b9e618dc944e95b518366ac0c43e` | `f8b8b582d9b03d35b39e4d24abea723b8c4dfa6f` | `vendor/zombie-core/` |
| Verifier | CVDR-Verify (`v0.6.1`), `mktd02/mktd02-verify/` subtree | `https://github.com/Together-Alone-Ventures/CVDR-Verify.git` | `ad16f2a` | `d832140efcc2c4fa800d2562afd506cd34abff3a` | `tools/cvdr-verify/` |
| Verifier | zombie-core (`zombie-core-v0.4.1`) | `https://github.com/Together-Alone-Ventures/zombie-core` | `27d508f0df9c6a1f86c11b2bf197e3f091cb858f` | `6b3af4c1acde259bfc159fcfc2e16d69e0e3cdd7` | `tools/cvdr-verify/vendor/zombie-core/` |

The CVDR-Verify repository root tree at `ad16f2a` is
`2b0ac4bf09289be11312409dad3c8f6de7e05d86`; the verifier snapshot is the
subtree identified separately in the table.

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
