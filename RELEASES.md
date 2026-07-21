# DaffyDefs — Release Record

> **This record is completed at W5 go-live and is the deploy ceremony's exit artifact.**
> Fields marked `PENDING` are filled during the ceremony from the values the ceremony
> itself produces. A `PENDING` field is never pre-filled, estimated, or back-filled from
> a local build — most importantly `module_hash` (see below). Values below that are
> already filled are knowable now and were verified against the tree at the stated
> commit, 17 Jul 2026.

## Release

| Field | Value |
|---|---|
| App name | **DaffyDefs** |
| Version | `PENDING` — proposed at gate close |
| Release date | `PENDING` — W5 go-live |
| Signer | `PENDING` — deploy ceremony signer |

## Baselines

This release identifies **two** baselines. Both are required to reproduce or audit it.

| Baseline | Value |
|---|---|
| **DaffyDefs application baseline** | source commit `PENDING` — the W1/W2 merge commit (see note) |
| **Integration baseline** | `ICP-Delete-Leaf @ fe55ff7` — helper (`zd-finalize-helper`) + host-integration contract docs |

**Note on the application baseline.** W1/W2 landed as three direct commits on `main`
(`4a0350a` profile_canister v0.5.0 adoption → `88dc02b` v4 factory finalize proxy →
`d03f9f1` rehearsal tests), not via a merge commit. There is currently no merge commit
to cite. Placeholder held pending the gate-close decision on what to cite: either the
W1/W2 tip (`d03f9f1` at time of writing) or a merge commit created at gate close. This
is a decision for the ceremony, not something to resolve by picking a value here.

## Canister IDs (mainnet)

| Canister | ID |
|---|---|
| `profile_factory` | `5g26e-liaaa-aaaaj-qp4tq-cai` |
| `bulletin_board` | `5iytm-qyaaa-aaaaj-qp4sq-cai` |
| `frontend` | `5b3yq-gqaaa-aaaaj-qp4ta-cai` |
| `profile_canister` | **per-user / dynamic** — minted by `profile_factory` at profile creation; no fixed ID. The factory's deploy cross-check gates the code identity installed into each. |

## module_hash

**`PENDING — mainnet go-live value; local/PocketIC hashes are prohibited here.`**

Two distinct Module Hashes are recorded at go-live. The **PROFILE CANISTER Module Hash**
is the subnet-attested code anchor carried by every receipt (the value V3 certifies). The
**FACTORY Module Hash** is host/factory deployment provenance only — it is not the
receipt's code anchor.

This field takes the mainnet value observed at go-live, read back from the deployed
canister. A hash from a local `dfx` or PocketIC build MUST NOT be entered, even
provisionally, even annotated: the build is not currently reproducible (see
*Verification* below), so a local hash carries no expectation of equalling the mainnet
value and would be actively misleading in this record.

## Dependency pins

| Component | Pin | Resolved |
|---|---|---|
| MKTd02 engine | `mktd02-v0.5.0` | `git+…/ICP-Delete-Leaf.git?tag=mktd02-v0.5.0#f0687ad23d1718aeb9231d32642089bd3cc01bc0` |
| zombie-core (DaffyDefs) | `zombie-core-v0.4.0` | `git+…/zombie-core?tag=zombie-core-v0.4.0#f3ab186fd091b9e618dc944e95b518366ac0c43e` |
| zombie-core (verifier / helper line) | `zombie-core-v0.4.1` | `git+…/zombie-core?tag=zombie-core-v0.4.1#27d508f0df9c6a1f86c11b2bf197e3f091cb858f` |

### The two zombie-core versions are intentional, and this is why it is correct

The deployed DaffyDefs tree resolves **zombie-core v0.4.0** — matching `mktd02-v0.5.0`'s
own pin, which keeps exactly one `zombie-core` in the canister dependency graph. The
**verifier / helper line uses v0.4.1**. This divergence is correct and deliberate.

v0.4.1 added **only** the off-canister finalization-delay constant. Verified against the
tag-to-tag diff (`git diff zombie-core-v0.4.0 zombie-core-v0.4.1`, 4 files,
+43 / −1):

- `src/protocol.rs` (new) — adds `MAX_FINALIZATION_DELAY_NS` (3,600 s in ns), the
  normative threshold interpreted authoritatively by CVDR-Verify.
- `src/lib.rs` — `pub mod protocol` + crate-root re-export.
- `Cargo.toml` — version bump `0.4.0` → `0.4.1`.
- `RELEASES.md` — release notes.

**No wire/schema change:** no receipt-schema, serialized-wire, preimage, domain-tag,
receipt-ID, or golden-vector change; v4 three-state semantics untouched; no dependency
bumps. The constant is consumed **off-canister only** (by the helper's guard, to decide
`DELAY_EXCEEDED`), and never by canister code. A canister pinned to v0.4.0 and a helper
pinned to v0.4.1 therefore agree on every byte that crosses the wire, and the receipts
the canister produces are bit-identical under either. Pinning the canister to v0.4.0
buys graph unity with the engine at zero semantic cost.

## Build recipe

| Field | Value |
|---|---|
| Recipe | `scripts/build.sh` (idempotent; builds `profile_canister` → `profile_factory` → `bulletin_board`, `ic-wasm shrink` per artifact into `wasm_out/`, then verifies Candid extraction on the shipped WASMs) |
| Toolchain pins | **NONE — see finding** |

### Finding: the build is not currently pinned or reproducible

This is recorded as a finding, not papered over. As of `d03f9f1`, the build recipe does
not pin its inputs:

- **No `rust-toolchain.toml` / `rust-toolchain` file.** `rustc` floats to whatever is
  ambient (observed at time of writing: `rustc 1.90.0 (1159e78c4 2025-09-14)`). A
  different `rustc` will generally produce a different `module_hash` from identical
  source.
- **`cargo build` is invoked without `--locked`.** Nothing in the recipe enforces that
  the committed `Cargo.lock` is the lock actually built against.
- **`ic-wasm` is unpinned** — an unversioned command on `PATH`. `shrink` output is part
  of the shipped artifact, so the `ic-wasm` version is `module_hash`-determining.
- **No `dfx` version pin.** (`dfx.json`'s `"version": 1` is the dfx.json schema version,
  not a dfx toolchain pin.)

**Consequence for this record:** the same source commit is not currently guaranteed to
reproduce the same `module_hash` on another machine, or on this machine at a later date.

## Verification

| Field | Value |
|---|---|
| `verification_level` | **`attested`** |

**`attested` is what honestly applies** — at go-live and after it. `reproducible` is
available only where the build recipe supports independent reproduction of the shipped
artifact, and per the finding above, it does not. `attested` means the recorded
`module_hash` is the value observed on the deployed mainnet canister and subnet-attested
via the code-identity flow (the `read_state` module-hash certificate); it does **not**
assert that a third party can rebuild that hash from source.

Raising this release to `reproducible` requires pinning `rustc` (via
`rust-toolchain.toml`), `ic-wasm`, and `dfx`, building with `--locked`, and then
demonstrating a byte-identical rebuild. That work is not in Gate 2's W1–W5 scope and is
not claimed here.
