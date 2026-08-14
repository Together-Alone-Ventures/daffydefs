# DaffyDefs — Release Record

## vNext DaffyDefs Demo Capsule — candidate (14 Aug 2026)

Historical release records below describe the deployment state and claims that applied to those earlier releases. Where an older section says the build was unpinned or attested-only, read that as a statement about that historical release, not this vNext candidate.

### Capsule identity

| Field | Value |
|---|---|
| Private branch | `vnext-self-contained-baseline` |
| Backed-up branch head at audit | `de7ca23f8787917daaac6018cdbdbacd6657f704` |
| Profile-repro recipe commit | `273906206a0760ca88896524761809e260d996c8` |
| Profile-WASM candidate SHA-256 | `cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9` |
| Live deployment binding | **PENDING controller-window acceptance** |

The capsule repository commit and the profile-WASM provenance boundary are distinct.

### Profile build boundary

The V4 reproducibility target is:

`wasm_out/profile_canister.wasm`

after `ic-wasm ... shrink`.

### Toolchain and source pins

| Component | Pin |
|---|---|
| Rust | `1.97.1` |
| target | `wasm32-unknown-unknown` |
| `ic-wasm` | `0.11.1` |
| product MKTd02 | `mktd02-v0.5.0` / `f0687ad23d1718aeb9231d32642089bd3cc01bc0` |
| product zombie-core | `zombie-core-v0.4.0` / `f3ab186fd091b9e618dc944e95b518366ac0c43e` |
| public Rust dependencies | exact resolution/checksums in root `Cargo.lock` |

Canonical recipe:

```bash
bash scripts/build-profile-repro.sh
```

Pinned container environment:

```bash
bash scripts/build-capsule-container.sh
```

### Reproduction evidence

The profile WASM has been reproduced from the DaffyDefs source in multiple clean same-host configurations and in a pinned Debian container built from a tracked-files-only capsule with no TAV credentials. These runs produced:

`cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9`

No reproduction on physically distinct hardware is claimed. The published build procedure and source material allow any third party to perform an independent rebuild.

### Deployment status

Before the demo capsule is frozen, the approved controller-window acceptance must:

1. deploy/confirm the browser-finalisation frontend required by the current flow;
2. build the factory using the exact candidate profile WASM;
3. deploy/upgrade the factory through the approved controller environment;
4. mint a fresh profile;
5. delete it through the live flow and download the CVDR JSON without transformation;
6. verify that JSON directly with the DaffyDefs reference verifier; and
7. confirm the receipt's certified `module_hash` equals the candidate hash above.

Only after that binding is observed should the live release be described as reproducibly grounded for V4.

---

## Historical release record — W5 / R-b (July 2026)

> **This record was completed at W5 go-live and is the deploy ceremony's exit artifact.**
> Fields marked `PENDING` were filled during the ceremony from the values the ceremony
> itself produced. Values below that are already filled were verified against the tree at the stated
> commit, 17 Jul 2026.

## Release

| Field | Value |
|---|---|
| App name | **DaffyDefs** |
| Version | proposed at gate close (held for docs word) |
| Release date | ceremony 21 Jul 2026; R-b remediation 22 Jul 2026 |
| Signer | `zd-deployer` = `q3gkv-ebczt-…-dqe` (stef-mvp), factory `5g26e` sole controller |

## Baselines

This release identifies **two** baselines. Both are required to reproduce or audit it.

| Baseline | Value |
|---|---|
| **DaffyDefs application baseline** | source commit `5ca421f` (R-b remediation SHA; supersedes ceremony go-live `25f199f` — see module_hash history) |
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

Filled from the mainnet deployment — R-b scoped remediation, 22 Jul 2026 (each value
read back certified via `fetch-cert`):

| Hash | Value | Role |
|---|---|---|
| **Profile canister Module Hash** (current deployed at that release) | `07421692872c49b1d44d700ab3c30d37d0f9ef53345de0b5de1328a012dd1af8` | subnet-attested code anchor for receipts finalized under the remediation build |
| **Factory Module Hash** (current deployed at that release) | `ccbfbdfd1ecc74667d09ae76fea1f1dca708b8855ef6526b64a6166d219bb905` | host/factory deployment provenance — **not** a receipt code anchor |
| **Ceremony receipt attested anchor** (historical) | `85a326cda94bff9e56e0c6f0b72d6412c6a76d71f4329c43f1f651c23ebe5cea` | the code identity the genuine W5 receipt `0eceff7d…` certifies (profile hash at deletion, before the R-b profile upgrade); its historical V3-A verdict = **SUBNET-ATTESTED** |

Two distinct Module Hashes are recorded. The **PROFILE CANISTER Module Hash**
is the subnet-attested code anchor carried by every receipt (current terminology: V3 attested code identity). The
**FACTORY Module Hash** is host/factory deployment provenance only — it is not the
receipt's code anchor.

**Superseded ceremony build (history).** The original 21 Jul ceremony deployed profile
`85a326cd…` / factory `b9b6a052…` from go-live SHA `25f199f`. The R-b remediation
(SHA `5ca421f`) re-upgraded factory `5g26e` (→ `ccbfbdfd…`) and ceremony profile `y5izv`
(→ `07421692…`). The prior factory `b9b6a052…` is archived as the rollback anchor
`rollback_artifacts/profile_factory_25f199f_PRE.wasm`.

## Ceremony & remediation record

**W5 mainnet ceremony (21 Jul 2026)** — §2 factory upgrade `5g26e` → `b9b6a052` (POST-verified);
§2.4 frontend asset-only sync to `5b3yq` (factory + bulletin invariant); §3 NO-OP on the 12
legacy profiles; §4 minted ceremony profile `y5izv-byaaa-aaaaj-qsdfq-cai` (owner
`zd-ceremony-test` = `bnei3-…-7ae`, external hash `85a326cd`), Phase A delete → receipt
`0eceff7de5785e5d50bedca0cb3553409ba6ef6c5e2929715f903b48ff6abf70`, factory 4-arg finalize OK
(first live-mainnet exercise of the v4 proxy), guard PASS (delta 1.31s).

**§5.1 incident + remediation (R-a/R-b).** The W5 §5.1 verifier network-fetch historical V3-A false-failed:
DaffyDefs' `mktd_get_receipt` export struct dropped `module_hash_certificate`, so the verifier
could not see the second certificate (the on-chain receipt was complete — proven at R-b step 5:
both certs present). Remediation: **R-a** (SHA `5ca421f`) exports the field additively; **R-b**
(22 Jul) re-upgraded `5g26e` (→ `ccbfbdfd`) and `y5izv` (→ `07421692`) on mainnet. The historical verifier
re-run exited 0; current terminology for the archival code-identity result is **V3 SUBNET-ATTESTED**. Live module corroboration reports the expected upgraded-since-deletion divergence. Full evidence: handoff directory
`ceremony_handoff_w5_remediated/`. §3 no-op remained fully in force; only `5g26e` and `y5izv`
were ever touched.

## Dependency pins

| Component | Pin | Resolved |
|---|---|---|
| MKTd02 engine | `mktd02-v0.5.0` | `git+…/ICP-Delete-Leaf.git?tag=mktd02-v0.5.0#f0687ad23d1718aeb9231d32642089bd3cc01bc0` |
| zombie-core (DaffyDefs) | `zombie-core-v0.4.0` | `git+…/zombie-core?tag=zombie-core-v0.4.0#f3ab186fd091b9e618dc944e95b518366ac0c43e` |
| zombie-core (verifier / helper line) | `zombie-core-v0.4.1` | `git+…/zombie-core?tag=zombie-core-v0.4.1#27d508f0df9c6a1f86c11b2bf197e3f091cb858f` |

### The two zombie-core versions are intentional

The deployed DaffyDefs tree resolves **zombie-core v0.4.0** — matching `mktd02-v0.5.0`'s
own pin. The **verifier / helper line uses v0.4.1**. v0.4.1 added the off-canister finalization-delay constant and did not change the receipt wire/schema or hash preimages.

## Historical build/provenance status

For this July release, the build recipe was not pinned sufficiently to support an independent source→WASM reproducibility claim. The historical release therefore used an **attested** provenance posture: the recorded module hash was the subnet-attested value observed on mainnet, not a claim that a third party could rebuild the same bytes from source.

That historical limitation is retained here as release history. It is superseded for the vNext candidate by the pinned profile build boundary and reproduction evidence recorded at the top of this file.
