# W5 RUNBOOK v2 — DaffyDefs v4 mainnet deployment & first genuine finalization
**(G conditionally approved 16 Jul; nine amendments incorporated. To be committed to daffydefs/tools/ and CD-verified as the exact committed version. This document is NOT the deployment word — mainnet execution requires Stef's explicit authorisation.)**

**Mutation scope:** factory upgrade (`5g26e-liaaa-aaaaj-qp4tq-cai`), frontend asset deploy (`5b3yq-gqaaa-aaaaj-qp4ta-cai`), one dedicated-test-principal profile mint, one real deletion finalized. Bulletin untouched.

## 0. Preconditions — ALL verified and recorded before any mutation
1. **Go-live commit:** all Gate 2 changesets pushed; runbook itself committed; working tree clean at the recorded SHA. CD has verified the exact go-live commit and this exact runbook version (G sequence step 1).
2. **Local rehearsal green at the go-live commit** (fresh replica, same day).
3. **[G-1] Upgrade-compatibility check (stable memory):** the engine delta includes `ReceiptBytes` 8192→16384 (a stable-structures bound change). Run the scripted compat check locally (`tools/upgrade_compat_check.sh` v2, **three-canister** shape): all three canisters install from the PRE wasm (`8f7b15f7…`) and upgrade to go-live (`85a326cd…`), differing only in pre-upgrade state.
   - **P1 — finalized-v3 survival (the core 8192→16384 question):** create profile → Phase A delete → finalize **under old code** via the v0.4.1-era 2-arg path → a finalized **v3** receipt under the old 8192 bound → upgrade → assert the receipt is intact, readable and exportable under new code, tombstone state preserved, `deletion_seq` preserved.
   - **P2 — plain-state survival:** create profile, no deletion → upgrade → assert profile data intact and functional.
   - **P3 — post-upgrade v4 capability:** install empty → upgrade → full fresh **v4** cycle (create → Phase A delete → helper fetch-cert → guard → direct 3-arg finalize) → finalized v4 receipt, both certificates present.
   - **Coexistence (restates "same store", impossible in Leaf):** P1's v3 and P3's v4 receipts are both valid under the **same post-upgrade storage schema** (16384 bound); Leaf mode holds one receipt per canister, so coexistence is realized as same schema across canisters, not two receipts in one store.
   PASS required (**all** P1/P2/P3 assertions). Any assertion failing → **return to G** (incompatible stable-memory migration trigger). Record transcript (retained at `tools/evidence/w5p_compat_v2.log`).
   - **OBSERVED EVIDENCE — canister-enforced upgrade invariant (a feature, not a failure):** upgrading a canister *while a receipt is pending* traps by design — `ic0.trap: 'MKTd02: cannot change certified data while finalization lock is held. Finalize the pending receipt before upgrading…'` (captured under old code, v0.4.1-era; transcript retained at `tools/evidence/w5p_trap_oldshape.log`). This is why P1 finalizes **before** upgrading, and why §3 gates every profile on pending state first.
   - **Test-shape authority:** the three-canister shape is C-ruled (G ruled the obligation — demonstrate no incompatible stable-memory migration — not the shape); the shape-correction trail is reported to G in the pre-deployment record.
4. **[G-1] Rollback capability is a precondition, not a hope — SATISFIED via POSSESSION (G 17 Jul):** the exact previously deployed factory WASM is archived at `rollback_artifacts/profile_factory_eb6bb58_PRE.wasm` and hashes exactly `08cb8ff504fab08a694d6b2c4337da90cf1389a302255d50953dd5b9dc5ba59a`, equal to the live factory's certified module hash (helper `fetch-cert`, 17 Jul, cert `/time` 1784266116724055819). The companion `rollback_artifacts/profile_canister_eb6bb58_PRE.wasm` (`8f7b15f7…d3f59a`) is archived for the §0.3 check; both hashes are recorded in `rollback_artifacts/SHA256SUMS`. **Per G, the rebuild-based rollback arm MUST NOT be relied upon for this deployment:** rebuild provenance (isolated worktree at `eb6bb58`) is recorded as **HISTORY only**, it reproduced only because the ambient toolchain happened to be unchanged, and **no reproducible-build claim is authorised anywhere** in this ceremony. Fresh possession re-check is §2.0; inequality there → ABORT (G return-trigger).
   - **[G — backlog, PROMOTED]** Toolchain pinning is now **required before the next production release that intends to claim reproducibility**. It is **not** blocking Gate 2; Gate 2 ships `verification_level: attested`.
5. **[G-1] PROFILE_MAP inventory:** export the complete pre-upgrade mapping (principal → canister ID) and retain it with the ceremony record. WASM rollback alone does not recover state.
6. **[G-3] Profile classification:** classify every existing mapping as (a) dedicated test/operator, (b) known user data, or (c) unknown. Only (a) may be upgraded in this ceremony. **Any (b) or (c) → STOP** (separate migration decision; G return-trigger if unclassifiable).
7. **Controller identity:** recorded; the operating identity is a controller of the factory; the factory is sole controller of minted profiles. Unexpected controller set → ABORT.
8. **[G-5] Publication-safe identity:** the ceremony uses a **dedicated test principal expressly created for public disclosure** — never Stef's personal II or an operational identity. Record: this principal and all resulting receipt metadata are approved for publication (the receipt becomes a committed public fixture).
9. **Cycles:** factory balance recorded, sufficient for one mint + headroom.
10. **Tooling provenance:** helper built from `ICP-Delete-Leaf@fe55ff7`; verifier from CVDR-Verify `v0.6.0` (→ `311aaa0`); both recorded (commit + binary sha256). Mainnet root key hardcoded.

## 1. Build & WASM provenance
1. Clean build at the go-live SHA via `scripts/build.sh`; toolchain versions recorded verbatim.
2. Record `sha256(profile_canister.wasm)` (the embedded/expected profile hash) and `sha256(profile_factory.wasm)`.
3. **[G-2] Frontend provenance:** produce a canonical archive of the exact asset build (`tar` with fixed ordering/mtime, or the asset manifest) and record its sha256 — never an undefined directory state.

## 2. Factory upgrade
0. **[G] Fresh possession re-check — immediately before any mutation:** `sha256sum` the archived artifact (`rollback_artifacts/profile_factory_eb6bb58_PRE.wasm`) **AND** fresh `fetch-cert` the live factory's certified module hash; the two values **MUST be equal**. Inequality = the ruled **stop-and-return** condition — do not proceed. Record both in the transcript.
1. **PRE:** `dfx canister --network ic status 5g26e-…` → record `module_hash`; confirm it equals the §0.4 rollback artifact's hash.
2. **[G-2] Deploy the exact pre-hashed artifact — no silent rebuild:** `dfx canister install 5g26e-… --network ic --mode upgrade --wasm <exact path to the §1.2 profile_factory.wasm>`. Record the precise command + artifact path in the transcript. (Mode upgrade only; reinstall prohibited — PROFILE_MAP.)
3. **POST:** `status` → `module_hash` MUST equal `sha256(profile_factory.wasm)`. Mismatch → ROLLBACK (§6.1).
4. Frontend: deploy the §1.3 archive's contents to `5b3yq-…`; record the deployed asset hash; spot-check pending-finalization copy, no finalize button.

## 3. Existing profile upgrades (only class (a) per §0.6)
**[pre-upgrade pending gate]** Before upgrading **any** profile canister, query its pending state (`mktd_get_certificate`). A pending receipt means the upgrade **will trap by design** (finalization-lock invariant — see §0.3 OBSERVED EVIDENCE). Resolve first: finalize the pending receipt via the helper flow, **then** upgrade. A pending receipt that cannot be finalized first is an abort condition (§7).

For each: `upgrade_profile_canister` (in-code cross-check active; mismatch errs, mapping intact). **[G-3] Additionally record, per profile, the externally observed post-upgrade `module_hash`** (via helper `fetch-cert`, which prints the certified module hash — no controller needed) **equal to the §1.2 profile hash.**

## 4. End-to-end ceremony
1. **Mint** (`get_or_create_profile_canister`, the §0.8 test principal) → record canister ID. Registration cannot occur before the in-code cross-check succeeds.
2. **[G-4] Minted-profile external check:** immediately query the minted canister's `module_hash` externally (helper `fetch-cert` — certified read, publicly available) and confirm it equals `sha256(profile_canister.wasm)` **before Phase A begins**. The ceremony record captures this independently of the factory's internal check.
3. **[G-6] ▓▓ POINT OF NO RETURN ▓▓** — from the next step onward, the deletion state transition cannot be rolled back. Subsequent failures enter recovery or incident handling (§6), never deployment rollback. A non-SUBNET-ATTESTED verifier result after finalization is an incident requiring investigation; it cannot undo the deletion or the finalized receipt.
4. **Create + Phase A delete** → pending receipt exists.
5. **Helper run** (finalizer actor = operator via helper; the normative path): Phase B fetch → module-hash cert fetch → guard. Expect PASS, seconds-scale delta. `DELAY_EXCEEDED` → pause, investigate before proceeding. `FAIL` → incident (§6.4); the deletion stands, finalization waits. **Framing (Plan v2.1 A2/A3):** the helper flow is the **REFERENCE / administrative** finalisation surface; the enterprise-hosted endpoint model is the product path and out of ceremony scope.
6. **Finalize — FACTORY MODE** (`--factory`, the ruled exit criterion) → expect OK.
7. **Receipt retrieval:** export finalized receipt (JSON + raw); record receipt_id, both cert sizes, both `/time` values; both certificates present.

## 5. Verification close + records
1. **[G-8] Ceremony success requires ALL of:** verifier exit code zero · valid finalized receipt state · **V1 (internal consistency)** and **V2 (certified commitment)** pass · **ALL V3 (attested code identity, formerly V3-A)** cryptographic checks pass · **V4 (code provenance)** where provenance fixtures/records apply · classification `SUBNET-ATTESTED` · the receipt's certified Module Hash equals the minted profile's externally observed Module Hash (§4.2) · delay below `MAX_FINALIZATION_DELAY_NS`. Anything less → incident (§6.4), not success.
   - **Nomenclature mapping (shipped verifier predates the renumbering):** CVDR-Verify `v0.6.0`'s label "V3-A" denotes **V3** (attested code identity); its "[6/6]" live-state step is the **RETIRED** former live check — its result is recorded in the transcript, **not** a §5.1 criterion. "V3-A" and the live check must not appear as current nomenclature elsewhere in this runbook.
2. **[G-9] RELEASES update (final), distinguishing the two hashes:** the **profile canister Module Hash** is the subnet-attested V3 (attested code identity) code anchor carried by the receipt; the **factory Module Hash** is host/factory deployment provenance, not the receipt's code anchor. Include the zombie-core distinction: v0.4.0 in the canister build (per `mktd02-v0.5.0`'s pin) vs v0.4.1 in the helper/verifier line (constant-only addition; no wire/schema change). Plus go-live SHA, date, verification_level, signer. Normal CD → word flow.
3. **W6 handoff:** receipt (+ module-hash certificate) → `v4_finalized_mainnet.json`; `positive_subnet_attested_pass` un-ignored → 58/0/0.

## 6. Rollback, recovery, incidents
1. **Factory post-check mismatch / failed upgrade:** re-install the §0.4 known-good artifact (mode upgrade; PROFILE_MAP survives). Record the incident.
2. **[G-7] Mint cross-check failure:** registration cannot occur before the cross-check succeeds. On failure, verify BOTH that no registry entry exists AND that the newly created canister was successfully deleted. **A failed cleanup is an unregistered-orphan incident** — record and resolve before retry.
3. **[G-7] Pending-finalization recovery:** under the stated operator assumptions (retained identity, receipt identifiers, helper access, canister availability), a pending receipt remains **protocol-recoverable** by rerunning the helper or conclusively checking finalized state — still pending → the full flow repeats (idempotent); previously succeeded → `AlreadyFinalized` semantic condition or `null` + finalized state, both normatively "complete" (D2/D3). This is a conditional recovery property, not an unconditional liveness guarantee.
4. **Post-finalization incidents** (guard FAIL pre-finalize; any §5.1 criterion unmet post-finalize): investigate, record, report to G. The deletion and any finalized receipt stand.
5. **Frontend rollback:** redeploy the previous recorded asset archive.

## 7. Abort criteria (pre-Point-of-No-Return; any one → stop, record, report)
Unclassifiable or user-data profile · rollback artifact unmatchable (§0.4) · upgrade-compat check FAIL (§0.3) · pending receipt on an upgrade-target profile that cannot be finalized first · unexpected controller set · any pre/post module-hash mismatch · PROFILE_MAP anomaly · any need to reinstall.

## G return-for-ruling triggers (standing)
Previous factory artifact cannot be matched · incompatible stable-memory migration discovered · any existing profile cannot be positively classified.
