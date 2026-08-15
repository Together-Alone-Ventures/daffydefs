# DaffyDefs Demo Pack

This is the shortest path for an independent outsider to try DaffyDefs, obtain a real deletion receipt, and verify what that receipt establishes.

No TAV credentials are required.

## What this demonstrates

DaffyDefs is a worked example of ICP-Delete (Leaf): each user profile is held in its own Internet Computer canister.

When a profile is deleted, DaffyDefs can export a Cryptographically Verifiable Deletion Receipt (CVDR) as JSON.

The verification model is cumulative:

- **V1 — internal consistency:** the receipt's cryptographic relationships recompute correctly.
- **V2 — certified commitment:** the receipt commitment is backed by a valid Internet Computer certificate/delegation path.
- **V3 — attested code identity:** the receipt preserves subnet-certified evidence of the profile-canister module hash at finalisation time.
- **V4 — code provenance:** an independent rebuild of the disclosed profile-canister source produces the same module hash that V3 attests in the receipt.

The supplied reference verifier automates V1–V3. It deliberately reports V4 as **NOT EVALUATED**. V4 is performed by rebuilding and comparing the profile WASM.

V1 is not a claim that arbitrary receipt contents are "true"; it establishes internal cryptographic consistency. V2–V4 add progressively stronger external evidence.

## Scope

The receipt's code-identity/provenance claim is about the **profile canister identified by that receipt**.

It does not claim deletion of every copy that may exist outside that proved system boundary. Shared bulletin-board content, client caches, screenshots, exports, third-party copies and other independently retained copies are outside this narrow profile proof unless separately covered.

## 1. Try the live application and download your own CVDR

Open:

`https://5b3yq-gqaaa-aaaaj-qp4ta-cai.icp0.io/`

Use the application normally:

1. sign in with Internet Identity;
2. create/use a DaffyDefs profile;
3. initiate profile deletion;
4. allow the automatic finalisation flow to complete; there is no separate user finalisation action;
5. download the resulting CVDR JSON when it is offered.

Keep that downloaded JSON unchanged. The strongest demonstration uses **your own fresh receipt**, not a preselected sample.

If the browser is interrupted before finalisation completes, DaffyDefs can attempt lazy repair on a later authenticated visit. Recovery may retry the normal process; it does not manufacture missing evidence.

## 2. V1–V3 — quickest verification

For V1–V3 you need only:

- your downloaded CVDR JSON;
- the supplied Linux x86_64 reference verifier; and
- ordinary public Internet access.

You do **not** need the DaffyDefs source tree for V1–V3.

### Download the packaged reference verifier

For a clean Linux x86_64 walkthrough, download the accepted executable directly from the public repository at the pinned provenance anchor:

```bash
curl -fL \
  --retry 5 \
  --retry-delay 2 \
  -o mktd02-verify \
  https://raw.githubusercontent.com/Together-Alone-Ventures/daffydefs/14fb08c40f42419a4ca767982c8f797351025ff1/tools/cvdr-verify/bin/linux-x86_64/mktd02-verify

chmod +x mktd02-verify
```

If you already have the repository checked out, the same accepted executable is at:

`tools/cvdr-verify/bin/linux-x86_64/mktd02-verify`

Its SHA-256 is:

`c355fe7e92a2c7db1862fb7dfa55822efc53659739abac69648cc741db7b037f`

It reports version:

`mktd02-verify 0.6.1`

The executable is a convenience artifact, **not a trust anchor**. You may instead inspect/build its source or independently implement the published checks.

If you have the repository checked out, verify the packaged executable before use:

```bash
sha256sum tools/cvdr-verify/bin/linux-x86_64/mktd02-verify
tools/cvdr-verify/bin/linux-x86_64/mktd02-verify --version
```

Expected SHA-256:

```text
c355fe7e92a2c7db1862fb7dfa55822efc53659739abac69648cc741db7b037f
```

### Run it on the exact downloaded JSON

```bash
tools/cvdr-verify/bin/linux-x86_64/mktd02-verify \
  --receipt-file /path/to/your-downloaded-receipt.json
```

For a valid current DaffyDefs receipt, the important result shape is:

```text
V1: PASS
V2: PASS
V3 — attested code identity: SUBNET-ATTESTED
V4 — code provenance: NOT EVALUATED
```

The tool also reports live module corroboration and tombstone persistence as **INFO / non-gating** checks.

The process exit for the DaffyDefs receipt path is gated by V1, V2 and V3.

## 3. Compare the receipt with the published release identity

Open `RELEASES.md`.

The accepted DaffyDefs profile-WASM SHA-256 is:

`cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9`

Compare that value with the `module_hash` in your receipt.

A match shows that the receipt's V3-attested code identity matches the DaffyDefs release identity recorded by TAV.

This is useful corroboration, but it is **not yet V4**: the release record alone does not prove that the disclosed source builds to that hash.

## 4. Optional current-state corroboration from ICP

You may also independently read the profile canister's **current** module hash from the Internet Computer.

With `dfx` installed:

```bash
dfx canister info <PROFILE_CANISTER_ID_FROM_YOUR_RECEIPT> \
  --network ic \
  --identity anonymous
```

Look for:

```text
Module hash: 0x<64-hex-sha256>
```

For an unchanged current profile, this should match the receipt's `module_hash`.

This is only **current-state corroboration**. A later canister upgrade can legitimately make the live hash differ while the receipt's archival V3 evidence remains valid.

> **Tool note:** current `dfx` versions may print a deprecation warning recommending `icp-cli`. For this optional corroboration step, that warning is not itself a failure; use the returned `Module hash` result. The published procedure can migrate to `icp-cli` separately without changing the verification claim.

## 5. V4 — independently rebuild the profile WASM

V4 is the strongest code-provenance step.

For the accepted live release, the product/build provenance anchor is:

`14fb08c40f42419a4ca767982c8f797351025ff1`

The target is the final **post-`ic-wasm shrink` profile canister WASM**:

`wasm_out/profile_canister.wasm`

Do not substitute the factory hash, frontend hash, bulletin-board hash or verifier-binary hash.

### Obtain the exact public source

A robust non-developer path is the exact-commit public archive:

```bash
set -euo pipefail

ANCHOR=14fb08c40f42419a4ca767982c8f797351025ff1

curl -fL \
  --retry 5 \
  --retry-delay 2 \
  -o "daffydefs-${ANCHOR}.tar.gz" \
  "https://codeload.github.com/Together-Alone-Ventures/daffydefs/tar.gz/${ANCHOR}"

tar -xzf "daffydefs-${ANCHOR}.tar.gz"
cd "daffydefs-${ANCHOR}"
```

Using the exact archive avoids dependence on a user's local Git URL-rewrite configuration.

A normal Git checkout at the exact commit is also acceptable.

### Required build identity

The reproducibility path is pinned to:

- Rust `1.97.1`
- target `wasm32-unknown-unknown`
- `ic-wasm` `0.11.1`
- exact Rust dependency resolution/checksums in `Cargo.lock`
- exact TAV source snapshots recorded in `VENDORED_SOURCES.md`

The repository's `.cargo/config.toml` redirects the TAV Git package identities used by Cargo to the disclosed local source snapshots under `vendor/`.

Cargo may therefore display the original TAV Git URLs as **package identities** during the build. That does not mean the build secretly fetched those TAV sources from private repositories.

### Build

Run:

```bash
bash scripts/build-profile-repro.sh
```

Then:

```bash
sha256sum wasm_out/profile_canister.wasm
```

For the accepted release, the expected post-shrink result is:

```text
cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9  wasm_out/profile_canister.wasm
```

Now compare that hash with the `module_hash` V3 attests in **your own receipt**.

If they match, you have completed V4 for that receipt:

**public source/build materials → independently rebuilt profile WASM → SHA-256 → same module hash certified in the deletion receipt.**

## 6. Optional pinned-container reproduction

The repository also supplies a pinned Debian environment wrapper:

```bash
bash scripts/build-capsule-container.sh
```

It invokes the same canonical profile build recipe.

The current evidence includes multiple clean same-host reproductions and a pinned Debian tracked-files-only container reproduction with no TAV credentials.

No reproduction on physically distinct hardware is claimed.

## Accepted worked example

A fresh mainnet acceptance receipt is retained only as a worked example and test artifact:

- profile canister: `5ff4g-7qaaa-aaaaj-qsehq-cai`
- receipt ID: `050f152899a866cd16cf3b7b9f3d49f17ae6d58499ac27d3fb7793dabc0963e6`
- receipt file: `docs/acceptance/receipts/deletion-receipt-050f1528.json`
- receipt-file SHA-256: `add5a6c5f3a996fa6e24184823e74ea1ff1bef0949fb86dff91b1cf04d2bf3e2`
- V3-attested profile hash: `cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9`

For that exact receipt:

- V1: PASS
- V2: PASS
- V3: SUBNET-ATTESTED
- reference verifier exit: `0`
- live module corroboration: MATCH
- independent V4 rebuild: same `cb16ee...` hash

The normal demo should still use **your own newly generated receipt**.

## What to trust — and what not to

A successful V1–V4 exercise still has residual assumptions.

V2 and V3 rely on the public Internet Computer trust root and the IC subnet/NNS certificate model. The subnet certifies relevant state; it does not act as an oracle for copies outside the certified system boundary.

The DaffyDefs operator can later upgrade or stop application canisters. An already-finalised receipt preserves archival code-identity evidence for the deletion it records.

The supplied reference verifier is not a compliance certification or independent trust anchor.

For the detailed technical rules, see:

- `docs/VERIFICATION_PROCEDURE.md`
- `docs/RESIDUAL_TRUST_STATEMENT.md`
- `docs/REFERENCE_VERIFIER.md`
- `RELEASES.md`
- `VENDORED_SOURCES.md`
