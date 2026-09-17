# DaffyDefs Demo Pack

Create a profile, delete it once, let automatic finalisation finish, download your CVDR, and verify that exact JSON.

**Distribution gate pending (17 Sep 2026):** the unauthenticated GitHub verifier and source-archive URLs below returned HTTP 404 during the freeze check. The pinned artifacts exist in the repository and pass local checks, but the no-credentials outsider walkthrough cannot be completed until public access is available.

## 1. Obtain your own receipt

Open https://5b3yq-gqaaa-aaaaj-qp4ta-cai.icp0.io/ and sign in with Internet Identity. Create a profile, then delete it once. Wait for automatic finalisation; there is no extra user finalisation action. Download the CVDR when the finalized receipt is ready and keep the file unchanged.

The normal demonstration uses **your own fresh receipt**. The receipt certifies deletion-event evidence and attested profile code identity. It does not establish deletion of copies outside the application boundary, such as screenshots, exports or shared bulletin-board content.

## 2. Verify the untouched JSON

On Linux x86_64, with `curl` and `sha256sum` installed, download the packaged reference verifier from the pinned capsule implementation:

```bash
curl -fL --retry 5 --retry-delay 2 -o mktd02-verify \
  https://raw.githubusercontent.com/Together-Alone-Ventures/daffydefs/e2b073971aae5f1c97edee59875bec15628821c7/tools/cvdr-verify/bin/linux-x86_64/mktd02-verify
printf '%s  %s\n' \
  b47e442b0f76331a14ff09bc70bd9f50682a635ebf2dfda90f15e4ed6b322a2c \
  mktd02-verify | sha256sum --check
chmod +x mktd02-verify
./mktd02-verify --version
```

The version is `mktd02-verify 0.8.0` (0.8.0 DRAFT, no release tag). Authoritative verifier source: `560e483b047209ee83463dfab29da07acb422feb` in Together-Alone-Ventures/CVDR-Verify. The capsule includes its source under `tools/cvdr-verify/`; the executable is convenience software, **not a trust anchor**.

Replace the receipt path below with your downloaded file:

```bash
./mktd02-verify --receipt-file /path/to/your-downloaded-receipt.json --trust-root mainnet
```

Expect V1 (internal cryptographic consistency), V2 (certified deletion-event evidence), V3A (attested code identity), and overall validity to pass. V3B is supplementary/non-gating build provenance and is not evaluated by this invocation. Output formatting is provisional; these are expected results, not a fixed transcript. V2 and V3A rely on the mainnet trust root and IC certificate model.

The accepted profile-WASM SHA-256 is:

```text
30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb
```

This is also the current profile hash in [RELEASES.md](../RELEASES.md); the [canonical verification procedure](VERIFICATION_PROCEDURE.md) defines the technical checks. Compare it directly with `module_hash` in your receipt. Equality binds the receipt's attested code identity to this accepted profile build. No separate live-module lookup is needed for this walkthrough.

## 3. Optional V3B: rebuild the profile WASM

Only the final post-`ic-wasm shrink` **profile-canister WASM** is a byte-exact reproducibility target. Factory, frontend and verifier binaries are outside that claim.

Prerequisites: Rust `1.97.1`, target `wasm32-unknown-unknown`, `ic-wasm` `0.11.1`, `curl`, `tar`, and access to public crates.io dependencies. Run from a fresh directory:

```bash
ANCHOR=e2b073971aae5f1c97edee59875bec15628821c7
curl -fL --retry 5 --retry-delay 2 -o "daffydefs-${ANCHOR}.tar.gz" \
  "https://codeload.github.com/Together-Alone-Ventures/daffydefs/tar.gz/${ANCHOR}"
tar -xzf "daffydefs-${ANCHOR}.tar.gz"
cd "daffydefs-${ANCHOR}"
bash scripts/build-profile-repro.sh
sha256sum wasm_out/profile_canister.wasm
```

Expected result:

```text
30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb  wasm_out/profile_canister.wasm
```

The committed lockfile pins public dependencies. The disclosed source snapshots and `.cargo/config.toml` supply:

- MKTd02 / Leaf: `2a10bf3ee056d3ff53327ca23654609a6f430c5e` (`vendor/mktd02/`).
- zombie-core: `223723885cfbb548d6b218aee8500b073fda4b58` (`vendor/zombie-core/`).

Compare the rebuilt hash with the receipt's attested `module_hash`. This is supplementary build provenance, not an additional validity gate. The canonical recipe reproduced the accepted hash during the capsule freeze; no reproduction on physically distinct hardware is claimed.

## Accepted worked example — 16 Sep 2026

See the concise [ceremony evidence record](acceptance/ceremony-2026-09-16.md).

The normal demo uses your own receipt. The repository also banks the exact untouched browser JSON from the accepted ceremony:

- Implementation: `e2b073971aae5f1c97edee59875bec15628821c7`.
- Profile: `petd6-ciaaa-aaaaj-qshha-cai`.
- Receipt: `90347766510e664818831810d7c53091936192dae63db48bb194b96e00006149`.
- File: `docs/acceptance/receipts/deletion-receipt-90347766.json` in the frozen repository (banked after the implementation anchor above).
- File SHA-256: `1a12152b8869814ddd80ef11234864211fa7f5119e0b7eebf4e9e46d8a6b62d1`; size: 5704 bytes. The banked copy is byte-identical to the browser download.
- Canonical, deployed and receipt-attested profile hash: `30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb`.

Both the packaged verifier and the ceremony's fresh source-built verifier at `560e483b047209ee83463dfab29da07acb422feb` returned V1 PASS, V2 PASS, V3A PASS and overall validity PASS on the untouched receipt, using the mainnet trust root. V3B was not evaluated. V2 certificate delta: 1.257879103 s; V3A finalisation delay: 1.281779666 s (ROUTINE).

The operator can later upgrade application canisters. A saved finalized receipt preserves the archival evidence for its recorded deletion event; it is not a claim about every external copy or future application state.
