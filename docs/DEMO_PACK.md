# DaffyDefs Demo Pack

Create a profile, delete it once, let automatic finalisation finish, download your CVDR, and verify that exact JSON.

## 1. Obtain your own receipt

Open https://5b3yq-gqaaa-aaaaj-qp4ta-cai.icp0.io/ and sign in with Internet Identity. Create a profile, then delete it once. Wait for automatic finalisation; there is no extra user finalisation action. Download the CVDR when the finalized receipt is ready and keep the file unchanged.

The normal demonstration uses **your own fresh receipt**. The receipt certifies deletion-event evidence and attested profile code identity. It does not establish deletion of copies outside the application boundary, such as screenshots, exports or shared bulletin-board content.

Your receipt's `record_id` is 32 random bytes drawn when your profile was created. It is not your Internet Identity principal.

## 2. Verify the untouched JSON

On Linux x86_64, with `curl` and `sha256sum` installed, download the packaged reference verifier from the pinned implementation:

```bash
curl -fL --retry 5 --retry-delay 2 -o mktd02-verify \
  https://raw.githubusercontent.com/Together-Alone-Ventures/daffydefs/84617bac4b00c9ec65a914c30eda74e73415680d/tools/cvdr-verify/bin/linux-x86_64/mktd02-verify
printf '%s  %s\n' \
  6460032695b1f9b8f31d6a435fcf46ebe883a5f1c67013af1a2f3915663c9f6b \
  mktd02-verify | sha256sum --check
chmod +x mktd02-verify
./mktd02-verify --version
```

The version is `mktd02-verify 0.8.0` (no release tag). Authoritative verifier source: `67cbe4bf3878a1853a1839dfe96a76281ce3feea` (branch `v5.1`) in Together-Alone-Ventures/CVDR-Verify. The capsule includes its source under `tools/cvdr-verify/`; the executable is convenience software, **not a trust anchor**.

Replace the receipt path below with your downloaded file:

```bash
./mktd02-verify --receipt-file /path/to/your-downloaded-receipt.json --trust-root mainnet
```

Expect the following to pass:
- V1: internal cryptographic consistency. For `mktd02-v5.1` this uses the five-part `MKTD02_EVENT_V3` event hash, which does not include `module_hash`.
- V2: certified deletion-event evidence.
- V3A: attested code identity.
- Overall validity.

V3B is supplementary/non-gating build provenance and is not evaluated by this invocation. Output formatting is provisional; these are expected results, not a fixed transcript. V2 and V3A rely on the mainnet trust root and IC certificate model. The exact formulas are in the [verification procedure](VERIFICATION_PROCEDURE.md).

The accepted profile-WASM SHA-256 is:

```text
a196de1dcbe13b6d7d84470aaaa8be236935de5db8503418777bae1f7a1a01d9
```

This is also the current profile hash in [RELEASES.md](../RELEASES.md); the [canonical verification procedure](VERIFICATION_PROCEDURE.md) defines the technical checks. Compare it directly with `module_hash` in your receipt. Equality binds the receipt's attested code identity to this accepted profile build. No separate live-module lookup is needed for this walkthrough.

## 3. Optional V3B: rebuild the profile WASM

Only the final post-`ic-wasm shrink` **profile-canister WASM** is a byte-exact reproducibility target. Factory, frontend and verifier binaries are outside that claim.

Prerequisites: Rust `1.97.1`, target `wasm32-unknown-unknown`, `ic-wasm` `0.11.1`, `curl`, `tar`, and access to public crates.io dependencies. Run from a fresh directory:

```bash
ANCHOR=84617bac4b00c9ec65a914c30eda74e73415680d
curl -fL --retry 5 --retry-delay 2 -o "daffydefs-${ANCHOR}.tar.gz" \
  "https://codeload.github.com/Together-Alone-Ventures/daffydefs/tar.gz/${ANCHOR}"
tar -xzf "daffydefs-${ANCHOR}.tar.gz"
cd "daffydefs-${ANCHOR}"
bash scripts/build-profile-repro.sh
sha256sum wasm_out/profile_canister.wasm
```

Expected result:

```text
a196de1dcbe13b6d7d84470aaaa8be236935de5db8503418777bae1f7a1a01d9  wasm_out/profile_canister.wasm
```

With Docker, `bash scripts/build-capsule-container.sh` in a Git checkout of the anchor runs the same recipe in the pinned container, with Rust 1.97.1 and ic-wasm 0.11.1 installed inside it.

The committed lockfile pins public dependencies. The disclosed source snapshots and `.cargo/config.toml` supply:

- MKTd02 / Leaf: `8e5024dc8d27be19dafc579b2ac955e45da28b0c` (`vendor/mktd02/`).
- zombie-core: `8ac64df5d0110ec7ebbbe8382b7a826dda17085a` (`vendor/zombie-core/`).

Compare the rebuilt hash with the receipt's attested `module_hash`. This is supplementary build provenance, not an additional validity gate. Two clean runs of the canonical container recipe reproduced the accepted hash; no reproduction on physically distinct hardware is claimed.

## Accepted worked example — 27 Sep 2026

See the concise [ceremony evidence record](acceptance/ceremony-2026-09-27-v5.1.md).

The normal demo uses your own receipt. The repository also banks the exact untouched browser JSON from the accepted ceremony:

- Implementation: `84617bac4b00c9ec65a914c30eda74e73415680d`.
- Profile: `ju7jm-caaaa-aaaaj-qshsq-cai`.
- Receipt: `26c4721ce54ca65cd9940b371c9fcae040f96b23020bd3c00c994d85934bad12` (`mktd02-v5.1`).
- File: `docs/acceptance/receipts/deletion-receipt-26c4721c.json` (banked after the implementation anchor above).
- File SHA-256: `e845e49ab4bae2488ca7da5f78243d29bd085ac9242e838183a1a7c632897051`; size: 5560 bytes. The banked copy is byte-identical to the browser download.
- Canonical, deployed and receipt-attested profile hash: `a196de1dcbe13b6d7d84470aaaa8be236935de5db8503418777bae1f7a1a01d9`.

Both verifiers returned V1 PASS, V2 PASS, V3A PASS and overall validity PASS on the untouched receipt, using the mainnet trust root:
- the packaged verifier;
- a fresh source build at CVDR-Verify `170c958cca9342ca3937c06f97edc0912de11dec`.

V3B was not evaluated. V2 certificate delta: 1.297284767 s; V3A finalisation delay: 0.853233239 s (ROUTINE).

The 16 Sep 2026 receipt `90347766…` ([record](acceptance/ceremony-2026-09-16.md)) is a historical `mktd02-v5` receipt and is no longer the canonical example.

The operator can later upgrade application canisters. A saved finalized receipt preserves the archival evidence for its recorded deletion event; it is not a claim about every external copy or future application state.
