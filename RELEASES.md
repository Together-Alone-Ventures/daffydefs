# DaffyDefs — Current Release

The DaffyDefs v5 release was accepted on mainnet on 16 September 2026.

| Release identity | Value |
|---|---|
| Live application | https://5b3yq-gqaaa-aaaaj-qp4ta-cai.icp0.io/ |
| Ceremony implementation anchor | `e2b073971aae5f1c97edee59875bec15628821c7` |
| Profile-canister WASM SHA-256 | `30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb` |
| Factory canister | `5g26e-liaaa-aaaaj-qp4tq-cai` |
| Factory deployed module hash | `b476a41de6c36556262282f9e93aa9e35e2957b5cd2a953dddf32651f9fc001e` |
| Frontend canister | `5b3yq-gqaaa-aaaaj-qp4ta-cai` |
| Frontend canister module hash | `2c24b5e1584890a7965011d5d1d827aca68c489c9a6308475730420fa53372e8` |
| Accepted profile | `petd6-ciaaa-aaaaj-qshha-cai` |
| Accepted receipt | `90347766510e664818831810d7c53091936192dae63db48bb194b96e00006149` |
| Receipt file | [Exact browser JSON](docs/acceptance/receipts/deletion-receipt-90347766.json) |
| Receipt SHA-256 | `1a12152b8869814ddd80ef11234864211fa7f5119e0b7eebf4e9e46d8a6b62d1` |
| Receipt size | 5704 bytes |
| Ceremony evidence | [16 September 2026](docs/acceptance/ceremony-2026-09-16.md) |
| Authoritative CVDR-Verify source | `560e483b047209ee83463dfab29da07acb422feb` — 0.8.0 DRAFT, no release tag |
| Packaged verifier SHA-256 | `b47e442b0f76331a14ff09bc70bd9f50682a635ebf2dfda90f15e4ed6b322a2c` |
| MKTd02 / Leaf source | `2a10bf3ee056d3ff53327ca23654609a6f430c5e` |
| zombie-core source | `223723885cfbb548d6b218aee8500b073fda4b58` |
| Toolchain | Rust 1.97.1; `wasm32-unknown-unknown`; `ic-wasm` 0.11.1 |

## Verification and build provenance

Both the packaged and fresh source-built verifier returned V1 PASS, V2 PASS, V3A PASS and overall validity PASS on the untouched browser receipt, with `--trust-root mainnet`. V3B was not evaluated in those invocations and remains supplementary/non-gating build provenance.

The canonical build reproduced the profile-WASM hash above, which equals the deployed and receipt-attested profile hash. To repeat the V3B comparison from the disclosed release source:

```bash
bash scripts/build-profile-repro.sh
sha256sum wasm_out/profile_canister.wasm
```

Compare the result with this record's profile hash and your receipt's `module_hash`. The [verification procedure](docs/VERIFICATION_PROCEDURE.md) defines the checks. Source pins are disclosed in [VENDORED_SOURCES.md](VENDORED_SOURCES.md) and dependencies in the committed lockfile.

The byte-exact reproducibility claim applies only to the final post-shrink profile-canister WASM. The verifier binary, frontend and factory are not reproducibility targets. No reproduction on physically distinct hardware is claimed.

The ceremony implementation anchor identifies the deployed ceremony code. Later documentation and frontend presentation changes do not imply another deployment. Earlier release records remain available in Git history and dated acceptance evidence.
