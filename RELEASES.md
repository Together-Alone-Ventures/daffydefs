# DaffyDefs — Current Release

The DaffyDefs v5.1 release (`mktd02-v5.1`) was accepted on mainnet on 27 September 2026. It implements:
- the MKTd02 v5.1 protocol correction (`vendor/zombie-core/docs/rulings/2026-09-25-mktd02-v5.1-amendment.md`);
- the DD2 non-identifying record_id (`docs/rulings/2026-09-27-dd2-non-identifying-record-id.md`).

| Release identity | Value |
|---|---|
| Live application | https://5b3yq-gqaaa-aaaaj-qp4ta-cai.icp0.io/ |
| Implementation anchor | `84617bac4b00c9ec65a914c30eda74e73415680d` (branch `v5.1`) |
| Protocol version | `mktd02-v5.1` |
| Profile-canister WASM SHA-256 | `a196de1dcbe13b6d7d84470aaaa8be236935de5db8503418777bae1f7a1a01d9` |
| Factory canister | `5g26e-liaaa-aaaaj-qp4tq-cai` |
| Factory deployed module hash | `7eaa25e334c51f8cfba041ae8708147743d4f20b06d966ae2824ee4373f6a461` |
| Frontend canister | `5b3yq-gqaaa-aaaaj-qp4ta-cai` |
| Frontend canister module hash | `04e565b3425fe7510ee16b02adcfe3f01abc9a2725c82a21cb08969241debd62` |
| Accepted profile | `ju7jm-caaaa-aaaaj-qshsq-cai` |
| Accepted receipt (canonical) | `26c4721ce54ca65cd9940b371c9fcae040f96b23020bd3c00c994d85934bad12` |
| Receipt file | [Exact browser JSON](docs/acceptance/receipts/deletion-receipt-26c4721c.json) |
| Receipt SHA-256 | `e845e49ab4bae2488ca7da5f78243d29bd085ac9242e838183a1a7c632897051` |
| Receipt size | 5560 bytes |
| Ceremony evidence | [27 September 2026](docs/acceptance/ceremony-2026-09-27-v5.1.md) |
| Authoritative CVDR-Verify source | `67cbe4bf3878a1853a1839dfe96a76281ce3feea` (branch `v5.1`; packaged copy); fresh-build check at `170c958cca9342ca3937c06f97edc0912de11dec` |
| Packaged verifier SHA-256 | `6460032695b1f9b8f31d6a435fcf46ebe883a5f1c67013af1a2f3915663c9f6b` |
| MKTd02 / Leaf source | `8e5024dc8d27be19dafc579b2ac955e45da28b0c` |
| zombie-core source | `8ac64df5d0110ec7ebbbe8382b7a826dda17085a` |
| Toolchain | Rust 1.97.1; `wasm32-unknown-unknown`; `ic-wasm` 0.11.1 (pinned container) |

## Verification and build provenance

Both the packaged verifier and a fresh build of CVDR-Verify `170c958` returned the same results on the untouched browser receipt, with `--trust-root mainnet`:
- V1 PASS, V2 PASS, V3A PASS and overall validity PASS;
- process exit 0, with byte-identical `--json` outputs.

V3B was not evaluated in those invocations and remains supplementary/non-gating build provenance. A field-by-field mutation matrix over the receipt showed 0 deviations. See the [ceremony record](docs/acceptance/ceremony-2026-09-27-v5.1.md).

Two clean builds of the canonical capsule container produced the profile-WASM hash above. That hash equals the deployed profile module hash and the receipt-attested `module_hash`. To repeat the V3B comparison from the disclosed release source (Docker required):

```bash
bash scripts/build-capsule-container.sh
sha256sum releases/CANDIDATE/container-output-$(git rev-parse HEAD)/profile_canister.wasm
```

`scripts/build-profile-repro.sh` performs the same build outside the container. It requires a local Rust 1.97.1 and `ic-wasm` 0.11.1.

Compare the result with this record's profile hash and your receipt's `module_hash`. The [verification procedure](docs/VERIFICATION_PROCEDURE.md) defines the checks. Source pins are disclosed in [VENDORED_SOURCES.md](VENDORED_SOURCES.md) and dependencies in the committed lockfile.

The byte-exact reproducibility claim applies only to the final post-shrink profile-canister WASM. The verifier binary, frontend and factory are not reproducibility targets. No reproduction on physically distinct hardware is claimed.

## Historical line

The 16 September 2026 receipt `90347766510e664818831810d7c53091936192dae63db48bb194b96e00006149` ([record](docs/acceptance/ceremony-2026-09-16.md)) is a historical `mktd02-v5` receipt. It remains verifiable under the frozen six-part `MKTD02_EVENT_V2` construction. It is no longer the canonical demonstration receipt. That release was built from implementation anchor `e2b073971aae5f1c97edee59875bec15628821c7` with profile WASM `30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb`, and was verified by CVDR-Verify `560e483b047209ee83463dfab29da07acb422feb` (packaged verifier `b47e442b0f76331a14ff09bc70bd9f50682a635ebf2dfda90f15e4ed6b322a2c`). Earlier release records remain available in Git history and dated acceptance evidence.
