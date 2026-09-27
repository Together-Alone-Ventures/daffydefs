# mktd02-v5.1 local end-to-end and mutation matrix

Development tooling for the DaffyDefs v5.1 line. Not part of the profile-WASM
provenance boundary.

- `local_e2e.py` runs create → upsert → delete → finalise (factory proxy, via
  `zd-finalize-helper --factory`) → export CVDR JSON → verify on a local replica.
  It asserts:
  - the DD2 record_id: 32 bytes and not the caller principal;
  - `resolve` is self-only for ordinary callers;
  - the pending receipt omits `module_hash`, `trust_root_key_id` and both certificates;
  - the finalized `module_hash` equals the certified module-hash leaf;
  - V1/V2/V3A PASS under the local root.
- `mutate_receipt.py` mutates each displayed field of a finalized receipt in
  turn. For each mutation it checks which gating checks fail and which keep passing.

Governing rulings: `docs/rulings/2026-09-25-mktd02-v5.1-amendment.md`
(zombie-core) and `docs/rulings/2026-09-27-dd2-non-identifying-record-id.md`.

## Run

Release profile WASMs come from `scripts/build-capsule-container.sh`. Copy its
`profile_canister.wasm` to `wasm_out/` and
`src/profile_factory/profile_canister_embedded.wasm`, then build and shrink the
factory and bulletin board into `wasm_out/`.

On WSL, PocketIC 13 refuses a state directory that does not exist yet. Start a
clean replica with:

```sh
rm -rf .dfx && mkdir -p .dfx/network/local/state/replicated_state
dfx start --background
dfx deploy profile_factory && dfx deploy bulletin_board
dfx ledger fabricate-cycles --canister profile_factory --t 50
(cd src/frontend && npm run build) && dfx deploy frontend
```

Then, with a dfx identity that has a plaintext PEM and no profile yet:

```sh
python3 tools/v51-e2e/local_e2e.py --identity <name> \
  --helper <path>/zd-finalize-helper \
  --expected-module-hash <profile WASM sha256> --out <dir>
python3 tools/v51-e2e/mutate_receipt.py \
  --receipt <dir>/receipt.json --root-pem <dir>/local_root.pem
```

`zd-finalize-helper` is built from ICP-Delete-Leaf `helper/` at the vendored
revision.
