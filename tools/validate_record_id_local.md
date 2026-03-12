# record_id Local Validation Checklist

Run this after `tools/clean_build_deploy_local.sh` completes successfully.

1. Register a fresh local identity:
   `dfx identity new test-user --storage-mode plaintext`
   `dfx identity use test-user`
   Record your principal: `dfx identity get-principal` -> `CALLER_PRINCIPAL`

2. Call the factory to create a new profile canister for this identity.
   Note the spawned canister ID. This canister must have been created
   AFTER the factory reinstall in the deploy script.

3. Trigger a deletion via the frontend. Wait for the receipt screen to render.

4. Download the receipt JSON. Note the value of `record_id`.

5. Convert `CALLER_PRINCIPAL` to hex:
   `python3 tools/principal_to_hex.py <CALLER_PRINCIPAL>`
   (If `tools/principal_to_hex.py` does not exist, flag this — it needs to
   be created before validation can be completed.)

6. Confirm:
   `record_id` hex == hex encoding of `CALLER_PRINCIPAL` bytes

   PASS: `record_id` is a non-empty hex string matching the caller principal.
   FAIL — empty string: the WASM fix has not reached the running canister.
          Check: `sha256sum wasm_out/profile_canister.wasm` vs `module_hash` in receipt.
   FAIL — non-empty but wrong bytes: the caller identity at deletion time
          differs from `CALLER_PRINCIPAL`. Confirm which identity was active
          when the deletion was triggered.
