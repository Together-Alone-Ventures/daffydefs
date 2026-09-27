# PocketIC end-to-end PortablePackageV3 (OpenChatZD suite-v5) — PROVENANCE

Source: open-chatZD `v5-retrofit` @ 5e85b4d30ca39464f421b284f4f27f6c350e05c2 (working tree of point E),
PocketIC test `cvdr_v2_upgrade_tests::stored_index_evidence_unblocks_upgrade_and_draft_finalises`
(pocket-ic 11.0.0 server). `package.json` is the EXACT byte body of `GET /cvdr/<receipt_id>` served by
the local_user_index named in the body (`index_canister_id`) after the draft finalised on the
upgraded Index; `root_key.hex` is the PocketIC NNS root key (DER, hex), supplied OUT
OF BAND because a V3 package carries no root material (fail closed on unknown keys).

package.json sha256 : 4d978e16b254bda37a3154ff5ff5b56c10a6acaa386147af92beced1d76d8e3f
receipt_body tag    : OPENCHATZD_RECEIPT_BODY_V2 (236 bytes)
trust_root_key_id   : non-production-test-root
index_module_hash   : 1494dc66d91f9108e6e0e0de09bb30776ca3c749389f311cab313b89ae1f8388
  (= sha256 of the all-canister-recipe `local_user_index.wasm.gz` at that source; see open-chatZD
   docs/dev/v5/BASELINE_c744de1.md §3.2 for the recipe)
certificates        : genuine PocketIC subnet signatures (commitment certificate over the receipt-tree
                      root; `/canister/<index>/module_hash` read_state certificate)

Expected: `mktd02-verify --package package.json --allow-fixture-root-key --fixture-root-key-hex $(cat root_key.hex)`
=> `validity: PASS`, V3A `V3A_PASS`, trust root announced NON-PRODUCTION (test verdict only).
Without the flag / root: `validity: FAIL (trust-root: …)`. Not a mainnet artefact; no cross-repo
byte anchor with the A1 fixture is expected.
