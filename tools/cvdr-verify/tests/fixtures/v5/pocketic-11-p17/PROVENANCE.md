# PocketIC v5 P1.7 regression fixture

Classification: **implementation-derived regression fixture; not a corpus vector**.
This is a real v5 V2 regression fixture, not a fully valid v5 CVDR.
The first fully verifiable V1+V2+V3A v5 receipt remains the Slice-5 DaffyDefs
mainnet reference CVDR. Authority: Amendment 1 F-9 / phase-1 item 4.

## Capture

- Leaf repository: https://github.com/Together-Alone-Ventures/ICP-Delete-Leaf
- Exact commit: `2a10bf3ee056d3ff53327ca23654609a6f430c5e` (detached checkout).
- PocketIC client and server: **11.0.0**; server reports `pocket-ic-server 11.0.0`.
- Generator: `harness/tests/runtime.rs::p1_7_export_finalized_receipt_and_instance_root`.
- Capture run: 2026-09-15 UTC; one test passed, 14 filtered out.
- Topology: one NNS subnet plus one application subnet. The test explicitly
  creates the Leaf harness canister on the application subnet and asserts placement.
- Canister: `7tjcv-pp777-77776-qaaaa-cai`.
- Application subnet: `j3hn4-tfek2-2dzwi-2fiwt-yl43g-lljef-o5tyt-oi44t-pnvrw-tbquz-bae`.
- Receipt exported from the engine's stored `FinalizedCandidate` through
  `h_export_finalized_receipt_cbor` → `get_receipt` → `export::to_cbor_bytes`.
- Embedded BLS certificate came from the real PocketIC query certificate;
  the generator asserts byte equality with the certificate passed to finalization.
- `root.der` is unchanged `root_key()` from the SAME PocketIC instance.
  `root.pem` is its PUBLIC KEY base64 encoding, produced and round-trip checked by
  the pinned generator's `harness/export_root_pem.py`.
- The four generated artifacts were copied together without reconstruction or edits.
  `provenance.txt` retains the generator's original text, including its statement
  that cryptographic verification is deferred to CVDR-Verify.

## Reproduce

In a detached checkout of the exact Leaf commit, with Rust's wasm32 target installed:

```sh
cargo build --manifest-path harness/Cargo.toml --locked --offline --target wasm32-unknown-unknown --release
POCKET_IC_BIN=/tmp/pocket-ic-server-11.0.0/pocket-ic cargo test --manifest-path harness/Cargo.toml --locked --offline --test runtime p1_7_export_finalized_receipt_and_instance_root -- --exact --nocapture
```

Preserve all four files from `harness/target/slice4-fixture/` together. A fresh
instance can produce different keys and bytes; these hashes pin this capture.

## Verification contract

`tests/v5_pocketic_regression.rs` exercises production intake, V1, V2, V3A,
validity derivation, and the CLI with `--trust-root-pem root.pem`.
V2 must cryptographically validate the BLS signature and NNS delegation,
authorize the canister range, resolve the certified-data path, reject genesis,
and bind `certified_data == deletion_event_hash`.

The module-hash certificate is intentionally dummy `vec![0x4D;8]`.
**V3A: FAIL — fixture** is therefore expected, with the production named error
`v3a:module-hash-certificate` and a module-hash certificate CBOR parse failure.
V1 and V2 must PASS; overall validity must FAIL. The retained receipt id
`trust_root_key_id = "mainnet"` does not select the key: the captured PEM does,
and `trust_root_mismatch` must be a warning fact while V2 passes.
No manually authored expected verifier output is stored as authoritative data.

## SHA-256

| Captured artifact | SHA-256 |
|---|---|
| receipt.cbor | `91dbce51e0401856721eaa46cb8fa46ad4ecc8d2d098de89b2560fd4f259f741` |
| root.der | `e8a47c78b3a7075cc6f0e1e66f9f1b5ba3da8e470f07723eb8cd2b61c6e4bcf2` |
| root.pem | `d7110b5b34a37dad591caf572f131ec89539e1898283462696913325964a2c26` |
| provenance.txt | `7dbb6b5f892b150f76e9ea50b8f29b4df70171adf0e3246d0b0a02f7d1cafe5c` |

The integration test pins every file above and this CVDR-side note (whose hash
is kept outside itself to avoid a self-referential hash).
