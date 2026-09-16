# Test fixtures (MKTd02 receipt path)

Every fixture here carries a provenance note. None is a corpus vector: the
countersigned mktd02-v5 corpus is read from the pinned zombie-core checkout by
`tests/v5_corpus_acceptance.rs` and is never copied into this crate.

| Path | What it is | Used for | Provenance |
|---|---|---|---|
| `v4/v4_finalized_mainnet.json` | DaffyDefs v4 reference CVDR: a genuine mainnet `mktd02-v4` receipt with a real bls certificate and a real module-hash certificate | Historical V1/V2/V3A: must verify `validity: PASS`, `protocol_line: mktd02-v4 (historical)` under `--trust-root mainnet` (`tests/historical_v4_reference.rs`, `tests/cli_trust_root.rs`, `src/v3_module.rs`) | `v4/PROVENANCE.md` §2; sha256 pinned there and asserted by the test |
| `v4/v4_module_hash_cert.json` | Real mainnet `read_state` certificate over `/canister/5g26e…/module_hash` | V3A certificate cases 1 and 3 (`src/v3_module.rs`) | `v4/PROVENANCE.md` §1 |
| `v5/pocketic-11-p17/` | PocketIC 11.0.0 mktd02-v5 finalized receipt with a real delegated BLS certificate and same-instance PocketIC root | Real v5 V1/V2 regression: V1 PASS, V2 PASS under the captured PEM; V3A deliberately FAIL because the module-hash certificate is the dummy fixture | `v5/pocketic-11-p17/PROVENANCE.md`; captured artefact hashes pinned there and asserted by `tests/v5_pocketic_regression.rs` |

## PocketIC v5 finalized receipt

The real PocketIC v5 V2 regression fixture is now stored under
`v5/pocketic-11-p17/`. It is implementation-derived regression evidence,
not a corpus vector. The production verifier establishes V1 PASS and V2
PASS using the captured PocketIC root PEM. V3A deliberately fails with
`v3a:module-hash-certificate` because the captured module-hash certificate
remains the known dummy fixture.

The earlier v5-shaped unit tests remain useful boundary tests, and the
countersigned corpus remains the authoritative parse/V1 corpus; neither
substitutes for this real PocketIC V2 fixture.

The first fully verifiable mainnet v5 receipt is DaffyDefs' reference CVDR,
produced later and verified by this verifier.
