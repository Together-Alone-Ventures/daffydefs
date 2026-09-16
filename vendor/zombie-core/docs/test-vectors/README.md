# MKTd02-v5 test-vector corpus

A Cryptographically Verifiable Deletion Receipt (CVDR) carries hashes and certificates that permit verification without exposing deleted plaintext. This corpus covers the ratified MKTd02-v5 hash constructions, receipt states, exact receipt encoding, named failures, and historical compatibility controls.

The derivation authority is `docs/spec/mktd02-v5-serialization.md`. The standard-library Python harness derives twelve positive v5 outputs from their inputs and derives thirteen negative/compatibility outcomes from malformed or candidate inputs plus the ratified normative rules. Negative inputs do not carry their expected answers. The harness also rederives three historical hash references where the published historical formula supports doing so. It does not derive the frozen v3 wire reference because the v5 serialization text deliberately does not redefine that historical encoder.

`tests/v5_corpus.rs` is a separate Rust implementation cross-check. It substantively loads every negative JSON vector as well as the positive and historical fixtures, and compares the library's digests, v5 CBOR byte strings, compact JSON, errors, state classifications, and frozen historical behavior with their JSON expectations. It is not the source of expected v5 values.

The `v4-historical/` directory contains the retired certified-commitment construction and tag, the active EVENT_V1 construction used only for issued v2-v4 receipts, and the frozen v3 CBOR/JSON reference. The hash values are rederived only where the historical formula supports it. The v3 wire reference was copied and compared byte-for-byte with the frozen pre-Slice-3 golden at `ac5c32d:src/receipt.rs`; it is an implementation-regression reference, not spec-derived. None is a v5 construction.

Expected v5 values were populated by the harness's guarded generation mode and now pass its read-only check mode. Phase 6 independently rederived the derivable corpus: 47/47 compared values matched with 0 mismatches; the copied historical `v4h-v3-wire` artefact was excluded by design. The corpus remains pending human countersignature.

The zombie-core checks for `gv5-002` and `gv5-011` validate the relevant formulas and primitives against supplied inputs only. They do not establish Leaf engine conformity. Under ruling D-2, Phase 9 must load both vectors in Leaf and perform the engine-to-JSON checks. `gv5-011` deliberately uses a synthetic fixed corpus schema; it is not a product-specific Leaf state schema.
