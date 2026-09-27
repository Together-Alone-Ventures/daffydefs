# Quick Verify v5 state matrix

These are receipt-wire fixtures, not new protocol vectors. They materialize
the existing countersigned zombie-core v5 inputs already exercised by
`tests/v5_corpus_acceptance.rs` at the verifier's pinned revision
`223723885cfbb548d6b218aee8500b073fda4b58`.

| Fixture | Existing source case | Preserved semantic |
| --- | --- | --- |
| `v1-invalid.json` | `nv5-009` in `verify_layer_negatives` | `receipt_id` is its exact presented all-`ff` mismatch; all other wire fields are the `gv5-007` receipt fixture. |
| `pending.json` | `gv5-008` in `receipt_fixtures_parse_and_pass_v1` | Neither finalization certificate is present, so the receipt remains `Pending`. |
| `incomplete.json` | `gv5-009` `bls_only` in `receipt_state_cases_through_intake` | Exactly one finalization certificate is present, so the receipt is `InvalidIncompleteFinalization`. |

`DELAY_EXCEEDED` deliberately has no receipt fixture: its existing exact case
is `src/v3_module.rs::v3a_tests::case10_delta_at_and_over_threshold`. A
standalone v5 receipt would need a new pair of valid signed certificates with
the required certified-time interval; this gate does not manufacture evidence.
