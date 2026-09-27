# OpenChatZD suite-v5 vector corpus — mirror

Byte-identical mirror of open-chatZD `docs/test-vectors/openchatzd-v5/` (branch `v5-retrofit`,
Brief B1 §2 step 6 / plan Step 9). The vectors are **generated** there from the live canister
formulas and wire encoders by `local_user_index_canister_impl::model::cvdr_vectors` and
hash-gated in both repositories:

- open-chatZD: `corpus_matches_committed_files_byte_for_byte` regenerates every file and compares
  it to the committed bytes; `corpus_mirror_in_cvdr_verify_is_byte_identical` compares this mirror
  to the source when a sibling CVDR-Verify checkout is present.
- CVDR-Verify: `tests/openchatzd_v5_corpus.rs` hash-checks every file against `manifest.json`
  before use and drives the vectors through the real CLI.

Source: open-chatZD `v5-retrofit` commit `f314663c5945b699cee50250514a5a1e4dce935d` (Step 9), directory
`docs/test-vectors/openchatzd-v5/`; `manifest.json` (its `files` map is the pin) is compared byte
for byte with the source by the open-chatZD mirror guard.

Not a countersigned corpus vector (unlike the mktd02-v5 corpus read from zombie-core): these are
implementation-derived, formula-pinning vectors; a diff is a formula or encoding change that must
be ruled, never absorbed. Refresh by copying the source directory verbatim.
