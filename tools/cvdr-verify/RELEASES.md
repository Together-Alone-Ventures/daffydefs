# mktd02-verify — releases

Tags are minted once, at the final release commit, with `tag == crate version`. An entry here
without a tag is a release number reserved for the line, not a published tag.

## v0.8.0 — OpenChatZD suite v5 verifier (branch `openchatzd-v5`; UNTAGGED)

Crate version `0.8.0` (`Cargo.toml`, set at `2ddee83` as DRAFT; confirmed as the suite-v5 release
number at Step 10 of the open-chatZD retrofit, 2026-09-22). The premature `v0.7.0` tag at
`e884ac43` was deleted and is never reused.

Line: `560e483` (mktd02-v5) merged with the OpenChat line `ac64c1b` → `9eb9614`; suite-v5
OpenChat verifier `37411f58`; vector corpus mirror `8b0d835`. All work inside
`mktd02/mktd02-verify/`.

- **OpenChatZD package path (`--package`):** `PortablePackageV3` (R-6) and historical V2 /
  FrozenWire decoders; exact package-version ↔ body-tag dispatch (`RECEIPT_BODY_V2` live,
  `_V1` historical; mismatch = malformed, never a prefix match); `receipt_id` recompute (R-5);
  RevealWire v2 `record_id_v2` linkage (R-1); leaf == `receipt_hash`.
- **Trust root is a selector, never evidence:** `mainnet` → built-in NNS key;
  `non-production-test-root` only with `--allow-fixture-root-key` + `--fixture-root-key-hex`
  (announced in the verdict); unknown ids and conflicting `--trust-root-key-id` fail closed.
- **V3A — exactly three outcomes:** `V3A_PASS`, `V3A_PENDING_IN_PROTECTED_WINDOW`,
  `V3A_PERMANENTLY_UNAVAILABLE`; named failures `INDEX_ATTESTATION_INVALID`,
  `INDEX_HASH_MISMATCH`. Window check = the Index's C2 certified-time comparison
  (`uninstall_completed_at ≤ /time ≤ +24 h`). Pending / permanently-unavailable are
  as-of-verification-time classifications: the report prints the evaluation time and its source
  (`--now-ns` | system clock).
- **Validity** `PASS | INCOMPLETE | FAIL`, exit `0 | 4 | 1`; timing axis and window tier
  non-gating. Evidence-binding rule: (`index_canister_id`, certified `/time` within the receipt's
  window), not receipt identity.
- **Fixtures / corpus:** genuine PocketIC `PortablePackageV3` (`tests/fixtures/v5-openchatzd/pocketic-v3/`)
  through the CLI; byte-identical mirror of the open-chatZD suite-v5 vector corpus
  (`tests/fixtures/v5-openchatzd/corpus/`, source commit in its PROVENANCE) driven through the CLI.
- **CI:** `ci.sh` requires clean fmt and clippy for the whole crate (the accepted OpenChatZD
  baseline from `25c2945` is retired); 156 tests; audit clean.
- Pinned by open-chatZD `.github/workflows/backend.yaml` at `8b0d835` (resolves once the branch
  is pushed).

## v0.6.1 / v0.6.0 / v0.5.1 / v0.5.0 / cvdr-verify-v0.4.0

Tagged MKTd02 receipt-path releases; see the tags and `docs/dev/slice4_notes.md`.
