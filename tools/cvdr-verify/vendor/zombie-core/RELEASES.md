# zombie-core release notes

> Historical convention in this repo has been **annotated git tags** (e.g.
> `git tag -a zombie-core-v0.3.1`) rather than a checked-in changelog. This
> file is introduced at v0.4.0 to hold the release-notes **draft** ahead of
> tagging; the annotated tag message for `zombie-core-v0.4.0` should mirror the
> entry below. **No tag is created by this change** — Stef gates tagging.

## v0.4.1 — normative finalization-delay threshold

**DRAFT — not tagged.** Tag `zombie-core-v0.4.1` will carry crate version `0.4.1`
(`Cargo.toml:4`). Tag, crate version, these notes, and downstream pins must state
`0.4.1` identically — the v0.3.1-tag/0.3.0-crate mismatch is the standing lesson.

### Added
- `MAX_FINALIZATION_DELAY_NS` (normative, G ruling 15 Jul 2026). No wire/schema
  change. The threshold (3,600 s in ns) is interpreted authoritatively by
  CVDR-Verify; `delta > MAX_FINALIZATION_DELAY_NS` is a `DELAY_EXCEEDED`
  downgrade (not receipt rejection), `delta < 0` is an ordering failure. Placed
  in `protocol` module, re-exported at crate root.

### Unchanged
- No receipt-schema, serialized-wire, preimage, domain-tag, receipt-ID, or
  golden-vector change. v4 three-state semantics untouched. No dependency bumps.

## v0.4.0 — mktd02-v4 schema (subnet-attested code identity)

**Tag/crate/notes agreement (G ruling):** tag `zombie-core-v0.4.0` will carry
crate version `0.4.0` (`Cargo.toml`). Tag, crate version, these notes, and all
downstream pins must state `0.4.0` identically — the v0.3.1-tag/0.3.0-crate
mismatch is not repeated.

### Added
- `ProtocolVersion::V4` → `"mktd02-v4"`.
- `DeletionReceipt.module_hash_certificate: Option<Vec<u8>>` — raw certificate
  from a `read_state` over `/canister/<id>/module_hash`. Present only on v4
  receipts; `None` for v2/v3. Serialised with the same hex pattern as
  `bls_certificate`, `#[serde(default)]` on decode.
- `ReceiptState` enum + `DeletionReceipt::state()` — three-outcome
  classification (G ruling): `Pending` (neither certificate),
  `FinalizedCandidate` (both), `InvalidIncompleteFinalization` (exactly one).
- `ReceiptSummary.state` reflects the classification.

### Fixed (hazard)
- **Version-dispatched serialisation.** The receipt wire dispatch no longer
  uses `starts_with("mktd02-v3")` with a silent `else`-to-V2 fallback. An
  unrecognised `protocol_version` is now a **hard error** on both serialise and
  deserialise — it can no longer silently degrade to the legacy V2 wire shape
  (which dropped `record_id`, set `subnet_id = anonymous`, and renamed
  `deletion_seq → nonce`). `"mktd02-v4"` routes to the V4 wire; `"mktd02-v3"`
  output is **byte-identical** to v0.3.x (golden vector locked).

### Unchanged (no hash-preimage changes)
- `receipt_id` derivation — still `(canister_id, record_id, deletion_seq)`.
- `deletion_event_hash` and `certified_commitment` preimages.
- Golden vectors prove all three are identical whether certificates are present
  or absent.

### Compatibility
- Clean protocol break (no MKTd02/MKTd03 deployed): no migration, no dual-format
  support. Existing v2/v3 receipts still decode; v3 bytes are unchanged.

### Downstream pins to update (separately, when gated)
- `ICP-Delete-Leaf/mktd02` and `CVDR-Verify` pin `zombie-core` by git tag;
  bump them to `tag = "zombie-core-v0.4.0"` after the tag exists.
