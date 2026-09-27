# MKTd02 v5.1 conformance matrix

**Authority:** [`docs/rulings/2026-09-25-mktd02-v5.1-amendment.md`](../rulings/2026-09-25-mktd02-v5.1-amendment.md) §§4, 6–11, and 14–22, Stef-ratified 25 Sep 2026. This is a planning and traceability matrix: it creates no implementation behaviour and does not alter frozen `mktd02-v5` receipts.

| ID | Governing amendment section | Owning repo/module | Intended test file | Status |
|---|---|---|---|---|
| V51-EVENT-01 | EVENT_V3 formula | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-EVENT-02 | EVENT_V3 excludes module_hash | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-EVENT-03 | EVENT_V3 binds receipt_id | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-VERSION-01 | version/tag registry | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-VERSION-02 | exact version matching | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-PENDING-01 | v5.1 pending structure | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-PENDING-02 | v5.1 pending structure/SR-11 | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-PENDING-03 | v5.1 pending structure | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-FINAL-01 | v5.1 finalisation set | ICP-Delete-Leaf / finalization | `mktd02/src/finalization.rs` tests | NEEDS IMPLEMENTATION |
| V51-FINAL-02 | fail-closed partial finalisation | zombie-core / receipt | `src/receipt.rs` tests | NEEDS IMPLEMENTATION |
| V51-PR7-01 | PR-7 exact leaf extraction | ICP-Delete-Leaf / finalization | `mktd02/src/finalization.rs` tests | NEEDS IMPLEMENTATION |
| V51-PR7-02 | PR-7 path failure | ICP-Delete-Leaf / finalization | `mktd02/src/finalization.rs` tests | NEEDS IMPLEMENTATION |
| V51-PR7-03 | PR-7 shape/length failure | ICP-Delete-Leaf / finalization | `mktd02/src/finalization.rs` tests | NEEDS IMPLEMENTATION |
| V51-SR11-01 | SR-11 core-owned stamp | ICP-Delete-Leaf / finalization | `mktd02/src/finalization.rs` tests | NEEDS IMPLEMENTATION |
| V51-SR11-02 | SR-11 client cannot select key | ICP-Delete-Leaf / host contract | `mktd02/src/finalization.rs` tests | NEEDS IMPLEMENTATION |
| V51-ROOT-01 | verifier root/label separation | CVDR-Verify / mktd02-verify | verifier JSON tests | NEEDS IMPLEMENTATION |
| V51-LOCK-01 | finalisation-window lock | ICP-Delete-Leaf / lifecycle | `harness/tests/runtime.rs` | EXISTS (v5) — EXTEND TO v5.1: add a v5.1 lifecycle fixture to `upgrade_during_pending_window_traps` |
| V51-VALIDITY-01 | V1 AND V2 AND V3A | CVDR-Verify / mktd02-verify | verifier JSON tests | EXISTS (v5) — EXTEND TO v5.1: add a finalized v5.1 receipt JSON fixture through the verifier `verify_receipt` V1/V2/V3A path |
| V51-DELAY-01 | DELAY_EXCEEDED non-gating | CVDR-Verify / mktd02-verify | `src/v3_module.rs` tests | NEEDS IMPLEMENTATION |
| V51-HIST-01 | historical freeze | zombie-core / corpus | `tests/v5_corpus.rs` (must continue to pass unchanged after v5.1 lands) | EXISTS |
| V51-MUTATE-01 | pre-ceremony mutation matrix | zombie-core / corpus | `docs/test-vectors/v5.1/` matrix harness | NEEDS IMPLEMENTATION |

`V51-MUTATE-01` requires a canonical v5.1 receipt field-mutation matrix before ceremony. For every displayed field it must record expected failing checks and expected still-passing checks; it is not a substitute for the named conformance tests above.

## Required release gates for v5.1

1. Changed formulas are written fresh from governing authority, with additions **and** removals explicitly listed.
2. The normative formula is compared with the governing amendment and White Paper.
3. The public verification procedure prints the formula.
4. Vectors are independently rederived from the amendment/White Paper. The independent v5.1 vector rederiver must not be the same agent that authored the normative v5.1 specification (CC is the intended rederiver; CD authored the specification).
5. Corpus countersignature checks amendment/White Paper ↔ normative spec ↔ independent vectors.
6. Every ratified implementation rule maps to a named test or an explicit documented reason it cannot.
7. The canonical receipt field-mutation matrix passes before ceremony.
8. Superseded reference material is marked historical.
9. Implementation claims are source-checked.
10. Ratified rulings governing an implementation are committed in the implementing repository and cited by path from its normative specification.

A lower-level ruling that appears to contradict the governing amendment or White Paper is a **CONFLICT TO ESCALATE**, not an omission to silently repair.

## DaffyDefs record_id boundary

The already-ratified requirement is that DaffyDefs must not expose the raw Internet Identity principal, or a straightforward deterministic/reversible derivative of it, as public `record_id`. Generic MKTd02 does not adopt an OpenChatZD-specific derivation here. The DaffyDefs host-specific derivation is deferred to a separate DD2 ruling and implementation slice.
