> Superseded, non-original: this reconstructed implementation summary is retained for history. See [the exact original report](../phase6/mktd02-v5-cleanroom-rederivation.md).

# MKTd02-v5 clean-room rederivation record

Date: 13 Sep 2026

Input isolation was the bundle identified by `MANIFEST.txt`; the received tarball had SHA-256 `5dc6e2b2a356c0d780538adeba373514c527e99578fd87dc775c49c72a33468a`. It contained the ratified serialization text with the recorded code/result-only deletions and input-only corpus JSON. It did not contain repository code, Rust tests, expected values, implementer notes, or the in-tree Python harness.

Result: **47/47 compared values matched; 0 mismatches**. There were zero underivable values among the derivable corpus. `v4h-v3-wire` was excluded by design because it is a copied frozen historical implementation-regression artefact rather than a spec-derived value.

Documentary findings returned to Phase 1c:

- G-1: `nv5-009` / `nv5-010` had no named V1 rejections in §7.
- G-2: `nv5-007` / `nv5-008` case 1 relied on message fragments not frozen by §7.
- G-3: `gv5-012` did not define the principal textual-form/raw-byte relation.
- G-4: `v4h-v3-wire` is underivable by design and must remain excluded; no v3 encoder is to be invented.

The layer vocabulary was a documentary corpus convention, not a G-item. Phase 1c closes G-1/G-2/G-3 and records G-4 without changing a protocol construction.

The isolated comparison-side expected values are deliberately not checked into this evidence directory. In particular, `expected_3a3e01d.json` is not clean-room input or evidence.
