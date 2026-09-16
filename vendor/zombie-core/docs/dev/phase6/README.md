# Phase 6 original clean-room artefacts

The report `mktd02-v5-cleanroom-rederivation.md` and script `derive.py` are exact archived clean-room outputs, copied verbatim from Stef’s Downloads. `MANIFEST.txt` is the exact bundle manifest. `spec-deletions-verbatim.txt` and `spec-deletions.rec` preserve the bundle preparation deletion records.

Tarball SHA-256: `5dc6e2b2a356c0d780538adeba373514c527e99578fd87dc775c49c72a33468a`.

The tarball is not committed. `expected_3a3e01d.json` is comparison-side material and was not a clean-room input; it is not committed here.

These original outputs are archived without edits, including their original findings and execution paths. They supersede the reconstructed report/script in `../slice3_phase6_evidence/`, which remain historical implementation artefacts. Archiving these files does not run a new clean-room pass or provide a countersignature.

The original `derive.py` contains a trailing space on line 184. The adjacent `.gitattributes` disables only the end-of-line whitespace check for this file so the verbatim archive passes `git diff --check`; the original bytes are preserved.
