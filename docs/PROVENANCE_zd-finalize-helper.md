# Provenance record — `zd-finalize-helper`

**Status:** RECOMPUTED, 17 Jul 2026. Substitution pending G acknowledgment.
**Authority:** G Gate-2 A4 ruling (16 Jul 2026) + W3/W4 addendum conditions (16 Jul 2026).

## What this record is

The original landing record for `zd-finalize-helper` (14 Jul 2026) — full hashes plus
the itemised three-file delta — is **LOST**. Only three truncated prefixes survive in
the ruling record:

| Anchor | Surviving prefix |
|---|---|
| Source tree | `b3e4df…` |
| Landed tree | `e4142244…` |
| Retired tarball | `e9c901…` |

This record is a **recomputation**, not a recovery. Per G's binding condition,
recomputation does not restore the lost record: surviving prefixes are preserved below
as **historical cited values**, and every newly computed value is recorded with its
date, exact command, and exact input tree. Where a cited value cannot be reproduced,
this record says so and does not substitute a recomputed value for it.

Nothing here is inferred, back-filled, or presented as the original.

---

## 1. Tarball — `zd-finalize-helper.tar.gz` (RETIRED anchor)

| Field | Value |
|---|---|
| Cited prefix | `e9c901…` |
| Recomputed (17 Jul 2026) | `e9c9013c94e7c56813d48caa64e29ed2960475649d202874bea8c4a1a56cfd7d` |
| Prefix match | **MATCH** |
| Command | `sha256sum ~/projects/zd-finalize-helper.tar.gz` |
| Input | `~/projects/zd-finalize-helper.tar.gz` (27,221 bytes, mtime 14 Jul 2026 10:43) |

The tarball digest reproduces its cited prefix exactly. **It is nevertheless RETIRED as
a provenance anchor** (ruled unverifiable, G): a tarball digest proves nothing about
tree contents to a third party who does not hold the published tarball. It is recorded
here for completeness of the historical chain, not as a verification input.

The tarball is retained read-only and its contents are byte-identical to the standalone
source tree (verified: `diff -rq` clean across all five source files), which is what
makes §2 reproducible from two independent inputs.

---

## 2. Source tree — VERIFIED

| Field | Value |
|---|---|
| Cited prefix | `b3e4df…` |
| Recomputed (17 Jul 2026) | `b3e4df6febad6c99eb0494cafcd9d8aed3967c91f30ffc00802339a588864b9e` |
| Prefix match | **MATCH** |
| Digest method | sha256 over a sorted path+digest manifest (**not** a git tree hash — see below) |

### Method (verbatim — reproduces the cited prefix)

Run with the working directory set to the tree root. The digest covers the **five
source files only**:

```sh
cd ~/projects/zd-finalize-helper
find . -type f \
  \( -name '*.rs' -o -name '*.toml' -o -name '*.lock' -o -name '*.md' -o -name '*.py' \) \
  -not -path './target/*' \
| sort | xargs sha256sum | sha256sum
# => b3e4df6febad6c99eb0494cafcd9d8aed3967c91f30ffc00802339a588864b9e
```

Equivalently, from the retired tarball (independent input, same result):

```sh
tar xzf ~/projects/zd-finalize-helper.tar.gz -C <tmp>
cd <tmp>/zd-finalize-helper && find . -type f | sort | xargs sha256sum | sha256sum
# => b3e4df6febad6c99eb0494cafcd9d8aed3967c91f30ffc00802339a588864b9e
```

**The method is load-bearing and must be reproduced exactly.** The manifest lines embed
`./`-relative paths, so running from a different working directory, or over a different
file set, yields a different digest. Two exclusions are essential:

- `target/` — a 1.5 GB build directory created 15 Jul 2026, *after* the 14 Jul landing.
- `daffy_factory_module_hash_cert.cbor` — an operational artifact created 15 Jul 2026,
  likewise after the landing.

Neither exists in the tarball; neither was part of the original hashed tree. Including
the `.cbor` changes the git tree hash to `2f59b4e9128bbad27f8c83a534343382c0187fab`.

### Exact input tree (five files, all mtime 13 Jul 2026)

| Path | sha256 |
|---|---|
| `./Cargo.lock` | `95c1a4f8fe1df5d5b3981a29cc671c68cc5a50d4b70293e03d670cd14780f66f` |
| `./Cargo.toml` | `2c94a203b35a40b05c4addbedd90a5e3309e8260043ca4a07702897405d59c01` |
| `./README.md` | `9d0b4fa9c0ce41c52f636dca9aedf88f73fa9c729a2fe74d2a93f4692705ab4d` |
| `./spike_read_state.py` | `e16c8d957d0adcbf680a8f94929d2b2d0b72b878d20630a295bb2880e52e95fd` |
| `./src/main.rs` | `2b7a65f549a07af87bc7e7581d057d1873d845f36716c6f1c5fe68db899bd098` |

### Note on the digest method (material)

The A4 work item assumed the cited source-tree hash was a **canonical git tree hash**.
It is not. The git tree hash of the same five files is
`31e756689e5eb6a77666cb63c08c4a578d9bd927` — **no match** against `b3e4df…`. The
sha256 path+digest manifest above reproduces the cited prefix exactly.

The match is on the **24 bits** that survive in the ruling record. That is strong
evidence — and the reproduction holds from two independent inputs (standalone dir and
retired tarball) — but a 6-hex-character prefix is not a full-value proof. What is
established: the method is recovered, documented, and reproducible by any third party
holding either input.

**Recorded as the verified source-tree hash:**
`b3e4df6febad6c99eb0494cafcd9d8aed3967c91f30ffc00802339a588864b9e`

Secondary modern anchor (git tree hash of the same five files, recorded for future
reference, **not** a cited historical value):
`31e756689e5eb6a77666cb63c08c4a578d9bd927`

---

## 3. Landed tree — UNREPRODUCIBLE

The originally-recorded landed-tree hash **`e4142244…` (14 Jul 2026) is cited from the
ruling record and is not independently reproducible from git history.** The
originally-landed working tree was never committed: the first commit to touch `helper/`
already contains the 1b threshold changeset.

This value is marked **UNREPRODUCIBLE**. It is **not** replaced, and no recomputed
value below stands in for it.

Both plausible methods were tried against both candidate commits; none matches:

| Candidate | Method | Value | vs `e4142244…` |
|---|---|---|---|
| `89b036c:helper` | git tree hash | `738b68a472c3d37f04eb3c64b9e5603b4b163f4f` | no match |
| `89b036c:helper` | sha256 manifest (§2 method) | `c68b76d62750bd8fbf533637b947e05665564d13fabcb7ba861bdcf983bee1e9` | no match |
| `fe55ff7:helper` | git tree hash | `ffc6f941a40dfa8b51f0ffc3ff0a725b69ebdd15` | no match |

Commands:

```sh
git -C ~/projects/ICP-Delete-Leaf rev-parse '89b036c:helper'   # => 738b68a4…
git -C ~/projects/ICP-Delete-Leaf rev-parse 'fe55ff7:helper'   # => ffc6f941…
```

### The new reproducible provenance anchor

Per G's binding condition, the **first committed helper tree is the new reproducible
provenance anchor**:

| Field | Value |
|---|---|
| Anchor | `helper/` tree at first commit `89b036c` (ICP-Delete-Leaf) |
| Git tree hash | `738b68a472c3d37f04eb3c64b9e5603b4b163f4f` |
| Commit | `89b036c` — *feat(helper): Phase C wiring + consume MAX_FINALIZATION_DELAY_NS from zombie-core v0.4.1 — warn-threshold flag non-normative, guard_report schema v0.2 (G rulings 15-16 Jul 2026)* |
| Caveat | This tree **additionally contains the 1b threshold changeset** (and more — see §4). It is *not* the 14 Jul landed tree. |

---

## 4. Delta — RECONSTRUCTED

The reproducible **source → first-commit** delta, computed 17 Jul 2026:

```sh
git -C ~/projects/ICP-Delete-Leaf archive 89b036c:helper | tar x -C <tmp>/landed
diff -rq <tmp>/tarx/zd-finalize-helper <tmp>/landed
```

### File list — **four** files, not three

| File | Change | 1b-attributable? |
|---|---|---|
| `Cargo.toml` | modified | **Partly.** `zombie-core` git dep pinned to tag `zombie-core-v0.4.1` = **1b**. The added `[workspace]` stanza (self-contained workspace, so the off-canister tool does not perturb the root `Cargo.lock`) is **NOT 1b**. |
| `Cargo.lock` | modified (61 changed lines) | **Yes** — `zombie-core` v0.4.1 (`27d508f0…`) entry and its transitive closure. |
| `src/main.rs` | modified (+911 / −146) | **Partly** — see breakdown below. |
| `README.md` | **present in source, ABSENT at `89b036c`** | **No.** Not landed at the first commit; added later at `fe55ff7` (blob `ddaef855…`). |

### `src/main.rs` breakdown

- **1b-attributable:** `use zombie_core::MAX_FINALIZATION_DELAY_NS` and its consumption
  as the sole normative threshold driving `DELAY_EXCEEDED`; the non-normative
  warn-threshold flag; 5 of the landed tests.
- **NOT 1b-attributable:** Phase C finalize wiring — the source tree carries only an
  empty `Finalize {}` stub subcommand, wired to a real implementation in `89b036c`;
  `guard_report.json` schema v0.2; the remaining 16 of 21 landed tests (source: 0
  tests, landed: 21).

### Why this is a reconstruction, and what it does *not* establish

Subtracting the 1b-attributable changes from the above does **not** isolate the original
14 Jul landing delta, and this record does not claim that it does.

`89b036c` bundles **three** distinct workstreams in a single commit — its own message
names them: (i) Phase C wiring, (ii) the 1b threshold changeset, (iii) `guard_report`
schema v0.2. Only (ii) is 1b. What remains after subtracting 1b therefore still
conflates the original landing with Phase C wiring and schema v0.2, which are Gate-1
work from 15–16 Jul — *after* the 14 Jul landing.

**The residue is an upper bound on the original landing delta, not a recovery of it.**
The lost record's itemisation is the only thing that could have separated (i) and (iii)
from the 14 Jul landing, and it is gone.

This section is labelled **RECONSTRUCTED**. It is **never** to be cited as "the ruled
three-file delta" — note that the reproducible delta spans **four** files, which is
itself evidence that the source→`89b036c` delta is not the three-file delta the lost
record described.

---

## 5. Provenance of this provenance record

- The original landing record (14 Jul 2026) is **LOST**; only the three prefixes in the
  table at the head of this document survive.
- This record was **recomputed 17 Jul 2026** per G's Gate-2 A4 ruling (16 Jul 2026),
  under the binding W3/W4 addendum conditions (16 Jul 2026).
- Inputs used: `~/projects/zd-finalize-helper/` (standalone source tree; source files
  unmodified since 13 Jul 2026 — see §2 for the two post-landing additions that are
  excluded), `~/projects/zd-finalize-helper.tar.gz` (retired, read-only), and
  `ICP-Delete-Leaf @ fe55ff7`.
- Status: **substitution pending G acknowledgment.** Until acknowledged, the cited
  prefixes remain the record of authority for §1 and §3; §2 is verified against its
  cited prefix and reproducible from two independent inputs.

### Summary

| Item | Disposition |
|---|---|
| Source tree `b3e4df6feb…` | **VERIFIED** (method recovered; reproduces cited prefix from two inputs) |
| Landed tree `e4142244…` | **CITED, UNREPRODUCIBLE** (not replaced) |
| Tarball `e9c9013c94…` | **RETIRED** as an anchor (digest matches; anchor value nil) |
| Three-file delta | **LOST**; §4 is a **RECONSTRUCTED** upper bound over four files |
| New reproducible anchor | `89b036c:helper` = `738b68a472c3d37f04eb3c64b9e5603b4b163f4f` |
