# DaffyDefs → mktd02-v0.4.1 (R2) — Bump Deliverable (inspect-and-propose)

**Mode:** inspect-and-propose. **Uncommitted.** No commit/push/tag; no dfx; gates apply.
**Repo:** `daffydefs` @ HEAD `7429237` (clean at preflight). **Engine:** `mktd02-v0.4.1` (ic-cdk 0.18 / is-0.7).
**Constraint:** deployed mainnet canisters hold live is-0.6 stable memory — encodings must stay byte-compatible for an UPGRADE to read existing data.

---

## 0. Engine resolution — RELEASED TAG (R1 complete; scaffold removed)

R1 is complete: **`mktd02-v0.4.1` is tagged (commit `921d710`), pushed, and released** (Integration Guide
attached). `profile_canister/Cargo.toml` pins `tag = "mktd02-v0.4.1"` and cargo resolves the engine
**directly from the GitHub source** — the temporary `[patch]` scaffold has been **removed** from the
workspace root `Cargo.toml`. Lock entry (verified):

```
mktd02 v0.4.1
source = "git+https://github.com/Together-Alone-Ventures/ICP-Delete-Leaf.git?tag=mktd02-v0.4.1#921d710c8e7295739ed6055991383bb0929e4cec"
```

**All build evidence in this deliverable is the tag-resolved rebuild against the released artifact**
(`#921d710c`). It **supersedes** the earlier local-engine-working-tree build used during Phase-2
iteration (which is no longer present — no `[patch]`, no path dep).

## 1. Evidence-based scope reduction (based on current recon evidence)

The packet asked for "is-0.7 in every crate sharing the engine's graph." **Based on current recon
evidence, this is narrowed:** ic-stable-structures has **no `links`**, and **no is-0.6 `Storable` type
crosses the `shared`→`profile_canister` boundary** (profile_canister imports from `shared` only
`log_error`, `log_event`, `DaffyError`, `SCHEMA_VERSION_V1` — none are `Storable`). So **is-0.7 is forced
ONLY in `profile_canister`**; `shared`/`bulletin_board`/`profile_factory` **retain is-0.6**, leaving their
live stable-data encodings byte-identical (their `Storable` source is untouched). This is the *minimal*
and *safest* choice for the mainnet preservation constraint.

**Phase-2 compile evidence CONFIRMS the scoping (it did not contradict it).** With is-0.7 in
profile_canister and is-0.6 retained elsewhere, the build produced is-0.7 trait errors (`into_bytes`
missing; `Cell::init`/`set` `Result` removed) **exclusively in `profile_canister`** —
`shared`/`bulletin_board`/`profile_factory` compiled **unchanged** under is-0.6. Had any is-0.6 Storable
type actually crossed into profile_canister's is-0.7 structures, the compiler would have raised a
trait-mismatch there; it did not. (Per G: a contradiction here would be **reported, not absorbed** — none arose.)

## 2. Why the whole workspace moves to ic-cdk 0.18 (the forced part)

One workspace, one `Cargo.lock`. `cargo tree -i ic-cdk-executor` (before): all three ic-cdk versions
(0.15.2 via timers, 0.16.1 via shared/bb/factory, 0.17.2 via mktd02/profile_canister) **unify on
`ic-cdk-executor v0.1.0`** → one executor → builds today. Registry facts: ic-cdk 0.16/0.17 require
executor `0.1.0`; **ic-cdk 0.18.7 requires executor `1.0.2`**; both executors carry the **same**
`links = "ic-cdk async executor…"`. Cargo forbids two same-`links` packages **in one resolve graph**
(proven by the OpenChatZD failure across *separate* canisters). A single shared lock ⇒ executor 0.1.0 and
1.0.2 cannot coexist ⇒ **every ic-cdk-pulling crate must move to 0.18**. `ic-cdk-timers 0.9` (→ ic-cdk
0.15 → executor 0.1.0) is part of the collision → it goes (see §5).

## 3. Diff inventory

| File | Change | Class |
|---|---|---|
| `Cargo.toml` (root) | **unchanged** (verification `[patch]` added then removed → pristine) | — |
| `src/shared/Cargo.toml` | ic-cdk 0.16→**0.18**; is **0.6 retained** | forced (links) |
| `src/bulletin_board/Cargo.toml` | ic-cdk 0.16→**0.18**; **remove ic-cdk-timers**; is 0.6 retained | forced |
| `src/profile_factory/Cargo.toml` | ic-cdk 0.16→**0.18**; **remove ic-cdk-timers**; is 0.6 retained | forced |
| `src/profile_canister/Cargo.toml` | ic-cdk 0.17→**0.18**; **remove ic-cdk-timers**; is 0.6→**0.7**; mktd02 tag v0.4.0→**v0.4.1** | forced |
| `src/profile_canister/src/lib.rs` | is-0.7: `StoredProfile::into_bytes`; drop `Result` on `Cell::init`/`set`; `caller→msg_caller` | forced + cleanup |
| `src/bulletin_board/src/lib.rs` | `ic_cdk::caller()`→`api::msg_caller()` ×4 | cleanup (deprecation) |
| `src/profile_factory/src/lib.rs` | `caller()`→`msg_caller()` ×2; `id()`→`canister_self()` ×1 | cleanup (deprecation) |
| `Cargo.lock` | refreshed by build (not hand-edited) | forced |

`src/shared/src/lib.rs` is **NOT modified** — `StorablePrincipal` and all shared logic byte-identical.

## 4. Preservation attestation — per Storable type (re-verified at HEAD + post-bump)

| Type | Crate | is after | Bound now→after | to_bytes/from_bytes | format | Encoding change? |
|---|---|---|---|---|---|---|
| **StoredProfile** | profile_canister | 0.6→**0.7** | 1024/false → **same** | unchanged; **+`into_bytes`** delegating to `to_bytes().into_owned()` | Candid (`encode_one`/`decode_one`) | **None** — written bytes identical |
| `u64` schema cell | profile_canister | 0.6→0.7 | builtin | builtin | raw LE | None |
| StorablePrincipal | shared | **0.6 (kept)** | 30/true | **untouched** | raw len-prefixed | **None** |
| Metadata / StoredChallenge / StoredComment | bulletin_board | **0.6 (kept)** | 128 / 256 / 1024, false | **untouched** | Candid | **None** |
| ChallengeCommentKey / LikeEdgeKey / DayRateLimitKey | bulletin_board | **0.6 (kept)** | 16 / 38 / 34, true | **untouched** | raw BE (+ embeds StorablePrincipal) | **None** |
| PROFILE_MAP `<StorablePrincipal,StorablePrincipal>`, schema u64 | profile_factory | **0.6 (kept)** | — | **untouched** | raw | **None** |

**Only `StoredProfile` moves is-version, and it is byte-identical:** `into_bytes` delegates to the
unchanged `to_bytes` (Candid); `Bound` unchanged; and is-0.7's `StableCell` on-disk format
(`MAGIC="SCL"`, `HEADER_V1_SIZE=8`, `LAYOUT_VERSION=1`, value@offset 8) is **identical to is-0.6**
(established in the engine v0.4.1 deliverable) → the existing is-0.6-written `PROFILE`/`SCHEMA_VERSION`
cells (MemoryId 1/0) read correctly on upgrade. **MemoryId map:** profile_canister own {0,1}; engine
`base_memory_id=100` → {100–107}; **disjoint** (and the engine slots, already written under is-0.6 by
mktd02 v0.4.0, are preserved per the engine attestation: Cell/BTreeMap formats unchanged).

## 5. ic-cdk-timers — removed (unused, forced into play)

`ic-cdk-timers` was declared in bulletin_board/profile_canister/profile_factory but **never used**
(`grep` for `set_timer`/`TimerId`/`ic_cdk_timers` → 0 hits). It was an **unused dependency forced into
play by the executor collision** (0.9 → ic-cdk 0.15 → executor 0.1.0). Per Phase-1 decision (b),
**removed** rather than bumped — the build is the backstop (compiles + wasm32 clean without it).

## 6. profile_factory management-canister API — DECISION: kept on deprecated `main` (value-identical)

The factory is the **cycle-critical** canister. Its `ic_cdk::api::management_canister::main` calls
(`create_canister`, `install_code`, `delete_canister`, `stop_canister`, `CanisterSettings`,
`CreateCanisterArgument`, `InstallCodeArgument`, `CanisterInstallMode`) **compile unchanged** under ic-cdk
0.18 — the module is **deprecated but a behavior-preserving compat shim** for the 0.16/0.17 contract. The
bump does **not force** changing them. Per "minimal change" + "flag ANY default that changed rather than
absorbing it", the **lowest-risk choice is to NOT touch the cycle-critical call sites** — which makes
default-drift impossible. Per-call-site value-identity (args **unchanged**, source untouched):

| Call site | Args — value-identical? |
|---|---|
| `create_canister(CreateCanisterArgument{ settings: CanisterSettings{ controllers: [<factory self>], compute/memory/freezing/reserved/log_visibility/wasm_memory_limit: None }}, CYCLES_PER_PROFILE_CANISTER)` | **Yes** — controllers = factory's own id (now `canister_self()`, **same principal** as `id()`); cycles arg unchanged; all settings `None` (system defaults) unchanged |
| `install_code(InstallCodeArgument{ mode: Install, canister_id, wasm_module, arg })` | **Yes** — mode `Install`, wasm + candid-encoded init arg unchanged |
| `delete_canister` / `stop_canister(CanisterIdRecord)` | **Yes** — unchanged |

> **Residual — ACCEPTED, DOCUMENTED DEBT (G-confirmed):** profile_factory emits **51 deprecation
> warnings** (management `main` API + `ic_cdk::call` + `canister_balance128`). The build and wasm32 succeed;
> behavior is value-identical via the compat shims. **Decision: KEEP-DEPRECATED is confirmed** for this
> bump — the cycle-critical call sites are not touched, so no default can drift. **Resolution path:** a
> named follow-up packet, **"DaffyDefs management-API migration"**, will migrate to the crate-root
> `ic_cdk::management_canister` + `ic_cdk::call::Call` APIs under independent review, with its own
> value-identity check of every create/install/cycles default. The 51 warnings are tracked debt resolved
> by that packet — not by this dependency bump.

## 7. Build / test / wasm32 results — TAG-RESOLVED (released `mktd02-v0.4.1#921d710`)

All evidence below is the rebuild after removing the scaffold, with cargo resolving the engine from the
**GitHub tag** (supersedes the earlier local-tree build):

| Check | Result |
|---|---|
| engine resolution | `mktd02 v0.4.1` from `git+…ICP-Delete-Leaf.git?tag=mktd02-v0.4.1#921d710c…` ✅ |
| `cargo build` (workspace) | **clean** (warnings only) |
| `cargo test` | **0 tests** — DaffyDefs has no Rust test suite (validation = Pass-3 proof scripts, out of scope); all 5 crates report `ok` |
| wasm32 release — bulletin_board | ✅ `bulletin_board.wasm` (1,017,005 B) |
| wasm32 release — profile_canister | ✅ `profile_canister.wasm` (1,219,095 B) |
| wasm32 release — profile_factory | ✅ `profile_factory.wasm` (2,033,861 B) |

**Resolved graph (re-verified against the released tag):** `ic-cdk v0.18.7` (only), `ic-cdk-executor
v1.0.2` (only — 0.1.0 collision gone), `ic-stable-structures v0.6.9 + v0.7.2` (coexist: is-0.6 for
shared/bb/factory, is-0.7 for profile_canister), `ic0 v1.1.0`, **`ic-cdk-timers` absent**, `mktd02 v0.4.1`
@ tag `mktd02-v0.4.1#921d710c`, `zombie-core` @ `zombie-core-v0.3.1#508f2f8b` (unchanged, unified).

Warning summary (all non-forced, build succeeds): shared 1 (elided-lifetime lint on the untouched
`StorablePrincipal::to_bytes` — left as-is to keep shared byte-identical), bulletin_board 7, profile_canister
1 (`unused import: log_error`), profile_factory 51 (§6 deprecations).

## 8. Candid `.did` / `.did.ts` — no sync needed (flagged, not touched)

Manually-maintained: `src/{bulletin_board,profile_canister,profile_factory}/*.did` and
`src/frontend/src/ic/*.did.ts`. **No candid TYPE or method signature changed** (edits were internal:
`caller` rename, `into_bytes`, `Result`-drop — none alter the public interface). So the `.did`/`.did.ts`
remain accurate; **no sync required**. (Not modified, per scope.)

## 9. Out of scope (not run / not prepared)

Deployment and **Pass-3** are out of scope. The proof-run scripts the human will invoke manually:
`scripts/build.sh`, `scripts/clean_build_deploy_local.sh`, `scripts/finalize_receipt.sh`,
`scripts/principal_to_hex.py`, `scripts/validate_record_id_local.md`. No engine change; no `.did`/`.did.ts`
edit.

## 10. G addendum — required confirmations (points 1–3) + HARD GATE

### Point 1 — dependency-graph evidence that ONLY profile_canister needs is-0.7

`cargo tree --locked -i` on the resolved graph (post-bump):

```
ic-stable-structures v0.7.2
├── mktd02 v0.4.1            → profile_canister
└── profile_canister                                  ← is-0.7 consumers: profile_canister (+ engine) ONLY

ic-stable-structures v0.6.9
├── bulletin_board
├── profile_factory
└── shared  → bulletin_board, profile_canister, profile_factory   ← is-0.6 consumers
```

is-0.7 is reached **only** through `mktd02 v0.4.1` and `profile_canister`'s own dep. **No-boundary-crossing
argument:** `shared` is compiled into profile_canister at **is-0.6**, but profile_canister consumes from
`shared` only non-`Storable` items (`log_error`/`log_event`/`DaffyError`/`SCHEMA_VERSION_V1`) — so no
is-0.6 `Storable` type (`StorablePrincipal`) is placed into profile_canister's is-0.7 `StableCell`/
`StableBTreeMap`. is has no `links`, so is-0.6 and is-0.7 coexist in the one lock (verified: both `0.6.9`
and `0.7.2` present). Confirmed by Phase-2 compile evidence (§1).

### Point 2 — the SEVEN live-mainnet Storable types left UNTOUCHED (Bound values, re-verified post-build)

Carried from Phase 1, re-verified against the post-build tree (`git diff` shows **zero edits** to any of
these impls):

| # | Type | Crate | `max_size` | `is_fixed_size` | Format |
|---|---|---|---|---|---|
| 1 | `StorablePrincipal` | shared | 30 | true | raw, length-prefixed |
| 2 | `Metadata` | bulletin_board | 128 | false | Candid (`encode_one`) |
| 3 | `StoredChallenge` | bulletin_board | 256 | false | Candid |
| 4 | `StoredComment` | bulletin_board | 1024 | false | Candid |
| 5 | `ChallengeCommentKey` | bulletin_board | 16 | true | raw BE (2× u64) |
| 6 | `LikeEdgeKey` | bulletin_board | 38 | true | raw (u64 BE ‖ `StorablePrincipal`) |
| 7 | `DayRateLimitKey` | bulletin_board | 34 | true | raw (`StorablePrincipal` ‖ u32 BE) |

`git diff src/shared/src/lib.rs` = **empty**; `git diff src/bulletin_board/src/lib.rs` touches **only**
four `ic_cdk::caller()`→`api::msg_caller()` lines (none inside any `Storable` impl). All seven retain
is-0.6 and their exact Bound/encoding.

### Point 3 — explicit confirmation: NO DaffyDefs-owned stable surface changed

- **Stable encodings:** the seven preserved types (Point 2) have **zero source edits**. The 8th DaffyDefs
  Storable, `StoredProfile` (profile_canister, is-0.7), has its `to_bytes`/`from_bytes`/`BOUND`
  **unchanged** (`git diff` confirms no edit to those lines); the only addition is the required
  `into_bytes` delegating to `to_bytes().into_owned()` ⇒ **emitted bytes byte-identical**.
- **Bounds:** **no `max_size`/`is_fixed_size` literal changed** anywhere (all 8 types) — verified by diff.
- **MemoryId allocations:** **unchanged** — no `MemoryId::new(_)` line edited (profile_canister {0,1};
  bulletin_board {0–6}; profile_factory {0,1,3}); engine base 100→{100–107} disjoint.
- **Upgrade/init hooks:** behavior unchanged. Edits inside `init`/`post_upgrade` are limited to the forced
  is-0.7 mechanical `Result`-drop on `Cell::set` (value-identical write of the same `SCHEMA_VERSION_V1` /
  `StoredProfile`); the schema-version gate, migration logic, MemoryId wiring, and `mktd02::on_post_upgrade`
  cascade call are untouched.
- **Candid `.did`/`.did.ts`:** **no public type or method signature changed** ⇒ no surface change, no sync
  needed; files not touched.

### HARD GATE (restated)

Any change to the seven preserved `Storable` surfaces (Point 2) is a **STOP / migration gate**, not a
routine bump. **Status: gate NOT tripped** — all seven are byte-identical and source-unmodified; the only
is-version move (`StoredProfile`) is byte-identical. G's commit-time nod is conditional on Points 1–3
holding, which they do.

## 11. Pre-commit checklist (for the human, through the ladder)

1. **R1 complete — verified against released tag.** `profile_canister/Cargo.toml` pins
   `tag = "mktd02-v0.4.1"`; cargo resolves it from GitHub to `#921d710c…` (lock verified); scaffold
   removed; root `Cargo.toml` pristine. All build/wasm32 evidence is the tag-resolved rebuild (supersedes
   the prior local-tree build). *(Was: "R1 must tag first" — now stale; superseded.)*
2. `Cargo.lock` refresh = its own deliberate commit.
3. §6 management-API decision: **KEEP-DEPRECATED confirmed**; 51 warnings accepted as documented debt,
   resolved by the named follow-up packet **"DaffyDefs management-API migration"** (not this bump).
4. CD independent review + G's commit-time nod (Points 1–3, §10) — both before the human commit.
5. Then Pass-3 (proof-run scripts in §9), run manually by the human.
