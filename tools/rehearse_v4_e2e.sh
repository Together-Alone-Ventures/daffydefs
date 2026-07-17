#!/usr/bin/env bash
# =============================================================================
# rehearse_v4_e2e.sh — DaffyDefs mktd02-v4 A→B→C rehearsal (LOCAL replica)
#
# CD VERIFICATION SUBSTRATE. Deterministic, idempotent, non-interactive, loud on
# failure. Exercises the full subnet-attested-code-identity finalize flow end to
# end on the local PocketIC-backed replica, in BOTH finalize modes, plus BOTH
# W1.3 deploy-time cross-checks:
#   - factory-level cross-check (condition 2): external read-back of the deployed
#     factory module hash == built factory WASM (this script).
#   - profile-level cross-check (condition 1a): the factory's in-code read-back
#     runs during get_or_create_profile_canister; a successful mint (Ok) proves it
#     passed (a mismatch would Err + clean up, never registering the mapping).
#   - direct 3-arg  : zd-finalize-helper finalize      -> profile.mktd_finalize_receipt
#   - factory 4-arg : zd-finalize-helper finalize --factory -> factory.finalize_profile_receipt
#
# WHAT THIS PROVES / DOES NOT PROVE
#   The local replica root key is NOT the IC mainnet root key. This proves the
#   PLUMBING (candid shapes, A→B→C wiring, both finalize modes, both certificates
#   land, both cross-checks). It does NOT produce a mainnet V3-A SUBNET-ATTESTED
#   verdict — that is the Gate 2 W5 mainnet run + CVDR-Verify.
#
# DIRECT-MODE NOTE: profile.mktd_finalize_receipt -> mktd02::finalize_receipt is
#   CONTROLLER-GUARDED. Factory-minted profiles are controlled only by the
#   factory, so direct mode is exercised against a STANDALONE profile canister
#   installed with the operator as controller. The normal app path is the factory
#   proxy (also exercised here).
#
# Usage:
#   HELPER_BIN=/path/to/zd-finalize-helper  bash tools/rehearse_v4_e2e.sh
#   (HELPER_BIN defaults to the released ICP-Delete-Leaf@fe55ff7 build if present.)
# =============================================================================
set -euo pipefail

STEP=0
trap 'echo "" >&2; echo "REHEARSAL FAILED at step ${STEP} (exit $?)." >&2' ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NETWORK="local"
IC_URL="http://127.0.0.1:4943"
RD="$ROOT_DIR/target/wasm32-unknown-unknown/release"
WASM_OUT="$ROOT_DIR/wasm_out"
EMBED="$ROOT_DIR/src/profile_factory/profile_canister_embedded.wasm"
HELPER_BIN="${HELPER_BIN:-$HOME/projects/ICP-Delete-Leaf/helper/target/release/zd-finalize-helper}"
PEM="/tmp/rehearse_operator.pem"

log() { echo ""; STEP=$((STEP+1)); echo "== Step ${STEP}: $* =="; }
die() { echo "FATAL: $*" >&2; exit 1; }
extract_cid() { grep -oE '[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-cai' | head -1; }

# --- Step 0: preflight --------------------------------------------------------
log "preflight (dfx, cargo, ic-wasm, jq, sha256sum, helper)"
for b in dfx cargo ic-wasm jq sha256sum; do command -v "$b" >/dev/null || die "missing $b"; done
[[ -x "$HELPER_BIN" ]] || die "helper not found/executable: $HELPER_BIN (build: cargo build --release --manifest-path \$HOME/projects/ICP-Delete-Leaf/helper/Cargo.toml)"
"$HELPER_BIN" --version || true

# --- Step 1: build (profile -> shrink -> embed -> REBUILD factory) ------------
log "build wasms (profile shrink+embed, then rebuild factory so it embeds it)"
mkdir -p "$WASM_OUT"
cargo build -p profile_canister --target wasm32-unknown-unknown --release
ic-wasm "$RD/profile_canister.wasm" -o "$WASM_OUT/profile_canister.wasm" shrink
cp "$WASM_OUT/profile_canister.wasm" "$EMBED"
cargo build -p profile_factory --target wasm32-unknown-unknown --release
cp "$RD/profile_factory.wasm" "$WASM_OUT/profile_factory.wasm"
PROFILE_MH="$(sha256sum "$WASM_OUT/profile_canister.wasm" | awk '{print $1}')"
FACTORY_MH="$(sha256sum "$WASM_OUT/profile_factory.wasm" | awk '{print $1}')"
echo "profile module_hash: $PROFILE_MH"
echo "factory module_hash: $FACTORY_MH"

# --- Step 2: fresh replica ----------------------------------------------------
log "start clean local replica"
dfx stop >/dev/null 2>&1 || true
dfx start --clean --background >/dev/null 2>&1
for _ in $(seq 1 30); do dfx ping "$NETWORK" >/dev/null 2>&1 && break; sleep 2; done
dfx ping "$NETWORK" >/dev/null 2>&1 || die "replica did not come up"
dfx identity export "$(dfx identity whoami)" > "$PEM"

# --- Step 3: deploy factory + factory-level cross-check (condition 2) ---------
log "create + install factory"
dfx canister create profile_factory --network "$NETWORK" >/dev/null 2>&1 || true
dfx canister install profile_factory --mode reinstall --yes \
  --wasm "$WASM_OUT/profile_factory.wasm" --network "$NETWORK"
dfx ledger fabricate-cycles --canister profile_factory --network "$NETWORK" >/dev/null 2>&1 || true

log "FACTORY cross-check: on-chain factory module hash == built factory WASM"
ONCHAIN_F="$(dfx canister status profile_factory --network "$NETWORK" 2>&1 \
  | grep -iE 'module hash' | grep -oiE '[0-9a-f]{64}' | head -1)"
[[ "$ONCHAIN_F" == "$FACTORY_MH" ]] || die "factory cross-check: on-chain $ONCHAIN_F != built $FACTORY_MH"
echo "factory cross-check PASS ($ONCHAIN_F)"

guard_then_finalize() { # <profile> <mode> [factory_id]
  local profile="$1" mode="$2" factory="${3:-}"
  dfx canister call "$profile" delete_profile --network "$NETWORK" >/dev/null
  dfx canister call "$profile" mktd_is_pending --network "$NETWORK" | grep -q true \
    || die "[$mode] expected pending receipt after delete_profile"
  "$HELPER_BIN" --ic-url "$IC_URL" --fetch-root-key --identity-pem "$PEM" guard \
    --canister-id "$profile" --expected-module-hash "$PROFILE_MH" \
    --out-cert "/tmp/reh_${mode}.cbor" --out-report "/tmp/reh_${mode}.json" >/dev/null
  jq -e '.guard_status=="PASS"' "/tmp/reh_${mode}.json" >/dev/null || die "[$mode] guard not PASS"
  if [[ "$mode" == "factory" ]]; then
    "$HELPER_BIN" --ic-url "$IC_URL" --fetch-root-key --identity-pem "$PEM" finalize --factory \
      --canister-id "$profile" --expected-module-hash "$PROFILE_MH" \
      --finalize-canister-id "$factory" --finalize-method finalize_profile_receipt \
      --out-cert "/tmp/reh_${mode}.cbor" --out-report "/tmp/reh_${mode}.json"
  else
    "$HELPER_BIN" --ic-url "$IC_URL" --fetch-root-key --identity-pem "$PEM" finalize \
      --canister-id "$profile" --expected-module-hash "$PROFILE_MH" \
      --finalize-method mktd_finalize_receipt \
      --out-cert "/tmp/reh_${mode}.cbor" --out-report "/tmp/reh_${mode}.json"
  fi
  # FinalizedCandidate proof: Phase B now returns none (only pending receipts show).
  dfx canister call "$profile" mktd_get_certificate --network "$NETWORK" | grep -q "null" \
    || die "[$mode] receipt still pending after finalize (expected FinalizedCandidate)"
  echo "[$mode] OK — finalized; both certificates present (Phase B now none)"
}

# --- Step 4: FACTORY MODE (4-arg) — mint via factory (profile cross-check 1a) --
log "FACTORY mode: mint (in-code profile cross-check) + factory 4-arg finalize"
FACTORY_ID="$(dfx canister id profile_factory --network "$NETWORK")"
MINT="$(dfx canister call profile_factory get_or_create_profile_canister --network "$NETWORK" 2>&1)"
echo "$MINT" | grep -q "Ok" || die "mint failed (profile cross-check would Err on mismatch): $MINT"
PROFILE_F="$(echo "$MINT" | extract_cid)"
[[ -n "$PROFILE_F" ]] || die "could not parse minted profile id"
echo "minted (cross-check passed, registered): $PROFILE_F"
guard_then_finalize "$PROFILE_F" factory "$FACTORY_ID"

# --- Step 5: DIRECT MODE (3-arg) — standalone operator-controlled profile ------
log "DIRECT mode: standalone operator-controlled profile + direct 3-arg finalize"
OWNER="$(dfx identity get-principal)"
dfx canister create profile_canister --network "$NETWORK" >/dev/null 2>&1 || true
dfx canister install profile_canister --mode reinstall --yes \
  --wasm "$WASM_OUT/profile_canister.wasm" \
  --argument "(principal \"$OWNER\", opt \"$PROFILE_MH\")" --network "$NETWORK"
PROFILE_D="$(dfx canister id profile_canister --network "$NETWORK")"
guard_then_finalize "$PROFILE_D" direct

echo ""
echo "============================================================"
echo "REHEARSAL PASSED — both cross-checks + both finalize modes (LOCAL)."
echo "  factory cross-check : $FACTORY_MH"
echo "  profile module_hash : $PROFILE_MH"
echo "  factory-mode profile: $PROFILE_F"
echo "  direct-mode  profile: $PROFILE_D"
echo "Reminder: local root key != mainnet; V3-A verdict is a mainnet-only claim (Gate 2 W5/W6)."
echo "============================================================"
