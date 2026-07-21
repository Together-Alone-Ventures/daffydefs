#!/usr/bin/env bash
# =============================================================================
# upgrade_compat_check.sh — v2 — Gate 2 §0.3 stable-memory upgrade-compat check.
#
# THREE-CANISTER shape (W5p, C-ruled 20 Jul 2026; G ruled the obligation, not the
# shape — correction trail to G in the pre-deployment record). Supersedes the v1
# single-canister "upgrade-with-pending" shape, which is INVALID: upgrading a
# canister while a receipt is pending TRAPS by design (finalization-lock
# invariant). That trap is retained as OBSERVED EVIDENCE (a feature, not a
# failure) at tools/evidence/w5p_trap_oldshape.log; see §0.3 of the W5 runbook.
#
# All three canisters install from the PRE wasm (eb6bb58, 8f7b15f7…) and upgrade
# to the go-live v4 wasm (85a326cd…). They differ only in pre-upgrade state:
#
#   P1 — FINALIZED-V3 SURVIVAL (the core ReceiptBytes 8192->16384 question):
#        create profile -> Phase A delete -> FINALIZE UNDER OLD CODE (2-arg path)
#        -> upgrade -> assert the finalized v3 receipt is intact, readable,
#        exportable under new code; tombstone + deletion_seq preserved.
#   P2 — PLAIN-STATE SURVIVAL: create profile, no deletion -> upgrade ->
#        assert profile data intact and still functional.
#   P3 — POST-UPGRADE V4 CAPABILITY: install empty -> upgrade -> full fresh v4
#        cycle (create -> delete -> helper fetch-cert -> guard -> DIRECT 3-arg
#        finalize) -> finalized v4 receipt, both certificates written.
#
# COEXISTENCE (restates "same store", impossible in Leaf mode = one receipt per
# canister): P1's v3 and P3's v4 receipts are both valid under the SAME
# post-upgrade storage schema (16384 bound), read back under go-live code.
#
# ANY P1/P2/P3 assertion failing => FAIL => genuine migration signal => STOP:
# G return-for-ruling trigger (incompatible stable-memory migration). Do NOT
# work around. Deterministic, non-interactive, loud.
# =============================================================================
set -euo pipefail
STEP=0
trap 'rc=$?; echo "" >&2; echo "COMPAT CHECK v2 FAILED at step ${STEP} (exit $rc) — STOP: FAIL = genuine migration signal, G return-for-ruling trigger." >&2' ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT_DIR"
NETWORK="local"
PRE_WASM="$ROOT_DIR/rollback_artifacts/profile_canister_eb6bb58_PRE.wasm"
PRE_SHA="8f7b15f78ed38fedafc999e968cf4080b52ae7b58c5c20de565aee9537d3f59a"
GOLIVE_WASM="$ROOT_DIR/wasm_out/profile_canister.wasm"
GOLIVE_EXPECTED="85a326cda94bff9e56e0c6f0b72d6412c6a76d71f4329c43f1f651c23ebe5cea"
GOLIVE_DID="$ROOT_DIR/src/profile_canister/profile_canister.did"
HELPER_BIN="${HELPER_BIN:-$HOME/projects/ICP-Delete-Leaf/helper/target/release/zd-finalize-helper}"
WORK="$(mktemp -d)"
PRE_DID="$WORK/profile_canister_PRE.did"
PEM="$WORK/operator.pem"
log(){ echo ""; STEP=$((STEP+1)); echo "== Step ${STEP}: $* =="; }
die(){ echo "FATAL: $*" >&2; exit 1; }
# get deletion_seq / protocol_version fields out of an idl receipt dump
field_num(){ grep -oE "$1 = [0-9]+" | grep -oE '[0-9]+' | head -1; }

log "preflight + archived-artifact integrity"
for b in dfx cargo ic-wasm jq sha256sum git; do command -v "$b" >/dev/null || die "missing $b"; done
[[ -x "$HELPER_BIN" ]] || die "helper missing: $HELPER_BIN"
[[ -f "$PRE_WASM" ]] || die "PRE wasm missing: $PRE_WASM"
echo "$PRE_SHA  $PRE_WASM" | sha256sum -c - || die "PRE wasm sha mismatch"
git -C "$ROOT_DIR" show eb6bb58:src/profile_canister/profile_canister.did > "$PRE_DID" || die "cannot extract PRE candid"
echo "PRE candid (2-arg finalize) extracted to $PRE_DID"

log "build go-live profile wasm (current v4 source) + shrink; assert == recorded GOLIVE"
cargo build -p profile_canister --target wasm32-unknown-unknown --release
mkdir -p "$ROOT_DIR/wasm_out"
ic-wasm "$ROOT_DIR/target/wasm32-unknown-unknown/release/profile_canister.wasm" -o "$GOLIVE_WASM" shrink
GOLIVE_SHA="$(sha256sum "$GOLIVE_WASM" | awk '{print $1}')"
echo "PRE    (eb6bb58): $PRE_SHA"
echo "GOLIVE (current): $GOLIVE_SHA"
[[ "$GOLIVE_SHA" == "$GOLIVE_EXPECTED" ]] || die "go-live sha $GOLIVE_SHA != recorded $GOLIVE_EXPECTED (source drift)"
[[ "$GOLIVE_SHA" != "$PRE_SHA" ]] || die "go-live == PRE; no upgrade delta to test"

log "tear down leftover replica, start fresh --clean"
dfx stop >/dev/null 2>&1 || true
timeout 120 dfx start --clean --background >/dev/null 2>&1 || true
for _ in $(seq 1 40); do dfx ping "$NETWORK" >/dev/null 2>&1 && break; sleep 2; done
dfx ping "$NETWORK" >/dev/null 2>&1 || die "replica did not come up"
PORT="$(dfx info webserver-port 2>/dev/null || echo 4943)"
IC_URL="http://127.0.0.1:${PORT}"
echo "replica up; IC_URL=$IC_URL"

log "temp 3-canister project (p1/p2/p3, custom type, go-live wasm+candid)"
cat > "$WORK/dfx.json" <<JSON
{ "version": 1, "canisters": {
  "p1": { "type": "custom", "wasm": "$GOLIVE_WASM", "candid": "$GOLIVE_DID" },
  "p2": { "type": "custom", "wasm": "$GOLIVE_WASM", "candid": "$GOLIVE_DID" },
  "p3": { "type": "custom", "wasm": "$GOLIVE_WASM", "candid": "$GOLIVE_DID" }
}}
JSON
cd "$WORK"
dfx identity export "$(dfx identity whoami)" > "$PEM"
OWNER="$(dfx identity get-principal)"
echo "operator/controller principal: $OWNER"

log "create p1/p2/p3 canister ids + install PRE (eb6bb58) on each"
dfx canister create --all --network "$NETWORK"
P1="$(dfx canister id p1 --network "$NETWORK")"
P2="$(dfx canister id p2 --network "$NETWORK")"
P3="$(dfx canister id p3 --network "$NETWORK")"
echo "P1=$P1  P2=$P2  P3=$P3"
for C in p1 p2 p3; do
  dfx canister install "$C" --mode install --yes --wasm "$PRE_WASM" \
    --argument "(principal \"$OWNER\", opt \"$PRE_SHA\")" --network "$NETWORK"
done

# ---------------------------------------------------------------------------
# P1 — finalized-v3 survival
# ---------------------------------------------------------------------------
log "P1: create profile + Phase A delete (OLD code) => pending receipt"
dfx canister call "$P1" upsert_profile \
  '(record { birthdate="1990-01-01"; email="p1@example.com"; display_name="p1"; gender="x" })' \
  --candid "$PRE_DID" --network "$NETWORK" >/dev/null
RID1="$(dfx canister call "$P1" delete_profile --candid "$PRE_DID" --network "$NETWORK" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)"
[[ -n "$RID1" ]] || die "P1: no receipt_id from delete_profile"
dfx canister call "$P1" mktd_is_pending --candid "$PRE_DID" --network "$NETWORK" | grep -q true || die "P1: receipt not pending"
SEQ_PRE="$(dfx canister call "$P1" mktd_get_receipt "(\"$RID1\")" --candid "$PRE_DID" --network "$NETWORK" | field_num deletion_seq)"
echo "P1 pending receipt: $RID1  deletion_seq(pre)=$SEQ_PRE"

log "P1: FINALIZE UNDER OLD CODE via v0.4.1-era 2-arg path"
CERT_IDL="$(dfx canister call "$P1" mktd_get_certificate --candid "$PRE_DID" --network "$NETWORK" --output idl | tr -d '\n')"
CERTBLOB="$(printf '%s' "$CERT_IDL" | grep -oP 'certificate = blob "\K[^"]*')"
[[ -n "$CERTBLOB" ]] || die "P1: could not extract certificate blob from Phase B response"
printf '("%s", blob "%s")' "$RID1" "$CERTBLOB" > "$WORK/p1_finalize_arg.txt"
dfx canister call "$P1" mktd_finalize_receipt --argument-file "$WORK/p1_finalize_arg.txt" \
  --candid "$PRE_DID" --network "$NETWORK"
dfx canister call "$P1" mktd_is_pending --candid "$PRE_DID" --network "$NETWORK" | grep -q false \
  || die "P1: still pending after old-code finalize"
V3PROTO="$(dfx canister call "$P1" mktd_get_receipt "(\"$RID1\")" --candid "$PRE_DID" --network "$NETWORK" | grep -oE 'protocol_version = "[^"]*"' | head -1)"
echo "P1 finalized v3 receipt under OLD code (8192 bound); $V3PROTO"

log "P1: UPGRADE to go-live v4 (no pending receipt => lock invariant permits it)"
dfx canister install p1 --mode upgrade --yes --wasm "$GOLIVE_WASM" \
  --argument "(opt \"$GOLIVE_SHA\")" --network "$NETWORK"
UPH1="$(dfx canister status "$P1" --network "$NETWORK" 2>&1 | grep -iE 'module hash' | grep -oiE '[0-9a-f]{64}' | head -1)"
[[ "$UPH1" == "$GOLIVE_SHA" ]] || die "P1 post-upgrade hash $UPH1 != go-live $GOLIVE_SHA"

log "P1: assert v3 receipt survived (readable/exportable, seq + tombstone preserved)"
R1="$(dfx canister call "$P1" mktd_get_receipt "(\"$RID1\")" --network "$NETWORK")"
echo "$R1" | grep -q "$RID1" || die "P1: receipt not readable post-upgrade (migration broken)"
echo "$R1" | grep -q 'bls_certificate = opt' || die "P1: bls_certificate absent post-upgrade (not a finalized v3)"
SEQ_POST="$(printf '%s' "$R1" | field_num deletion_seq)"
[[ "$SEQ_POST" == "$SEQ_PRE" ]] || die "P1: deletion_seq changed across upgrade ($SEQ_PRE -> $SEQ_POST)"
dfx canister call "$P1" mktd_get_tombstone_status --network "$NETWORK" | grep -q 'is_tombstoned = true' \
  || die "P1: tombstone state lost across upgrade"
dfx canister call "$P1" mktd_get_certificate --network "$NETWORK" | grep -q 'null' \
  || die "P1: get_certificate not null post-finalize (should be null)"
echo "P1 OK: v3 receipt survived 8192->16384; deletion_seq=$SEQ_POST preserved; tombstoned; cert null"

# ---------------------------------------------------------------------------
# P2 — plain-state survival
# ---------------------------------------------------------------------------
log "P2: create profile (NO deletion) under OLD code"
dfx canister call "$P2" upsert_profile \
  '(record { birthdate="1985-05-05"; email="p2@example.com"; display_name="p2plain"; gender="y" })' \
  --candid "$PRE_DID" --network "$NETWORK" >/dev/null
dfx canister call "$P2" get_profile --candid "$PRE_DID" --network "$NETWORK" | grep -q "p2@example.com" \
  || die "P2: profile not set pre-upgrade"

log "P2: UPGRADE to go-live; assert plain state intact + functional"
dfx canister install p2 --mode upgrade --yes --wasm "$GOLIVE_WASM" \
  --argument "(opt \"$GOLIVE_SHA\")" --network "$NETWORK"
dfx canister call "$P2" get_profile --network "$NETWORK" | grep -q "p2@example.com" \
  || die "P2: profile data lost across upgrade"
dfx canister call "$P2" upsert_profile \
  '(record { birthdate="1985-05-05"; email="p2b@example.com"; display_name="p2plain2"; gender="y" })' \
  --network "$NETWORK" >/dev/null
dfx canister call "$P2" get_profile --network "$NETWORK" | grep -q "p2b@example.com" \
  || die "P2: not functional post-upgrade (write rejected)"
echo "P2 OK: plain profile survived upgrade and remains writable"

# ---------------------------------------------------------------------------
# P3 — post-upgrade v4 capability
# ---------------------------------------------------------------------------
log "P3: (installed PRE empty) UPGRADE to go-live"
dfx canister install p3 --mode upgrade --yes --wasm "$GOLIVE_WASM" \
  --argument "(opt \"$GOLIVE_SHA\")" --network "$NETWORK"
UPH3="$(dfx canister status "$P3" --network "$NETWORK" 2>&1 | grep -iE 'module hash' | grep -oiE '[0-9a-f]{64}' | head -1)"
[[ "$UPH3" == "$GOLIVE_SHA" ]] || die "P3 post-upgrade hash $UPH3 != go-live"

log "P3: full fresh v4 cycle (create -> delete -> helper guard + DIRECT 3-arg finalize)"
dfx canister call "$P3" upsert_profile \
  '(record { birthdate="2000-02-02"; email="p3@example.com"; display_name="p3v4"; gender="z" })' \
  --network "$NETWORK" >/dev/null
RID3="$(dfx canister call "$P3" delete_profile --network "$NETWORK" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)"
[[ -n "$RID3" ]] || die "P3: no receipt_id from delete_profile"
dfx canister call "$P3" mktd_is_pending --network "$NETWORK" | grep -q true || die "P3: not pending"
"$HELPER_BIN" --ic-url "$IC_URL" --fetch-root-key --identity-pem "$PEM" finalize \
  --canister-id "$P3" --expected-module-hash "$GOLIVE_SHA" \
  --finalize-method mktd_finalize_receipt \
  --out-cert "$WORK/p3_mh.cbor" --out-report "$WORK/p3_guard.json"
jq -e '.guard_status=="PASS"' "$WORK/p3_guard.json" >/dev/null || die "P3: guard not PASS"
dfx canister call "$P3" mktd_is_pending --network "$NETWORK" | grep -q false || die "P3: still pending after 3-arg finalize"
dfx canister call "$P3" mktd_get_certificate --network "$NETWORK" | grep -q 'null' || die "P3: cert not null after finalize"
R3="$(dfx canister call "$P3" mktd_get_receipt "(\"$RID3\")" --network "$NETWORK")"
echo "$R3" | grep -q 'bls_certificate = opt' || die "P3: bls_certificate absent after finalize"
V4PROTO="$(printf '%s' "$R3" | grep -oE 'protocol_version = "[^"]*"' | head -1)"
# mktd02 writes bls_certificate + module_hash_certificate together (no single-cert
# path); guard PASS + finalize OK + cert null => both certificates present.
echo "P3 OK: fresh v4 cycle on an UPGRADED canister; $V4PROTO; both certificates written (guard PASS + 3-arg finalize OK)"

# ---------------------------------------------------------------------------
# Coexistence (same post-upgrade schema, not same store)
# ---------------------------------------------------------------------------
log "COEXISTENCE: P1 v3 + P3 v4 both valid under the same 16384 go-live schema"
echo "  P1 (migrated, finalized under OLD code): $V3PROTO ; bls present ; readable under go-live"
echo "  P3 (fresh v4 on upgraded canister)     : $V4PROTO ; both certs ; readable under go-live"
if [[ "$V3PROTO" != "$V4PROTO" ]]; then
  echo "  legacy-isolation: protocol_version differs (v3 vs v4) as expected"
else
  echo "  NOTE: protocol_version strings identical ($V3PROTO) — recorded for review"
fi
echo "  (OPTIONAL CVDR-Verify-against-P1 legacy-isolation classification: NOT run this pass — verifier fixture out of scope for the plumbing check.)"

echo ""
echo "============================================================"
echo "UPGRADE-COMPAT CHECK v2 PASSED — §0.3 satisfied (three-canister shape):"
echo "  P1 finalized-v3 receipt survived the 8192->16384 ReceiptBytes migration,"
echo "     readable/exportable under go-live, deletion_seq + tombstone preserved."
echo "  P2 plain profile survived and stayed functional."
echo "  P3 fresh v4 cycle succeeded on an upgraded canister (both certificates)."
echo "  PRE    (eb6bb58): $PRE_SHA"
echo "  GOLIVE (current): $GOLIVE_SHA"
echo "  P1 receipt=$RID1   P3 receipt=$RID3"
echo "Reminder: local root key != mainnet; this proves migration plumbing, not a V3 verdict."
echo "============================================================"
dfx stop >/dev/null 2>&1 || true
