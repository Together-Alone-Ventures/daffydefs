#!/usr/bin/env bash
# =============================================================================
# finalize_receipt.sh — DaffyDefs Recovery Tool (Phases B + C)
#
# NOT the normal user flow. Normal flow is frontend orchestration (A→B→C).
# This is a recovery tool if Phase A completed but B/C did not.
#
# Usage:
#   ./scripts/finalize_receipt.sh <profile_canister_id> [network]
#
# Examples:
#   ./scripts/finalize_receipt.sh be2us-64aaa-aaaaa-qaabq-cai local
#   ./scripts/finalize_receipt.sh <profile_id> ic
# =============================================================================
set -euo pipefail

PROFILE="${1:-}"
NETWORK="${2:-local}"

if [[ -z "$PROFILE" ]]; then
  echo "Usage: $0 <profile_canister_id> [network]" >&2
  exit 1
fi

# repo root
cd "$(dirname "$0")/.."

# auto-detect factory id from dfx project
FACTORY="$(dfx --network "$NETWORK" canister id profile_factory)"

echo "[*] Using network: $NETWORK"
echo "[*] Profile canister: $PROFILE"
echo "[*] Factory canister: $FACTORY"

# Call the generic script from the local MKTd02 clone
GENERIC="$HOME/projects/MKTd02/scripts/finalize_receipt_generic.sh"

if [[ ! -x "$GENERIC" ]]; then
  echo "ERROR: Generic script not found/executable at: $GENERIC" >&2
  echo "Fix: ensure MKTd02 repo is present at $HOME/projects/MKTd02 and the script is executable." >&2
  exit 1
fi

"$GENERIC" --profile "$PROFILE" --factory-canister "$FACTORY" --network "$NETWORK"
