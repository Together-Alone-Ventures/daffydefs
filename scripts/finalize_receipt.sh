#!/usr/bin/env bash
# =============================================================================
# finalize_receipt.sh — DaffyDefs wrapper for receipt finalization recovery
#
# This is not the normal in-app user path.
# Normal app path: frontend/user flow drives A→B→C via factory proxy calls.
#
# This wrapper is for recovery/operations when Phase A completed but B/C did not.
# It delegates to generic MKTd02 recovery tooling.
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

# Delegate to generic recovery tooling in the MKTd02 repo
GENERIC="$HOME/projects/MKTd02/scripts/finalize_receipt_generic.sh"

if [[ ! -x "$GENERIC" ]]; then
  echo "ERROR: Generic script not found/executable at: $GENERIC" >&2
  echo "Fix: ensure the MKTd02 repo is present at $HOME/projects/MKTd02 and the generic script is executable." >&2
  exit 1
fi

"$GENERIC" --profile "$PROFILE" --factory-canister "$FACTORY" --network "$NETWORK"
