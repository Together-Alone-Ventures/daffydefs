#!/usr/bin/env bash
# ==============================================================
# DaffyDefs Build Script — app build pipeline for this example repo
# ==============================================================
#
# Builds DaffyDefs canisters/frontend in app-specific order, optimises
# shipped WASMs, verifies Candid extraction on shipped artifacts, and
# builds the frontend bundle.
#
# This script is DaffyDefs-specific operational tooling.
# Generic MKTd02 protocol/recovery tooling belongs in the MKTd02 repo.
#
# Usage: bash scripts/build.sh
#
# The script is idempotent — safe to re-run at any time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Output directory for optimised WASMs — dfx.json references these
WASM_OUT="$PROJECT_ROOT/wasm_out"
mkdir -p "$WASM_OUT"

CARGO_TARGET="wasm32-unknown-unknown"
RELEASE_DIR="$PROJECT_ROOT/target/$CARGO_TARGET/release"

echo "=========================================="
echo "DaffyDefs Build Pipeline"
echo "=========================================="

# ----------------------------------------------------------
# Step 1: Build profile_canister (must be first — factory embeds it)
# ----------------------------------------------------------
echo ""
echo "[1/11] Building profile_canister..."
cargo build -p profile_canister --target $CARGO_TARGET --release

# ----------------------------------------------------------
# Step 2: Optimise profile_canister WASM
# ----------------------------------------------------------
echo "[2/11] Optimising profile_canister WASM..."
SHRINK_CMD="ic-wasm $RELEASE_DIR/profile_canister.wasm -o $WASM_OUT/profile_canister.wasm shrink"
echo "  Running: $SHRINK_CMD"
$SHRINK_CMD

# ----------------------------------------------------------
# Step 3: Copy for factory's include_bytes!
# The factory embeds this WASM via include_bytes! at compile time.
# ----------------------------------------------------------
echo "[3/11] Copying profile_canister WASM for factory embedding..."
cp "$WASM_OUT/profile_canister.wasm" "$PROJECT_ROOT/src/profile_factory/profile_canister_embedded.wasm"

# ----------------------------------------------------------
# Step 4: Build profile_factory (embeds profile_canister WASM)
# ----------------------------------------------------------
echo "[4/11] Building profile_factory..."
cargo build -p profile_factory --target $CARGO_TARGET --release

# ----------------------------------------------------------
# Step 5: Optimise profile_factory WASM
# ----------------------------------------------------------
echo "[5/11] Optimising profile_factory WASM..."
SHRINK_CMD="ic-wasm $RELEASE_DIR/profile_factory.wasm -o $WASM_OUT/profile_factory.wasm shrink"
echo "  Running: $SHRINK_CMD"
$SHRINK_CMD

# ----------------------------------------------------------
# Step 6: Build bulletin_board
# ----------------------------------------------------------
echo "[6/11] Building bulletin_board..."
cargo build -p bulletin_board --target $CARGO_TARGET --release

# ----------------------------------------------------------
# Step 7: Optimise bulletin_board WASM
# ----------------------------------------------------------
echo "[7/11] Optimising bulletin_board WASM..."
SHRINK_CMD="ic-wasm $RELEASE_DIR/bulletin_board.wasm -o $WASM_OUT/bulletin_board.wasm shrink"
echo "  Running: $SHRINK_CMD"
$SHRINK_CMD

# ----------------------------------------------------------
# Step 8: Candid verification on FINAL shipped WASMs
# We do NOT rely on any specific shrink flag to preserve Candid
# metadata. Instead, we verify extraction succeeds on the final
# optimised WASMs. If extraction fails (for any reason, including
# stripped metadata), the build fails.
# ----------------------------------------------------------
echo "[8/11] Verifying Candid interfaces on final shipped WASMs..."

CANDID_OK=true

for CANISTER in profile_canister profile_factory bulletin_board; do
    WASM_FILE="$WASM_OUT/$CANISTER.wasm"
    DID_COMMITTED="$PROJECT_ROOT/src/$CANISTER/$CANISTER.did"
    DID_EXTRACTED="/tmp/${CANISTER}_extracted.did"

    echo "  Checking $CANISTER..."

    # Extract Candid from the final shipped WASM
    if ! candid-extractor "$WASM_FILE" > "$DID_EXTRACTED" 2>/dev/null; then
        echo "  ERROR: candid-extractor failed on $WASM_FILE"
        echo "  This likely means ic-wasm shrink stripped the Candid custom section."
        echo "  The shrink command used was logged above."
        CANDID_OK=false
        continue
    fi

    # Compare with committed .did file
    if ! diff -q "$DID_COMMITTED" "$DID_EXTRACTED" > /dev/null 2>&1; then
        echo "  ERROR: Candid mismatch for $CANISTER"
        echo "  Committed:  $DID_COMMITTED"
        echo "  Extracted:  $DID_EXTRACTED"
        echo "  Diff:"
        diff "$DID_COMMITTED" "$DID_EXTRACTED" || true
        CANDID_OK=false
    else
        echo "  OK: $CANISTER Candid matches"
    fi
done

if [ "$CANDID_OK" = false ]; then
    echo ""
    echo "BUILD FAILED: Candid verification errors (see above)"
    echo "If .did files need updating, copy the extracted versions to src/<canister>/<canister>.did"
    exit 1
fi

# ----------------------------------------------------------
# Step 9: Generate JS IDL factory from profile_canister.did
# This is used by the frontend for dynamic actor construction.
# ----------------------------------------------------------
echo "[9/11] Generating JS IDL factory for profile_canister..."
PROFILE_DID="$PROJECT_ROOT/src/profile_canister/profile_canister.did"
IDL_OUT="$PROJECT_ROOT/src/frontend/src/declarations/profile_canister"
mkdir -p "$IDL_OUT"

# Use didc if available, otherwise skip direct bind generation here
if command -v didc &> /dev/null; then
    didc bind "$PROFILE_DID" --target js > "$IDL_OUT/profile_canister.idl.js"
    echo "  Generated IDL via didc"
else
    # dfx generate will handle declared canisters. profile_canister has deploy:false.
    # If didc is unavailable, skip direct JS bind generation here.
    echo "  Note: didc not found. Skipping direct profile_canister JS bind generation."
    echo "  Use didc or your standard dfx/declarations flow when needed."
fi

# ----------------------------------------------------------
# Step 10: Install frontend dependencies if needed
# ----------------------------------------------------------
echo "[10/11] Building frontend..."
cd "$PROJECT_ROOT/src/frontend"
if [ ! -d "node_modules" ]; then
    echo "  Installing npm dependencies..."
    npm install
fi

# ----------------------------------------------------------
# Step 11: Build frontend
# ----------------------------------------------------------
npm run build
cd "$PROJECT_ROOT"

echo ""
echo "=========================================="
echo "BUILD COMPLETE"
echo "=========================================="
echo "WASM outputs:  $WASM_OUT/"
echo "Frontend dist: src/frontend/dist/"
echo ""
echo "Next: dfx deploy"
