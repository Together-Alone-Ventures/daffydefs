#!/usr/bin/env bash
set -euo pipefail

STEP=0
on_error() {
  local exit_code=$?
  echo ""
  echo "ERROR: Step ${STEP} failed. Aborting." >&2
  exit "$exit_code"
}
trap on_error ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CARGO_TARGET="wasm32-unknown-unknown"
RELEASE_DIR="$ROOT_DIR/target/${CARGO_TARGET}/release"
WASM_OUT_DIR="$ROOT_DIR/wasm_out"
LOCKFILE="$ROOT_DIR/Cargo.lock"
PROFILE_EMBED_PATH="$ROOT_DIR/src/profile_factory/profile_canister_embedded.wasm"

mkdir -p "$WASM_OUT_DIR"

echo "[INFO] Root: $ROOT_DIR"

echo ""
STEP=1
echo "Step ${STEP}: dfx stop (safe no-op if not running)"
if ! dfx stop; then
  echo "[INFO] dfx stop returned non-zero; continuing as safe no-op."
fi

echo ""
STEP=2
echo "Step ${STEP}: dfx start --clean --background"
dfx start --clean --background

echo ""
STEP=3
echo "Step ${STEP}: cargo update (authoritative lockfile)"
cargo update --manifest-path "$ROOT_DIR/Cargo.toml"
echo "Updated lockfile(s):"
echo "- $LOCKFILE"

echo ""
STEP=4
echo "Step ${STEP}: cargo clean for profile_canister"
cargo clean -p profile_canister --manifest-path "$ROOT_DIR/Cargo.toml"

echo ""
STEP=5
echo "Step ${STEP}: build profile_canister WASM (project command)"
cargo build -p profile_canister --target "$CARGO_TARGET" --release

PROFILE_BUILD_TMP="$WASM_OUT_DIR/profile_canister.built.wasm"
ic-wasm "$RELEASE_DIR/profile_canister.wasm" -o "$PROFILE_BUILD_TMP" shrink

echo ""
STEP=6
echo "Step ${STEP}: copy profile_canister WASM to embed path and wasm_out"
cp "$PROFILE_BUILD_TMP" "$PROFILE_EMBED_PATH"
cp "$PROFILE_BUILD_TMP" "$WASM_OUT_DIR/profile_canister.wasm"
echo "Destination (a): $PROFILE_EMBED_PATH"
echo "Destination (b): $WASM_OUT_DIR/profile_canister.wasm"

echo ""
STEP=7
echo "Step ${STEP}: compute PROFILE_WASM_HASH"
PROFILE_WASM_HASH="$(sha256sum "$WASM_OUT_DIR/profile_canister.wasm" | awk '{print $1}')"
echo "PROFILE_WASM_HASH=$PROFILE_WASM_HASH"

echo ""
STEP=8
echo "Step ${STEP}: cargo clean for profile_factory"
cargo clean -p profile_factory --manifest-path "$ROOT_DIR/Cargo.toml"

echo ""
STEP=9
echo "Step ${STEP}: build profile_factory WASM"
cargo build -p profile_factory --target "$CARGO_TARGET" --release

echo ""
STEP=10
echo "Step ${STEP}: copy profile_factory WASM to wasm_out/profile_factory.wasm"
cp "$RELEASE_DIR/profile_factory.wasm" "$WASM_OUT_DIR/profile_factory.wasm"

echo ""
STEP=11
echo "Step ${STEP}: sha256sum wasm_out/profile_factory.wasm"
sha256sum "$WASM_OUT_DIR/profile_factory.wasm"

echo ""
STEP=12
echo "Step ${STEP}: reinstall profile_factory from explicit wasm_out artifact"
dfx canister install profile_factory --mode reinstall --wasm "$WASM_OUT_DIR/profile_factory.wasm"

echo ""
STEP=13
echo "Step ${STEP}: checkpoint"
echo "CHECKPOINT: Factory deployed. Embedded profile WASM sha256: ${PROFILE_WASM_HASH}."
echo "Any profile canister spawned from this point forward runs the new code."
echo "Do not reuse a profile canister created before this deployment."
echo "Proceed to tools/validate_record_id_local.md"

rm -f "$PROFILE_BUILD_TMP"
