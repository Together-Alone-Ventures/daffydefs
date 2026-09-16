#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(rustc --version)" == "rustc 1.97.1 "* ]] || { echo "Rust 1.97.1 required" >&2; exit 1; }
[[ "$(ic-wasm --version)" == "ic-wasm 0.11.1" ]] || { echo "ic-wasm 0.11.1 required" >&2; exit 1; }
# Ambient flags can change bytes despite identical committed inputs.
[[ -z "${RUSTFLAGS:-}" && -z "${CARGO_ENCODED_RUSTFLAGS:-}" ]] || { echo "Unset ambient Rust flags" >&2; exit 1; }
PROFILE_TARGET_DIR="${CARGO_TARGET_DIR:-target}"

# Network access is for crates.io public dependencies only. TAV-private git
# sources must resolve from the repository's .cargo/config.toml + vendor/ tree.
# Fail closed if Cargo ever attempts the upstream TAV Git namespace.
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=url.https://tav-private-fetch-forbidden.invalid/.insteadOf
export GIT_CONFIG_VALUE_0=https://github.com/Together-Alone-Ventures/

export RUSTFLAGS="--remap-path-prefix=$(pwd)=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"

cargo build -p profile_canister --target wasm32-unknown-unknown --release --locked
sha256sum "$PROFILE_TARGET_DIR/wasm32-unknown-unknown/release/profile_canister.wasm"

mkdir -p wasm_out
ic-wasm "$PROFILE_TARGET_DIR/wasm32-unknown-unknown/release/profile_canister.wasm" \
  -o wasm_out/profile_canister.wasm shrink
sha256sum wasm_out/profile_canister.wasm
