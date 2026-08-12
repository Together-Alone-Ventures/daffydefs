#!/usr/bin/env bash
set -euo pipefail

# Network access is for crates.io public dependencies only. TAV-private git
# sources must resolve from the repository's .cargo/config.toml + vendor/ tree.
# Fail closed if Cargo ever attempts the upstream TAV Git namespace.
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=url.https://tav-private-fetch-forbidden.invalid/.insteadOf
export GIT_CONFIG_VALUE_0=https://github.com/Together-Alone-Ventures/

cargo build -p profile_canister --target wasm32-unknown-unknown --release --locked
sha256sum target/wasm32-unknown-unknown/release/profile_canister.wasm

mkdir -p wasm_out
ic-wasm target/wasm32-unknown-unknown/release/profile_canister.wasm \
  -o wasm_out/profile_canister.wasm shrink
sha256sum wasm_out/profile_canister.wasm
