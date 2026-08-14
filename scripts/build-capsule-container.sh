#!/usr/bin/env bash
set -euo pipefail

SHA="$(git rev-parse HEAD)"
test -z "$(git status --short)" || { echo "working tree dirty"; exit 1; }

ARCHIVE="releases/CANDIDATE/capsule-src.tar"
IMAGE="daffydefs-capsule:${SHA}"
CONTAINER="daffydefs-capsule-${SHA}"
OUTPUT_DIR="releases/CANDIDATE/container-output-${SHA}"

git archive --format=tar \
  --add-virtual-file=".capsule-commit:${SHA}" \
  HEAD > "${ARCHIVE}"

docker build \
  --build-arg SOURCE_COMMIT="${SHA}" \
  --tag "${IMAGE}" \
  --file releases/CANDIDATE/Dockerfile \
  releases/CANDIDATE

docker create --name "${CONTAINER}" "${IMAGE}" true >/dev/null
trap 'docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true' EXIT

mkdir -p "${OUTPUT_DIR}"
docker cp "${CONTAINER}:/workspace/target/wasm32-unknown-unknown/release/profile_canister.wasm" \
  "${OUTPUT_DIR}/profile_canister.pre-shrink.wasm"
docker cp "${CONTAINER}:/workspace/wasm_out/profile_canister.wasm" \
  "${OUTPUT_DIR}/profile_canister.wasm"

echo "pre-shrink:  $(sha256sum "${OUTPUT_DIR}/profile_canister.pre-shrink.wasm")"
echo "post-shrink: $(sha256sum "${OUTPUT_DIR}/profile_canister.wasm")"
