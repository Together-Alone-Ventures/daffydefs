FROM --platform=linux/amd64 debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG RUSTUP_VERSION=1.29.0
ARG RUSTUP_INIT_SHA256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
ARG RUST_VERSION=1.97.1
ARG IC_WASM_VERSION=0.11.1
ARG SOURCE_COMMIT=c0fbb14f885896ed9d34871b108252702dbf8e62
ARG SOURCE_SNAPSHOT_SHA256=e3c6aa50350adcc411dbc055dbba2ec831d0d3a99ffe5a1b4d4a93bd211dfe12

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:/opt/rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin:${PATH} \
    CARGO_INCREMENTAL=0 \
    SOURCE_DATE_EPOCH=1785665049

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git build-essential pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
 && echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
 && rm /tmp/rustup-init \
 && rustup target add wasm32-unknown-unknown --toolchain "${RUST_VERSION}" \
 && rustc --version --verbose \
 && cargo --version --verbose

RUN cargo install ic-wasm --version "${IC_WASM_VERSION}" --locked \
 && ic-wasm --version

WORKDIR /workspace

# The embedded commit marker is the source identity. The deterministic archive
# digest verifies packaging transport integrity; the tarball is not provenance.
COPY source-snapshot.tar.gz /tmp/source-snapshot.tar.gz
RUN echo "${SOURCE_SNAPSHOT_SHA256}  /tmp/source-snapshot.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/source-snapshot.tar.gz -C /workspace \
 && rm /tmp/source-snapshot.tar.gz \
 && test "$(cat .baseline-source-commit)" = "${SOURCE_COMMIT}"

ENV RUSTFLAGS="--remap-path-prefix=/workspace=. --remap-path-prefix=/opt/cargo=/cargo"

# Public dependencies are fetched from crates.io under Cargo.lock pins and
# checksums. TAV git sources resolve from the in-repository vendor directory.
RUN cargo fetch --locked

RUN cargo build -p profile_canister --target wasm32-unknown-unknown --release --locked \
 && sha256sum target/wasm32-unknown-unknown/release/profile_canister.wasm | tee /pre-shrink.sha256 \
 && mkdir -p wasm_out \
 && ic-wasm target/wasm32-unknown-unknown/release/profile_canister.wasm \
      -o wasm_out/profile_canister.wasm shrink \
 && sha256sum wasm_out/profile_canister.wasm | tee /module.sha256

# RUN echo "<CANDIDATE_MODULE_SHA256>  wasm_out/profile_canister.wasm" | sha256sum -c -
