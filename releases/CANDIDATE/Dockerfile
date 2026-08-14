FROM --platform=linux/amd64 debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG RUSTUP_VERSION=1.29.0
ARG RUSTUP_INIT_SHA256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
ARG RUST_VERSION=1.97.1
ARG IC_WASM_VERSION=0.11.1
ARG SOURCE_COMMIT

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:/opt/rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin:${PATH}

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

# SOURCE_COMMIT identifies the capsule repository state as a whole. The
# profile-WASM provenance boundary is the profile source, its TAV snapshots,
# lockfile, toolchain, and build recipe; harness, verifier, and documentation
# commits change the capsule identity but never that profile-WASM boundary.
COPY capsule-src.tar /tmp/capsule-src.tar
RUN test -n "${SOURCE_COMMIT}" \
 && tar -xf /tmp/capsule-src.tar -C /workspace \
 && rm /tmp/capsule-src.tar \
 && archive_commit="$(cat .capsule-commit)" \
 && printf 'SOURCE_COMMIT=%s\n.capsule-commit=%s\n' "${SOURCE_COMMIT}" "${archive_commit}" \
 && test "${archive_commit}" = "${SOURCE_COMMIT}"

# Public dependencies are fetched from crates.io under Cargo.lock pins and
# checksums. TAV git sources resolve from the in-repository vendor directory.
RUN cargo fetch --locked

RUN bash scripts/build-profile-repro.sh
