# syntax=docker/dockerfile:1

# ─── Build stage ─────────────────────────────────────────────────────────────
FROM nvidia/cuda:12.9.1-devel-ubuntu22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# System deps:
#   clang       – required by guest build (CC=clang in guest/.cargo/config.toml)
#   cmake 3.28+ – required by airbender-platform GPU prover (via Kitware APT repo)
#   libssl-dev  – link-time dep for some cargo crates
#   git, curl   – fetch crates from GitHub git sources
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        clang \
        git \
        ca-certificates \
        curl \
        gpg \
    && curl -fsSL https://apt.kitware.com/keys/kitware-archive-latest.asc \
        | gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ jammy main" \
        > /etc/apt/sources.list.d/kitware.list \
    && apt-get update && apt-get install -y --no-install-recommends cmake \
    && cmake --version \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# nightly-2026-02-10 as required by rust-toolchain.toml.
# rust-src + llvm-tools-preview are needed for the guest RISC-V build:
#   - rust-src:            enables -Zbuild-std (std compiled from source for riscv32im-risc0-zkvm-elf)
#   - llvm-tools-preview:  ships the llvm-objcopy binary that cargo-binutils wraps
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain nightly-2026-02-10 --profile minimal \
    && rustup component add rust-src llvm-tools-preview

# cargo-binutils provides the `cargo objcopy` subcommand that cargo-airbender
# invokes to produce app.bin / app.text from the guest ELF.
RUN cargo install cargo-binutils --locked

# Install cargo-airbender at the exact commit pinned in Cargo.lock.
# --no-default-features skips GPU support in the tool itself (only needed for `prove`, not `build`).
RUN cargo install \
        --git https://github.com/matter-labs/airbender-platform \
        --rev 6a81afcf992f586256b943ba3241254202de8901 \
        cargo-airbender \
        --no-default-features

WORKDIR /workspace
COPY . .

# Step 1: build the guest program for RISC-V.
# Produces guest/dist/app/{app.bin,app.elf,app.text,manifest.toml}.
RUN cargo airbender build --project guest

# CUDA archs to build for. The gpu_prover default `native` requires a GPU on the
# build host (which CI lacks) and otherwise falls back to an arch < compute_70,
# breaking `__grid_constant__`. Mirrors airbender-platform's test-gpu CI.
ENV CUDAARCHS="80;89;90"

# Step 2: build the server binary.
RUN cargo build --release --locked --package eravm-prover-server

# Step 3: pre-fetch the bellman SNARK trusted setup so the runtime image ships
# with it already in place. Matches the default URL used by the host CLI's
# `download-trusted-setup` subcommand (CPU; server builds without `snark_gpu`).
# Override via `--build-arg SNARK_TRUSTED_SETUP_URL=...`.
ARG SNARK_TRUSTED_SETUP_URL="https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_2^24.key"
RUN mkdir -p /setup \
    && curl --fail --location --retry 5 --retry-delay 5 \
        "${SNARK_TRUSTED_SETUP_URL}" -o /setup/setup.key

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM nvidia/cuda:12.9.1-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/eravm-prover-server /usr/local/bin/eravm-prover-server
COPY --from=builder /workspace/guest/dist/app /guest-program
COPY --from=builder /setup/setup.key /setup/setup.key

ENV PROVER_GUEST_DIST_DIR=/guest-program

# Bellman SNARK trusted setup ships with the image. The server fails fast at
# startup if the file is missing; override `SNARK_TRUSTED_SETUP_FILE` only if
# you are mounting it from a different path.
ENV SNARK_TRUSTED_SETUP_FILE=/setup/setup.key

# Optional Prometheus metrics port
EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/eravm-prover-server"]
