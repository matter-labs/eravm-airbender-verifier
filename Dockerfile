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

# Step 2: build era-bellman-cuda. `zksync-crypto-gpu`'s `gpu-ffi` build script
# reads `BELLMAN_CUDA_DIR` from the env when the server is compiled with
# `--features snark_gpu` (forwards to `zkos-wrapper/gpu`). Same recipe as
# `ci-check.yaml::server-integration-build`.
RUN git clone --depth=1 https://github.com/matter-labs/era-bellman-cuda.git /workspace/era-bellman-cuda \
    && cmake -B /workspace/era-bellman-cuda/build -S /workspace/era-bellman-cuda -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /workspace/era-bellman-cuda/build -j"$(nproc)"
ENV BELLMAN_CUDA_DIR=/workspace/era-bellman-cuda

# Step 3: build the server binary with GPU SNARK proving enabled.
RUN cargo build --release --locked --package eravm-prover-server --features snark_gpu

# Step 4: pre-fetch the bellman SNARK trusted setup so the runtime image ships
# with it already in place. GPU build uses `setup_compact.key`. Override via
# `--build-arg SNARK_TRUSTED_SETUP_URL=...`.
ARG SNARK_TRUSTED_SETUP_URL="https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_compact.key"
RUN mkdir -p /setup \
    && curl --fail --location --retry 5 --retry-delay 5 \
        "${SNARK_TRUSTED_SETUP_URL}" -o /setup/setup.key

# Step 5: stage the bellman-cuda shared libraries the runtime needs. The
# runtime base ships libcudart already, but bellman-cuda's own outputs are not
# in any standard path.
RUN mkdir -p /bellman-cuda-libs \
    && find /workspace/era-bellman-cuda/build -type f \( -name '*.so*' -o -name '*.a' \) \
        -exec cp -v {} /bellman-cuda-libs/ \;

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM nvidia/cuda:12.9.1-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/eravm-prover-server /usr/local/bin/eravm-prover-server
COPY --from=builder /workspace/guest/dist/app /guest-program
COPY --from=builder /setup/setup.key /setup/setup.key
COPY --from=builder /bellman-cuda-libs /usr/local/lib/bellman-cuda

# `libbellman-cuda.so` etc. aren't in any default loader path; register them
# via ldconfig so the dynamic linker picks them up without a runtime override.
RUN echo "/usr/local/lib/bellman-cuda" > /etc/ld.so.conf.d/bellman-cuda.conf \
    && ldconfig

ENV PROVER_GUEST_DIST_DIR=/guest-program

# Bellman SNARK trusted setup ships with the image. The server fails fast at
# startup if the file is missing; override `SNARK_TRUSTED_SETUP_FILE` only if
# you are mounting it from a different path.
ENV SNARK_TRUSTED_SETUP_FILE=/setup/setup.key

# Optional Prometheus metrics port
EXPOSE 3000

# SNARK wrapper recursion needs an unbounded stack — see README.md. Wrap the
# binary in a shell so we can raise the soft RLIMIT_STACK before exec'ing it;
# glibc seeds pthread stack sizes from RLIMIT_STACK, so this also reaches the
# prover's worker threads. The container runtime must permit it (`docker run
# --ulimit stack=-1`, or no explicit Kubernetes cap), otherwise the soft limit
# clamps to the hard limit and SNARK proving will still crash.
ENTRYPOINT ["/bin/sh", "-c", "ulimit -s unlimited; exec /usr/local/bin/eravm-prover-server \"$@\"", "--"]
