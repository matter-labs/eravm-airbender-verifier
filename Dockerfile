# syntax=docker/dockerfile:1

# ─── Build stage ─────────────────────────────────────────────────────────────
# CUDA 12.9 devel toolchain, kept in lockstep with the 12.9.1-runtime base
# below so the prover server's CUDA runtime requirements match production's
# driver floor. The guest is NOT built here (committed app.bin is used), so we
# skip cargo-airbender and its guest-only extras (rust-src, llvm-tools-preview,
# cargo-binutils) — recipe otherwise mirrors airbender-platform's
# cargo-airbender-cuda image.
FROM nvidia/cuda:12.9.1-devel-ubuntu22.04 AS builder

ARG RUST_TOOLCHAIN=nightly-2026-02-10
ARG CMAKE_VERSION=3.30.2

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:${PATH} \
    CARGO_TERM_COLOR=always

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        curl \
        git \
        libssl-dev \
        lld \
        pkg-config \
        wget && \
    rm -rf /var/lib/apt/lists/*

# gpu_prover's CUDA build via the `cmake` crate needs newer CUDA language
# handling than Ubuntu 22.04's packaged CMake provides.
RUN curl -LO "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.sh" && \
    chmod +x "cmake-${CMAKE_VERSION}-linux-x86_64.sh" && \
    "./cmake-${CMAKE_VERSION}-linux-x86_64.sh" --skip-license --prefix=/usr/local && \
    rm "cmake-${CMAKE_VERSION}-linux-x86_64.sh"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain "${RUST_TOOLCHAIN}"

WORKDIR /workspace
COPY . .

# Step 1: the guest binary (guest/dist/app/app.bin) is committed to the repo and
# picked up by `COPY . .` above. It is built inside the pinned cargo-airbender
# image and refreshed through `/update-vks`, not built here. Guard against a
# context missing the committed binary.
RUN test -f guest/dist/app/app.bin \
    || (echo "ERROR: guest/dist/app/app.bin missing from build context." \
             "It is committed to the repo; refresh it with /update-vks." >&2; exit 1)

# CUDA archs to build for. The gpu_prover default `native` requires a GPU on the
# build host (which CI lacks) and otherwise falls back to an arch < compute_70,
ENV CUDAARCHS="80;89;90;100;120"

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

# Step 3b: also build the host CLI so the runtime image can run `gen-vks`
# (and the other host subcommands) without a separate toolchain. The
# `/update-vks` CI workflow pulls this image and invokes `eravm-prover-host`
# from it, so PR-author code never compiles the binary that produces the
# committed verification keys.
RUN cargo build --release --locked --package eravm-prover-host --features snark_gpu

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
COPY --from=builder /workspace/target/release/eravm-prover-host /usr/local/bin/eravm-prover-host
COPY --from=builder /workspace/guest/dist/app /guest-program
COPY --from=builder /workspace/vks /vks
COPY --from=builder /setup/setup.key /setup/setup.key
COPY --from=builder /bellman-cuda-libs /usr/local/lib/bellman-cuda

# `libbellman-cuda.so` etc. aren't in any default loader path; register them
# via ldconfig so the dynamic linker picks them up without a runtime override.
RUN echo "/usr/local/lib/bellman-cuda" > /etc/ld.so.conf.d/bellman-cuda.conf \
    && ldconfig

ENV PROVER_GUEST_DIST_DIR=/guest-program

# The committed FRI and SNARK verification keys ship with the image. The
# server hard-fails at startup if either file is missing or doesn't match
# the bundled guest binary — it never derives a VK on the fly.
ENV FRI_VK=/vks/fri_vk.bin
ENV SNARK_VK=/vks/snark_vk.json

# Bellman SNARK trusted setup ships with the image. The server fails fast at
# startup if the file is missing; override `SNARK_TRUSTED_SETUP_FILE` only if
# you are mounting it from a different path.
ENV SNARK_TRUSTED_SETUP_FILE=/setup/setup.key

# Default stack size for Rust-spawned threads inside the server process. The
# server's prover thread already sets its own stack size, but inner library
# threads (rayon, etc.) inherit this default. Required because the SNARK
# wrapper's recursion blows past Rust's 2 MB default.
ENV RUST_MIN_STACK=134217728

# Optional Prometheus metrics port
EXPOSE 3000

# SNARK wrapper recursion needs an unbounded stack — see README.md. Wrap the
# binary in a shell so we can raise the soft RLIMIT_STACK before exec'ing it;
# glibc seeds pthread stack sizes from RLIMIT_STACK, so this also reaches the
# prover's worker threads. The container runtime must permit it (`docker run
# --ulimit stack=-1`, or no explicit Kubernetes cap), otherwise the soft limit
# clamps to the hard limit and SNARK proving will still crash.
ENTRYPOINT ["/bin/sh", "-c", "ulimit -s unlimited; exec /usr/local/bin/eravm-prover-server \"$@\"", "--"]
