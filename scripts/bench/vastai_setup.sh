#!/usr/bin/env bash
# Provision a vast.ai box to build and run `eravm-prover-server` from source.
#
# Expects the instance to be launched with a base image like
# `nvidia/cuda:12.9.1-devel-ubuntu22.04` (or any Ubuntu 22.04 with CUDA dev
# tools on PATH). Mirrors the project Dockerfile so the build environment is
# identical to what CI uses.
#
# Total runtime on a 16-core box: ~20-40 min (most of it cargo build).

set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
# Matches the pin in the project Dockerfile.
CARGO_AIRBENDER_REV="${CARGO_AIRBENDER_REV:-6a81afcf992f586256b943ba3241254202de8901}"
# Build for every recent NVIDIA arch — A100 (sm_80), RTX 30xx (sm_86), RTX 40xx
# / RTX 6000 Ada (sm_89), H100 (sm_90), RTX 50xx Blackwell consumer (sm_120).
# Note: sm_120 requires CUDA toolkit >= 12.8. Override if your toolkit is older.
export CUDAARCHS="${CUDAARCHS:-80;86;89;90;120}"

step() { printf '\n== %s ==\n' "$*"; }

step "verifying GPU"
if ! command -v nvidia-smi >/dev/null 2>&1; then
    echo "error: nvidia-smi missing. Launch the vast.ai instance on a CUDA-enabled image." >&2
    exit 1
fi
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv

step "verifying CUDA toolkit"
if ! command -v nvcc >/dev/null 2>&1; then
    echo "error: nvcc missing. Use the CUDA *devel* image (e.g. nvidia/cuda:12.9.1-devel-ubuntu22.04)." >&2
    exit 1
fi
nvcc --version | tail -1

step "installing apt packages"
export DEBIAN_FRONTEND=noninteractive
SUDO=""
if [[ "${EUID}" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    SUDO=sudo
fi
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev clang git ca-certificates curl gpg

step "installing cmake from kitware (need >= 3.28 for airbender gpu-prover)"
if ! command -v cmake >/dev/null 2>&1 || \
   [[ "$(cmake --version | awk 'NR==1{print $3}' | cut -d. -f1-2)" < "3.28" ]]; then
    curl -fsSL https://apt.kitware.com/keys/kitware-archive-latest.asc \
        | $SUDO gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ jammy main" \
        | $SUDO tee /etc/apt/sources.list.d/kitware.list >/dev/null
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends cmake
fi
cmake --version | head -1

step "installing rustup + toolchain pinned in rust-toolchain.toml"
if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain none --profile minimal
fi
# Source the cargo env without reopening the shell.
. "$HOME/.cargo/env"

# rust-toolchain.toml lives at repo root; cargo will install the right channel
# the first time it's invoked there. Trigger it now so the rustup output stays
# in the setup log rather than mixed with build output later.
(cd "$REPO_DIR" && rustc --version)

step "installing rust-src + llvm-tools-preview (needed for guest RISC-V build)"
rustup component add rust-src llvm-tools-preview

step "installing cargo-binutils"
if ! command -v cargo-objcopy >/dev/null 2>&1; then
    cargo install cargo-binutils --locked
fi

step "installing cargo-airbender (pinned rev $CARGO_AIRBENDER_REV)"
if ! command -v cargo-airbender >/dev/null 2>&1; then
    cargo install \
        --git https://github.com/matter-labs/airbender-platform \
        --rev "$CARGO_AIRBENDER_REV" \
        cargo-airbender \
        --no-default-features
fi

step "building guest (RISC-V)"
(cd "$REPO_DIR" && cargo airbender build --project guest)
ls -la "$REPO_DIR/guest/dist/app"

step "building eravm-prover-server (release, GPU prover, CUDAARCHS=$CUDAARCHS)"
(cd "$REPO_DIR" && cargo build --release --locked -p eravm-prover-server)
ls -lh "$REPO_DIR/target/release/eravm-prover-server"

step "done"
echo "next: scripts/bench/run_fri_bench.sh"
