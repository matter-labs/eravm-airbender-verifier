#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/vast/run-pr17-integration.sh

Environment variables:
  REPO_URL                  Git repository to clone.
                            Default: https://github.com/matter-labs/eravm-airbender-verifier.git
  REPO_REF                  Branch, tag, or commit to test.
                            Default: jack/vast-ai-test-run
  EXPECTED_SHA              Optional exact commit SHA to require after checkout.
  WORKSPACE_DIR             Root work directory on the rented machine.
                            Default: /workspace
  TEST_FILTER               Optional cargo-test filter, e.g. prover_server_proves_fri_then_snark.
                            Default: empty, which runs all ignored integration tests.
  IT_RUN_MULTI_BATCH_FRI_SNARK
                            Set to 1 to run the manual multi-batch fri-snark sizing test.
                            Default: inferred as 1 when TEST_FILTER is prover_server_proves_multi_batch_fri_snark.
  TEST_THREADS              Number of libtest worker threads.
                            Default: 1, because the GPU prover tests are VRAM-exclusive.
  BATCH_FILES               Comma-separated LFS batch files to fetch and pass to integration tests.
                            Default: 506093.bin.gz.
  IT_GENERATE_FRI_FIXTURES  Set to 1 to generate reusable FRI proof fixtures.
                            Default: inferred as 1 when TEST_FILTER is prover_server_generates_fri_fixtures.
  IT_RUN_SNARK_ONLY_REPLAY  Set to 1 to replay FRI fixtures through snark-only mode.
                            Default: inferred as 1 when TEST_FILTER is prover_server_replays_snark_only_fixtures.
  IT_FRI_FIXTURES_DIR       Directory for generated or replayed FRI proof fixtures.
                            Default: /workspace/fri-fixtures.
  IT_FRI_PROOF_TIMEOUT_SECS Timeout for each awaited FRI proof submission.
                            Default: 3600 for FRI fixture generation, otherwise 1200.
  IT_SNARK_PROOF_TIMEOUT_SECS Timeout for each awaited SNARK proof submission.
                            Default: 3600.
  GPU_METRICS_INTERVAL_SECONDS
                            Interval for nvidia-smi sampling into artifacts.
                            Default: 1.
  SNARK_TRUSTED_SETUP_URL   URL for setup_compact.key used by the snark_gpu build.
  FORCE_REBUILD_BELLMAN_CUDA Rebuild era-bellman-cuda even if build outputs exist.
                            Default: 0
  RUST_MIN_STACK            Stack size in bytes for Rust-spawned prover threads.
                            Default: 268435456
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

repo_url="${REPO_URL:-https://github.com/matter-labs/eravm-airbender-verifier.git}"
repo_ref="${REPO_REF:-jack/vast-ai-test-run}"
expected_sha="${EXPECTED_SHA:-}"
workspace_dir="${WORKSPACE_DIR:-/workspace}"
cache_dir="${CACHE_DIR:-$workspace_dir/cache}"
artifacts_root="${ARTIFACTS_DIR:-$workspace_dir/artifacts}"
repo_dir="${REPO_DIR:-$workspace_dir/eravm-airbender-verifier}"
test_filter="${TEST_FILTER:-}"
test_threads="${TEST_THREADS:-1}"
batch_files="${BATCH_FILES:-506093.bin.gz}"
run_multi_batch_fri_snark="${IT_RUN_MULTI_BATCH_FRI_SNARK:-}"
generate_fri_fixtures="${IT_GENERATE_FRI_FIXTURES:-}"
run_snark_only_replay="${IT_RUN_SNARK_ONLY_REPLAY:-}"
fri_fixtures_dir="${IT_FRI_FIXTURES_DIR:-$workspace_dir/fri-fixtures}"
fri_proof_timeout_secs="${IT_FRI_PROOF_TIMEOUT_SECS:-}"
snark_proof_timeout_secs="${IT_SNARK_PROOF_TIMEOUT_SECS:-3600}"
gpu_metrics_interval="${GPU_METRICS_INTERVAL_SECONDS:-1}"
needs_snark_setup="1"
snark_trusted_setup_url="${SNARK_TRUSTED_SETUP_URL:-https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_compact.key}"
bellman_cuda_dir="${BELLMAN_CUDA_DIR:-/opt/era-bellman-cuda}"
force_rebuild_bellman_cuda="${FORCE_REBUILD_BELLMAN_CUDA:-0}"

if [ -z "$run_multi_batch_fri_snark" ] && [ "$test_filter" = "prover_server_proves_multi_batch_fri_snark" ]; then
  run_multi_batch_fri_snark="1"
fi
run_multi_batch_fri_snark="${run_multi_batch_fri_snark:-0}"
if [ -z "$generate_fri_fixtures" ] && [ "$test_filter" = "prover_server_generates_fri_fixtures" ]; then
  generate_fri_fixtures="1"
fi
generate_fri_fixtures="${generate_fri_fixtures:-0}"
if [ -z "$run_snark_only_replay" ] && [ "$test_filter" = "prover_server_replays_snark_only_fixtures" ]; then
  run_snark_only_replay="1"
fi
run_snark_only_replay="${run_snark_only_replay:-0}"
if [ "$test_filter" = "prover_server_generates_fri_fixtures" ] && [ "$generate_fri_fixtures" = "1" ]; then
  needs_snark_setup="0"
fi
if [ -z "$fri_proof_timeout_secs" ]; then
  if [ "$generate_fri_fixtures" = "1" ]; then
    fri_proof_timeout_secs="3600"
  else
    fri_proof_timeout_secs="1200"
  fi
fi

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_dir="$artifacts_root/$run_id"
mkdir -p "$artifact_dir" "$cache_dir"

exec > >(tee -a "$artifact_dir/run.log") 2>&1

log_step() {
  printf '\n[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

run() {
  log_step "$*"
  "$@"
}

gpu_samples_file="$artifact_dir/gpu-samples.csv"
gpu_process_samples_file="$artifact_dir/gpu-process-samples.csv"
gpu_summary_file="$artifact_dir/gpu-summary.txt"
gpu_sampler_pid=""

start_gpu_metrics_sampler() {
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    log_step "nvidia-smi not found; GPU metrics sampling disabled"
    return
  fi

  {
    echo "sample_utc,index,name,gpu_util_pct,mem_util_pct,memory_used_mib,memory_total_mib,power_w,temp_c"
  } > "$gpu_samples_file"
  {
    echo "sample_utc,pid,process_name,used_memory_mib"
  } > "$gpu_process_samples_file"

  (
    while true; do
      sample_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      nvidia-smi \
        --query-gpu=index,name,utilization.gpu,utilization.memory,memory.used,memory.total,power.draw,temperature.gpu \
        --format=csv,noheader,nounits 2>/dev/null \
        | awk -v sample_utc="$sample_utc" -F', ' '{print sample_utc "," $0}' \
        >> "$gpu_samples_file" || true

      nvidia-smi \
        --query-compute-apps=pid,process_name,used_memory \
        --format=csv,noheader,nounits 2>/dev/null \
        | awk -v sample_utc="$sample_utc" -F', ' '{print sample_utc "," $0}' \
        >> "$gpu_process_samples_file" || true

      sleep "$gpu_metrics_interval"
    done
  ) &
  gpu_sampler_pid="$!"
  log_step "Started GPU metrics sampler pid=$gpu_sampler_pid interval=${gpu_metrics_interval}s"
}

stop_gpu_metrics_sampler() {
  if [ -n "$gpu_sampler_pid" ] && kill -0 "$gpu_sampler_pid" >/dev/null 2>&1; then
    kill "$gpu_sampler_pid" >/dev/null 2>&1 || true
    wait "$gpu_sampler_pid" >/dev/null 2>&1 || true
  fi
}

summarize_gpu_metrics() {
  if [ ! -s "$gpu_samples_file" ]; then
    return
  fi

  awk -F',' '
    NR > 1 {
      for (i = 1; i <= NF; i++) {
        gsub(/^ +| +$/, "", $i)
      }
      used = $6 + 0
      if (used > max_used) {
        max_used = used
        max_ts = $1
        max_gpu = $2
        max_name = $3
        max_gpu_util = $4
        max_mem_util = $5
        max_total = $7
        max_power = $8
        max_temp = $9
      }
    }
    END {
      if (NR <= 1) {
        print "gpu_samples=0"
      } else {
        print "max_memory_used_mib=" max_used
        print "memory_total_mib=" max_total
        print "max_memory_sample_utc=" max_ts
        print "gpu_index=" max_gpu
        print "gpu_name=" max_name
        print "gpu_util_at_max_memory_pct=" max_gpu_util
        print "mem_util_at_max_memory_pct=" max_mem_util
        print "power_at_max_memory_w=" max_power
        print "temp_at_max_memory_c=" max_temp
      }
    }
  ' "$gpu_samples_file" > "$gpu_summary_file"

  echo "GPU metrics summary:"
  cat "$gpu_summary_file"
}

cleanup() {
  status="$?"
  set +e
  stop_gpu_metrics_sampler
  summarize_gpu_metrics
  exit "$status"
}

trap cleanup EXIT

detect_cuda_arch() {
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    return 1
  fi

  local compute_cap
  compute_cap="$(
    nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null \
      | head -n1 \
      | tr -d '[:space:].'
  )"

  if [[ "$compute_cap" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$compute_cap"
    return 0
  fi

  return 1
}

ensure_bellman_cuda() {
  if [ ! -d "$bellman_cuda_dir" ]; then
    run git clone --depth=1 https://github.com/matter-labs/era-bellman-cuda.git "$bellman_cuda_dir"
  fi

  if [ "$force_rebuild_bellman_cuda" != "1" ] && [ -d "$bellman_cuda_dir/build" ]; then
    log_step "Reusing existing era-bellman-cuda build at $bellman_cuda_dir/build"
    return
  fi

  if [ "$force_rebuild_bellman_cuda" = "1" ]; then
    rm -rf "$bellman_cuda_dir/build"
  fi

  run cmake \
    -B "$bellman_cuda_dir/build" \
    -S "$bellman_cuda_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CUDA_ARCHITECTURES="$CUDAARCHS"
  run cmake --build "$bellman_cuda_dir/build" -j"$(nproc)"
}

export_bellman_cuda_libs() {
  if [ ! -d "$bellman_cuda_dir/build" ]; then
    return
  fi

  local lib_dirs
  lib_dirs="$(
    find "$bellman_cuda_dir/build" -type f -name '*.so*' -exec dirname {} \; \
      | sort -u \
      | paste -sd: -
  )"

  if [ -n "$lib_dirs" ]; then
    export LD_LIBRARY_PATH="$lib_dirs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi
}

log_step "Starting Vast PR integration run"
echo "Run ID: $run_id"
echo "Repository: $repo_url"
echo "Ref: $repo_ref"
echo "Workspace: $workspace_dir"
echo "Artifacts: $artifact_dir"

start_gpu_metrics_sampler

export PATH="/usr/local/cargo/bin:/usr/local/cuda/bin:$PATH"
export CARGO_HOME="${CARGO_HOME:-$cache_dir/cargo-home}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$cache_dir/cargo-target}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export RUST_LOG="${RUST_LOG:-info}"
export RUST_MIN_STACK="${RUST_MIN_STACK:-268435456}"
export BELLMAN_CUDA_DIR="$bellman_cuda_dir"

if [ -z "${CUDAARCHS:-}" ]; then
  detected_arch="$(detect_cuda_arch || true)"
  if [ -n "$detected_arch" ]; then
    export CUDAARCHS="$detected_arch"
  else
    export CUDAARCHS="89"
  fi
fi
export CUDA_ARCH="${CUDA_ARCH:-$CUDAARCHS}"

log_step "Environment diagnostics"
nvidia-smi || true
nvcc --version || true
rustc --version
cargo --version
cmake --version
git --version
git lfs version
echo "CUDAARCHS=$CUDAARCHS"
echo "CUDA_ARCH=$CUDA_ARCH"
echo "BELLMAN_CUDA_DIR=$BELLMAN_CUDA_DIR"
echo "RUST_MIN_STACK=$RUST_MIN_STACK"
df -h
free -h || true
ulimit -s 300000 || true

ensure_bellman_cuda
export_bellman_cuda_libs
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}"

if [ ! -d "$repo_dir/.git" ]; then
  rm -rf "$repo_dir"
  run git clone "$repo_url" "$repo_dir"
fi

cd "$repo_dir"

run git remote set-url origin "$repo_url"
run git fetch origin --prune
if git show-ref --verify --quiet "refs/remotes/origin/$repo_ref"; then
  run git checkout --force -B "$repo_ref" "origin/$repo_ref"
else
  run git checkout --force "$repo_ref"
fi

actual_sha="$(git rev-parse HEAD)"
echo "Checked out SHA: $actual_sha"
if [ -n "$expected_sha" ] && [ "$actual_sha" != "$expected_sha" ]; then
  echo "error: expected SHA $expected_sha but checked out $actual_sha" >&2
  exit 1
fi

run git lfs install --local
run ./scripts/fetch_lfs_batches.sh "$batch_files"

setup_key="${IT_SNARK_TRUSTED_SETUP:-$cache_dir/setup_compact.key}"
if [ "$needs_snark_setup" = "1" ] && [ ! -s "$setup_key" ]; then
  run curl -fL --retry 5 --retry-delay 5 -o "$setup_key" "$snark_trusted_setup_url"
fi
if [ "$needs_snark_setup" = "1" ]; then
  ls -lh "$setup_key"
else
  log_step "Skipping SNARK trusted setup download for FRI-only fixture generation"
fi

log_step "Build Airbender guest"
run cargo airbender build --project guest

log_step "Build prover server binary"
run cargo build --release --locked --features snark_gpu --package eravm-prover-server

log_step "Build integration test binary"
run cargo test --release --locked --features snark_gpu \
  --package eravm-prover-server \
  --test integration_test \
  --no-run

test_cmd=(
  cargo test --release --locked --features snark_gpu
  --package eravm-prover-server
  --test integration_test
)

if [ -n "$test_filter" ]; then
  test_cmd+=("$test_filter")
fi

test_cmd+=(-- --ignored --nocapture "--test-threads=$test_threads")

log_step "Run ignored integration tests"
echo "IT_SNARK_TRUSTED_SETUP=$setup_key"
echo "IT_GUEST_DIST_DIR=$repo_dir/guest/dist/app"
echo "IT_BATCHES_DIR=$repo_dir/testdata/era_mainnet_batches/binary"
echo "IT_BATCH_FILES=$batch_files"
echo "IT_RUN_MULTI_BATCH_FRI_SNARK=$run_multi_batch_fri_snark"
echo "IT_GENERATE_FRI_FIXTURES=$generate_fri_fixtures"
echo "IT_RUN_SNARK_ONLY_REPLAY=$run_snark_only_replay"
echo "IT_FRI_FIXTURES_DIR=$fri_fixtures_dir"
echo "IT_FRI_PROOF_TIMEOUT_SECS=$fri_proof_timeout_secs"
echo "IT_SNARK_PROOF_TIMEOUT_SECS=$snark_proof_timeout_secs"
echo "Command: ${test_cmd[*]}"

IT_SNARK_TRUSTED_SETUP="$setup_key" \
IT_GUEST_DIST_DIR="$repo_dir/guest/dist/app" \
IT_BATCHES_DIR="$repo_dir/testdata/era_mainnet_batches/binary" \
IT_BATCH_FILES="$batch_files" \
IT_RUN_MULTI_BATCH_FRI_SNARK="$run_multi_batch_fri_snark" \
IT_GENERATE_FRI_FIXTURES="$generate_fri_fixtures" \
IT_RUN_SNARK_ONLY_REPLAY="$run_snark_only_replay" \
IT_FRI_FIXTURES_DIR="$fri_fixtures_dir" \
IT_FRI_PROOF_TIMEOUT_SECS="$fri_proof_timeout_secs" \
IT_SNARK_PROOF_TIMEOUT_SECS="$snark_proof_timeout_secs" \
"${test_cmd[@]}"

if [ -d "$fri_fixtures_dir" ]; then
  fixture_archive="$artifact_dir/fri-fixtures.tar.gz"
  log_step "Archive FRI fixtures"
  tar -C "$fri_fixtures_dir" -czf "$fixture_archive" .
  ls -lh "$fixture_archive"
fi

log_step "Finished successfully"
git status --short
df -h
echo "Artifacts written to: $artifact_dir"
