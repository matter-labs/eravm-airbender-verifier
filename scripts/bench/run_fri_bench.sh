#!/usr/bin/env bash
# Orchestrates a FRI proving benchmark on a vast.ai box.
#
# Pipeline:
#   1. Coordinator (Python) is started and queues every proof_inputs_*.json
#      from $CORPUS_DIR. Streams batches one at a time as the server polls.
#   2. eravm-prover-server (built natively by vastai_setup.sh) is launched
#      with --server-url=http://127.0.0.1:$COORDINATOR_PORT.
#   3. Background sampler captures nvidia-smi + /proc/<pid>/status every
#      250 ms / 1 s.
#   4. Wait until the coordinator marks every queued batch as completed,
#      then SIGINT the server and samplers cleanly.
#
# Output (under $RESULTS_DIR):
#   context.txt
#   coordinator.log, coordinator_results.json
#   prover.log
#   gpu_samples.csv, host_samples.csv

set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

CORPUS_DIR="${CORPUS_DIR:-${PWD}/bench-corpus}"
RESULTS_DIR="${RESULTS_DIR:-${PWD}/bench-results/$(date -u +%Y%m%dT%H%M%SZ)}"
VK_CACHE_DIR="${VK_CACHE_DIR:-${PWD}/vk-cache}"
PROVER_BIN="${PROVER_BIN:-$REPO_DIR/target/release/eravm-prover-server}"
GUEST_DIST="${GUEST_DIST:-$REPO_DIR/guest/dist/app}"
COORDINATOR_PORT="${COORDINATOR_PORT:-8080}"
POLL_INTERVAL_MS="${POLL_INTERVAL_MS:-250}"
METRICS_PORT="${METRICS_PORT:-3000}"
MAX_WAIT_SECS="${MAX_WAIT_SECS:-14400}"   # 4 hours

if [[ ! -x "$PROVER_BIN" ]]; then
    echo "error: prover binary not built ($PROVER_BIN)." >&2
    echo "       run scripts/bench/vastai_setup.sh first." >&2
    exit 1
fi
if [[ ! -d "$GUEST_DIST" ]]; then
    echo "error: guest dist missing ($GUEST_DIST)." >&2
    exit 1
fi
if [[ ! -d "$CORPUS_DIR" ]]; then
    echo "error: corpus directory $CORPUS_DIR missing." >&2
    echo "       run scripts/bench/prepare_local.sh locally and upload the result." >&2
    exit 1
fi

shopt -s nullglob
batch_files=("$CORPUS_DIR"/proof_inputs_*.json)
if [[ ${#batch_files[@]} -eq 0 ]]; then
    echo "error: no proof_inputs_*.json under $CORPUS_DIR" >&2
    exit 1
fi
n_batches=${#batch_files[@]}

mkdir -p "$RESULTS_DIR" "$VK_CACHE_DIR"
echo "[bench] results dir: $RESULTS_DIR"
echo "[bench] queued batches: $n_batches"

# Capture immutable environment context so a result file is self-describing.
{
    echo "== GPU =="
    nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv 2>&1 || true
    echo
    echo "== prover binary =="
    file "$PROVER_BIN" 2>&1 || true
    "$PROVER_BIN" --version 2>&1 || true
    echo
    echo "== host =="
    uname -a
    echo "cpu_count=$(nproc 2>/dev/null || echo unknown)"
    echo "mem_total_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo unknown)"
    echo
    echo "== git =="
    (cd "$REPO_DIR" && git rev-parse HEAD 2>&1 || true)
    (cd "$REPO_DIR" && git status --short 2>&1 || true)
} > "$RESULTS_DIR/context.txt"

PROVER_PID=""
COORDINATOR_PID=""
SAMPLER_PID=""

cleanup() {
    set +e
    echo "[bench] cleanup..."
    if [[ -n "$PROVER_PID" ]]; then
        # SIGINT gives the server a chance to flush metrics and exit cleanly
        # (see the ctrlc handler in server/src/main.rs).
        kill -INT "$PROVER_PID" 2>/dev/null
        # Bounded wait so we don't hang here if the prover is stuck.
        for _ in $(seq 1 30); do
            kill -0 "$PROVER_PID" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "$PROVER_PID" 2>/dev/null
        wait "$PROVER_PID" 2>/dev/null
    fi
    if [[ -n "$SAMPLER_PID" ]]; then
        kill -TERM "$SAMPLER_PID" 2>/dev/null
        wait "$SAMPLER_PID" 2>/dev/null
    fi
    if [[ -n "$COORDINATOR_PID" ]]; then
        kill -INT "$COORDINATOR_PID" 2>/dev/null
        wait "$COORDINATOR_PID" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

echo "[bench] starting coordinator on :$COORDINATOR_PORT"
python3 "$SCRIPT_DIR/coordinator.py" \
    --batches-dir "$CORPUS_DIR" \
    --port "$COORDINATOR_PORT" \
    --results "$RESULTS_DIR/coordinator_results.json" \
    > "$RESULTS_DIR/coordinator.log" 2>&1 &
COORDINATOR_PID=$!

for _ in $(seq 1 50); do
    if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1', $COORDINATOR_PORT))==0 else 1)" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

echo "[bench] starting prover"
# The VK cache is written to CWD; switch in so it lands in $VK_CACHE_DIR.
# ulimit -s required by airbender; matches CI workflow.
(
    cd "$VK_CACHE_DIR"
    ulimit -s 300000
    RUST_BACKTRACE=1 RUST_LOG="${RUST_LOG:-info}" \
        PROVER_GUEST_DIST_DIR="$GUEST_DIST" \
        "$PROVER_BIN" \
            --server-url "http://127.0.0.1:$COORDINATOR_PORT" \
            --poll-interval-ms "$POLL_INTERVAL_MS" \
            --metrics-port "$METRICS_PORT" \
        > "$RESULTS_DIR/prover.log" 2>&1
) &
PROVER_PID=$!

# Wait until the prover writes its first log line (means tracing is up and
# the FRI pipeline has at least started initializing) before starting the
# sampler — otherwise the very first sample includes pre-launch noise.
for _ in $(seq 1 50); do
    [[ -s "$RESULTS_DIR/prover.log" ]] && break
    kill -0 "$PROVER_PID" 2>/dev/null || { echo "prover exited before producing output" >&2; exit 1; }
    sleep 0.1
done

echo "[bench] starting sampler (pid=$PROVER_PID)"
bash "$SCRIPT_DIR/sample_metrics.sh" "$RESULTS_DIR" "$PROVER_PID" \
    > "$RESULTS_DIR/sampler.log" 2>&1 &
SAMPLER_PID=$!

echo "[bench] waiting for $n_batches batches to complete (max ${MAX_WAIT_SECS}s)..."
deadline=$(( $(date +%s) + MAX_WAIT_SECS ))
last_completed=-1
while true; do
    if (( $(date +%s) >= deadline )); then
        echo "[bench] deadline reached, aborting" >&2
        break
    fi

    completed_count=0
    if [[ -f "$RESULTS_DIR/coordinator_results.json" ]]; then
        completed_count=$(python3 -c "
import json
try:
    with open('$RESULTS_DIR/coordinator_results.json') as f:
        d = json.load(f)
    print(len(d.get('completed', [])))
except Exception:
    print(0)
")
    fi

    if [[ "$completed_count" -ne "$last_completed" ]]; then
        echo "[bench] progress: $completed_count / $n_batches"
        last_completed=$completed_count
    fi

    if [[ "$completed_count" -ge "$n_batches" ]]; then
        echo "[bench] all batches completed"
        break
    fi

    if ! kill -0 "$PROVER_PID" 2>/dev/null; then
        echo "[bench] prover exited unexpectedly; see prover.log" >&2
        break
    fi

    sleep 5
done

echo
echo "[bench] artifacts:"
ls -lh "$RESULTS_DIR"
echo
echo "next: ./summarize.py $RESULTS_DIR"
