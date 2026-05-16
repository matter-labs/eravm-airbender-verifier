#!/usr/bin/env bash
# Background sampler for GPU and host process metrics.
#
# Writes two CSVs into $OUT_DIR:
#   gpu_samples.csv  — nvidia-smi every 250ms (header row from nvidia-smi)
#   host_samples.csv — proc-status snapshot every 1s
#
# host_samples columns: timestamp_iso, vm_rss_kb, vm_peak_kb, vm_hwm_kb, threads
#   VmRSS  — current resident set size
#   VmHWM  — high-water mark of RSS (lifetime peak of physical memory)
#   VmPeak — high-water mark of virtual address space
#
# Both samplers exit cleanly on SIGTERM.

set -euo pipefail

OUT_DIR="${1:?usage: sample_metrics.sh <out_dir> <prover_pid>}"
PID="${2:?usage: sample_metrics.sh <out_dir> <prover_pid>}"
GPU_INTERVAL_MS="${GPU_INTERVAL_MS:-250}"
HOST_INTERVAL_S="${HOST_INTERVAL_S:-1}"

mkdir -p "$OUT_DIR"
gpu_csv="$OUT_DIR/gpu_samples.csv"
host_csv="$OUT_DIR/host_samples.csv"

nvidia-smi \
    --query-gpu=timestamp,memory.used,utilization.gpu,utilization.memory,temperature.gpu,power.draw \
    --format=csv,nounits \
    -lms "$GPU_INTERVAL_MS" \
    > "$gpu_csv" &
gpu_pid=$!

{
    echo "timestamp_iso,vm_rss_kb,vm_peak_kb,vm_hwm_kb,threads"
    while true; do
        # Stop sampling when the target process is gone — otherwise we'd spin
        # writing blank rows forever.
        if [[ ! -d "/proc/$PID" ]]; then
            break
        fi
        ts=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
        # Use a single read of /proc/<pid>/status; awk extracts the fields we
        # want. If the process exits mid-read awk produces blanks, which is
        # fine — summarize.py treats those as "no sample".
        eval "$(awk '
            /^VmRSS:/  { printf "rss=%s\n", $2 }
            /^VmPeak:/ { printf "peak=%s\n", $2 }
            /^VmHWM:/  { printf "hwm=%s\n", $2 }
            /^Threads:/{ printf "threads=%s\n", $2 }
        ' /proc/$PID/status 2>/dev/null)" || true
        echo "${ts},${rss:-},${peak:-},${hwm:-},${threads:-}"
        sleep "$HOST_INTERVAL_S"
    done
} > "$host_csv" &
host_pid=$!

cleanup() {
    kill "$gpu_pid" "$host_pid" 2>/dev/null || true
    wait "$gpu_pid" "$host_pid" 2>/dev/null || true
}
trap cleanup TERM INT EXIT

# Block until either sampler exits or we get a signal.
wait "$gpu_pid" "$host_pid"
