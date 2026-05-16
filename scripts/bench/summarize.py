#!/usr/bin/env python3
"""Summarize a FRI bench run into per-batch metrics.

Joins three artifacts produced by `run_fri_bench.sh`:

  - coordinator_results.json: per-batch handoff/submit timestamps + proof
    size. The wall window between `handed_out_at` and `submitted_at` is the
    coordinator's view of one batch's full prove+verify+submit cycle.
  - gpu_samples.csv: nvidia-smi -lms output. We compute peak VRAM, peak GPU
    util, and average GPU util inside each batch's wall window.
  - host_samples.csv: /proc/<pid>/status snapshots. We take the max VmHWM
    in each batch's window (overall peak RSS-to-date at that moment),
    plus VmPeak (virtual address space high-water).

Usage:
  ./summarize.py <results_dir>
  ./summarize.py <results_dir> --format json   # machine-readable
"""

import argparse
import csv
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Optional


def parse_iso(ts: str) -> Optional[float]:
    """Parse an ISO-8601 timestamp into a Unix epoch float. Returns None on
    failure so callers can drop unparseable rows quietly."""
    ts = ts.strip()
    if not ts:
        return None
    # nvidia-smi default format: "YYYY/MM/DD HH:MM:SS.mmm"
    # docker stats helper: ISO-8601 with millisecond precision and Z suffix.
    for fmt in (
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
    ):
        try:
            return dt.datetime.strptime(ts, fmt).replace(tzinfo=dt.timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def parse_kb(token: str) -> Optional[int]:
    """Parse a kilobyte integer from /proc/<pid>/status (already in KB)."""
    token = token.strip()
    if not token:
        return None
    try:
        return int(token)
    except ValueError:
        return None


def load_gpu(path: Path) -> list[tuple[float, int, int, int]]:
    """Returns rows of (epoch, mem_used_mib, util_gpu_pct, util_mem_pct)."""
    if not path.exists():
        return []
    rows: list[tuple[float, int, int, int]] = []
    with path.open() as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return []
        # nvidia-smi header (with `nounits`): "timestamp, memory.used [MiB], ..."
        # Find indices by substring match so format tweaks don't break us.
        def col(name: str) -> int:
            for idx, h in enumerate(header):
                if name in h.lower():
                    return idx
            return -1

        i_ts = col("timestamp")
        i_mem = col("memory.used")
        i_util_gpu = col("utilization.gpu")
        i_util_mem = col("utilization.memory")
        for row in reader:
            if i_ts < 0 or i_ts >= len(row):
                continue
            epoch = parse_iso(row[i_ts])
            if epoch is None:
                continue
            try:
                mem = int(float(row[i_mem])) if i_mem >= 0 else 0
                ug = int(float(row[i_util_gpu])) if i_util_gpu >= 0 else 0
                um = int(float(row[i_util_mem])) if i_util_mem >= 0 else 0
            except (ValueError, IndexError):
                continue
            rows.append((epoch, mem, ug, um))
    return rows


def load_host(path: Path) -> list[tuple[float, Optional[int], Optional[int], Optional[int]]]:
    """Returns rows of (epoch, vm_rss_kb, vm_peak_kb, vm_hwm_kb)."""
    if not path.exists():
        return []
    rows: list[tuple[float, Optional[int], Optional[int], Optional[int]]] = []
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            epoch = parse_iso(row.get("timestamp_iso", ""))
            if epoch is None:
                continue
            rss = parse_kb(row.get("vm_rss_kb", ""))
            peak = parse_kb(row.get("vm_peak_kb", ""))
            hwm = parse_kb(row.get("vm_hwm_kb", ""))
            rows.append((epoch, rss, peak, hwm))
    return rows


def metrics_in_window(
    gpu_rows: list[tuple[float, int, int, int]],
    host_rows: list[tuple[float, Optional[int], Optional[int], Optional[int]]],
    start: float,
    end: float,
) -> dict:
    """Compute peak/avg metrics from samples that fall in [start, end]."""
    gpu_window = [r for r in gpu_rows if start <= r[0] <= end]
    host_window = [r for r in host_rows if start <= r[0] <= end]

    out: dict = {}
    if gpu_window:
        out["peak_vram_mib"] = max(r[1] for r in gpu_window)
        out["peak_util_gpu_pct"] = max(r[2] for r in gpu_window)
        out["avg_util_gpu_pct"] = round(sum(r[2] for r in gpu_window) / len(gpu_window), 1)
        out["peak_util_mem_pct"] = max(r[3] for r in gpu_window)
        out["gpu_samples"] = len(gpu_window)
    else:
        out["gpu_samples"] = 0

    rss_samples = [r[1] for r in host_window if r[1] is not None]
    peak_samples = [r[2] for r in host_window if r[2] is not None]
    hwm_samples = [r[3] for r in host_window if r[3] is not None]
    if rss_samples:
        out["host_max_rss_kb"] = max(rss_samples)
    if peak_samples:
        out["host_vm_peak_kb"] = max(peak_samples)
    if hwm_samples:
        out["host_vm_hwm_kb"] = max(hwm_samples)
    out["host_samples"] = len(host_window)

    return out


def fmt_mib_from_kb(kb: Optional[int]) -> str:
    if kb is None:
        return "-"
    return f"{kb / 1024:.0f}"


def fmt_secs(s: Optional[float]) -> str:
    if s is None:
        return "-"
    return f"{s:.1f}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results_dir")
    ap.add_argument("--format", choices=("table", "json"), default="table")
    args = ap.parse_args()

    rd = Path(args.results_dir)
    coord_path = rd / "coordinator_results.json"
    gpu_path = rd / "gpu_samples.csv"
    host_path = rd / "host_samples.csv"

    if not coord_path.exists():
        print(f"missing {coord_path}", file=sys.stderr)
        return 1

    with coord_path.open() as f:
        coord = json.load(f)

    gpu_rows = load_gpu(gpu_path)
    host_rows = load_host(host_path)

    rows: list[dict] = []
    for entry in sorted(coord.get("completed", []), key=lambda e: e.get("batch_number", 0)):
        start = entry.get("handed_out_at")
        end = entry.get("submitted_at")
        wall = entry.get("wall_seconds")
        if start is None or end is None:
            continue
        m = metrics_in_window(gpu_rows, host_rows, start, end)
        m["batch_number"] = entry.get("batch_number")
        m["wall_seconds"] = wall
        m["proof_bytes_len"] = entry.get("proof_bytes_len")
        rows.append(m)

    if args.format == "json":
        print(json.dumps({"rows": rows}, indent=2))
        return 0

    if not rows:
        print("no completed batches found")
        return 0

    headers = [
        "batch",
        "wall(s)",
        "peak_vram(MiB)",
        "peak_gpu%",
        "avg_gpu%",
        "host_vm_hwm(MiB)",
        "proof(bytes)",
    ]
    cell_widths = [len(h) for h in headers]

    body: list[list[str]] = []
    for r in rows:
        cells = [
            str(r.get("batch_number", "?")),
            fmt_secs(r.get("wall_seconds")),
            str(r.get("peak_vram_mib", "-")),
            str(r.get("peak_util_gpu_pct", "-")),
            str(r.get("avg_util_gpu_pct", "-")),
            fmt_mib_from_kb(r.get("host_vm_hwm_kb") or r.get("host_max_rss_kb")),
            str(r.get("proof_bytes_len", "-")),
        ]
        body.append(cells)
        for i, c in enumerate(cells):
            cell_widths[i] = max(cell_widths[i], len(c))

    def line(cells: list[str]) -> str:
        return "  ".join(c.rjust(cell_widths[i]) for i, c in enumerate(cells))

    print(line(headers))
    print(line(["-" * w for w in cell_widths]))
    for row in body:
        print(line(row))

    walls = [r["wall_seconds"] for r in rows if r.get("wall_seconds")]
    vrams = [r["peak_vram_mib"] for r in rows if r.get("peak_vram_mib") is not None]
    if walls:
        print()
        print(f"runs={len(rows)}  total_wall={sum(walls):.1f}s  median_wall={sorted(walls)[len(walls)//2]:.1f}s")
        if vrams:
            print(f"peak_vram_overall={max(vrams)} MiB  median_peak_vram={sorted(vrams)[len(vrams)//2]} MiB")

    return 0


if __name__ == "__main__":
    sys.exit(main())
