#!/usr/bin/env python3
"""Mock job coordinator for `eravm-prover-server` benchmarking.

The real prover deployment polls a coordinator that hands out
`AirbenderVerifierInput` JSON payloads via `POST /airbender/proof_inputs`
and accepts proofs via `POST /airbender/submit_proofs`. This script
mimics that minimum protocol surface so we can replay the user's
captured `proof_inputs_*.json` files through an unmodified server
binary.

Usage:
    python3 coordinator.py \\
        --batches-dir /path/to/proof_inputs \\
        --port 8080 \\
        --results coordinator_results.json

The script writes `coordinator_results.json` on shutdown (SIGINT/SIGTERM)
with per-batch handoff and submission timestamps, which the benchmark
summarizer joins with GPU/host samples.

Implementation note: stdlib only. The proof inputs are ~100 MiB each,
so we stream both the response body and the submission body without
buffering the full payload into Python memory.
"""

import argparse
import json
import os
import re
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_BATCH_NUMBER_RE = re.compile(r"(\d+)")

# Wrap bare `V1AirbenderVerifierInput` payloads into the externally-tagged
# enum the server expects. Toggled via `--no-wrap-v1` if the corpus already
# ships in `{"V1": {…}}` shape.
WRAP_PREFIX = b'{"V1":'
WRAP_SUFFIX = b"}"
WRAP_V1 = True

_state_lock = threading.Lock()
_pending: list[Path] = []
_inflight: dict[int, dict] = {}
_completed: list[dict] = []


def parse_batch_number(path: Path) -> int:
    match = _BATCH_NUMBER_RE.search(path.name)
    if not match:
        raise ValueError(f"no batch number in filename {path.name}")
    return int(match.group(1))


def now() -> float:
    return time.time()


class Handler(BaseHTTPRequestHandler):
    # Default BaseHTTPRequestHandler logs every request to stderr in apache
    # format. Mute it; we emit our own structured lines.
    def log_message(self, fmt, *args):
        return

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _drain_body(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 16))
            if not chunk:
                break
            remaining -= len(chunk)

    def do_POST(self):
        if self.path == "/airbender/proof_inputs":
            self._handle_fetch()
        elif self.path == "/airbender/submit_proofs":
            self._handle_submit()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _handle_fetch(self):
        self._drain_body()

        with _state_lock:
            if not _pending:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            path = _pending.pop(0)
            batch_number = parse_batch_number(path)
            handed_at = now()
            _inflight[batch_number] = {
                "handed_out_at": handed_at,
                "path": str(path),
            }

        # The captured `proof_inputs_*.json` files are bare
        # `V1AirbenderVerifierInput` payloads (top-level keys: `vm_run_data`,
        # `l1_batch_env`, …). The current `eravm-prover-server` expects the
        # externally-tagged enum wrapper `{"V1": {…}}`. We stream-wrap on the
        # way out so the captured corpus stays untouched on disk.
        prefix = WRAP_PREFIX if WRAP_V1 else b""
        suffix = WRAP_SUFFIX if WRAP_V1 else b""
        size = path.stat().st_size + len(prefix) + len(suffix)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        try:
            if prefix:
                self.wfile.write(prefix)
            with path.open("rb") as src:
                while True:
                    chunk = src.read(1 << 16)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            if suffix:
                self.wfile.write(suffix)
        except (BrokenPipeError, ConnectionResetError):
            sys.stderr.write(
                f"[coordinator] client disconnected mid-stream for batch {batch_number}\n"
            )
            with _state_lock:
                _inflight.pop(batch_number, None)
                _pending.insert(0, path)
            return
        sys.stderr.write(
            f"[coordinator] handed out batch {batch_number} ({size} bytes, wrap_v1={WRAP_V1})\n"
        )
        sys.stderr.flush()

    def _handle_submit(self):
        raw = self._read_body()
        try:
            payload = json.loads(raw)
        except Exception as err:
            sys.stderr.write(f"[coordinator] bad submission JSON: {err}\n")
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        batch_number = int(payload.get("l1_batch_number", -1))
        proof_hex = payload.get("proof", "")
        # proof is hex-encoded; halve to bytes.
        proof_bytes_len = len(proof_hex) // 2
        prover_id = payload.get("prover_id", "")

        with _state_lock:
            entry = _inflight.pop(batch_number, None)
            handed_at = entry.get("handed_out_at") if entry else None
            submitted_at = now()
            _completed.append({
                "batch_number": batch_number,
                "handed_out_at": handed_at,
                "submitted_at": submitted_at,
                "wall_seconds": (submitted_at - handed_at) if handed_at else None,
                "proof_bytes_len": proof_bytes_len,
                "prover_id": prover_id,
            })

        sys.stderr.write(
            f"[coordinator] received proof for batch {batch_number} ({proof_bytes_len} bytes)\n"
        )
        sys.stderr.flush()

        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def write_results(results_path: Path) -> None:
    with _state_lock:
        snapshot = {
            "completed": list(_completed),
            "remaining_in_queue": [str(p) for p in _pending],
            "still_inflight": {str(k): v for k, v in _inflight.items()},
        }
    tmp = results_path.with_suffix(results_path.suffix + ".tmp")
    tmp.write_text(json.dumps(snapshot, indent=2))
    os.replace(tmp, results_path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--batches-dir", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--results", default="coordinator_results.json")
    ap.add_argument("--pattern", default="proof_inputs_*.json")
    ap.add_argument(
        "--no-wrap-v1",
        action="store_true",
        help="Skip the {\"V1\": …} envelope (use if the corpus already wraps).",
    )
    args = ap.parse_args()

    global WRAP_V1
    WRAP_V1 = not args.no_wrap_v1

    batches_dir = Path(args.batches_dir)
    paths = sorted(batches_dir.glob(args.pattern))
    if not paths:
        print(
            f"error: no files matched {args.pattern} in {batches_dir}",
            file=sys.stderr,
        )
        return 1

    global _pending
    _pending = list(paths)
    sys.stderr.write(
        f"[coordinator] queued {len(paths)} batches "
        f"(numbers {[parse_batch_number(p) for p in paths]})\n"
    )

    results_path = Path(args.results)

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    sys.stderr.write(f"[coordinator] listening on :{args.port}\n")
    sys.stderr.flush()

    stop = threading.Event()

    def shutdown(signum, _frame):
        sys.stderr.write(f"[coordinator] received signal {signum}, shutting down\n")
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Periodically flush results so even an abrupt termination preserves
    # most of the data.
    def periodic_flush():
        while not stop.is_set():
            time.sleep(2)
            try:
                write_results(results_path)
            except Exception as err:
                sys.stderr.write(f"[coordinator] flush error: {err}\n")

    flusher = threading.Thread(target=periodic_flush, daemon=True)
    flusher.start()

    try:
        server.serve_forever()
    finally:
        write_results(results_path)
        sys.stderr.write(f"[coordinator] wrote {results_path}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
