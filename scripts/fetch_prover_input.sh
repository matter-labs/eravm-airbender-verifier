#!/usr/bin/env bash
set -euo pipefail

# Fetches a prover input from the job server and writes the JSON body to a file
# (or stdout). No zksync / airbender dependencies — just curl against the job
# server's HTTP API.
#
#   --batch N : GET  {server}/airbender/proof_inputs_no_lock/N
#               Read-only fetch of a SPECIFIC batch. Does NOT claim/lock the
#               job, so it's safe to run against a live server. Same JSON body
#               as the polling endpoint (V1AirbenderVerifierInput).
#   (default) : POST {server}/airbender/proof_inputs
#               Polls for the NEXT available FRI job — this LOCKS the job
#               server-side, same as a real prover.
#   --snark   : POST {server}/airbender/snark_inputs
#               Polls for the next SNARK input ({ l1_batch_number, fri_proof }).
#
# 200 OK         -> body is saved.
# 204 No Content -> no job available (polling endpoints).
# 404 Not Found  -> requested batch is not available (--batch).

usage() {
  cat <<'EOF'
Usage:
  ./scripts/fetch_prover_input.sh --batch N [--out FILE] [SERVER_URL]   # specific batch, no lock
  ./scripts/fetch_prover_input.sh [--snark] [--out FILE] [SERVER_URL]   # poll next job (locks)

Options:
  --batch N      Fetch the input for L1 batch N without locking it (read-only).
  --snark        Poll for a SNARK input instead of a FRI input (mutually exclusive with --batch).
  --out FILE     Write the body here instead of stdout.
  -h, --help     Show this help.

Server URL resolution (first match wins):
  1. positional SERVER_URL argument
  2. $PROVER_SERVER_URL
  3. http://localhost:8080
EOF
}

kind="fri"
method="POST"
path="/airbender/proof_inputs"
batch=""
out=""
server="${PROVER_SERVER_URL:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --batch) batch="${2:?--batch needs a number}"; shift 2 ;;
    --snark) kind="snark"; shift ;;
    --out)   out="${2:?--out needs a file}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)  server="$1"; shift ;;
  esac
done

if [ -n "$batch" ]; then
  if [ "$kind" = "snark" ]; then
    echo "error: --batch and --snark are mutually exclusive" >&2
    exit 1
  fi
  case "$batch" in
    ''|*[!0-9]*) echo "error: --batch must be a non-negative integer, got '$batch'" >&2; exit 1 ;;
  esac
  kind="batch ${batch}"
  method="GET"
  path="/airbender/proof_inputs_no_lock/${batch}"
elif [ "$kind" = "snark" ]; then
  path="/airbender/snark_inputs"
fi

server="${server:-http://localhost:8080}"
server="${server%/}"
url="${server}${path}"

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

body="$(mktemp)"
trap 'rm -f "$body"' EXIT

# -s silent, -S still surface errors.
status="$(curl -sS -X "$method" \
  -o "$body" \
  -w '%{http_code}' \
  "$url")"

case "$status" in
  200)
    if [ -n "$out" ]; then
      cp "$body" "$out"
      echo "fetched ${kind} input -> ${out} ($(wc -c < "$out" | tr -d ' ') bytes)" >&2
    else
      cat "$body"
    fi
    ;;
  204)
    echo "no ${kind} job available (204 No Content) from ${url}" >&2
    exit 2
    ;;
  404)
    echo "${kind} not available (404 Not Found) from ${url}" >&2
    exit 2
    ;;
  *)
    echo "error: ${url} returned HTTP ${status}" >&2
    cat "$body" >&2
    exit 1
    ;;
esac
