#!/usr/bin/env bash
set -euo pipefail

# Fetch a batch's proof-generation data from an airbender-proof-data-handler and
# save the raw JSON response verbatim.
#
# Uses the read-only, no-lock endpoint:
#   GET {base_url}/airbender/proof_inputs_no_lock/{batch}
# (see zksync-era core/node/airbender_proof_data_handler/src/lib.rs)
#
# The handler returns:
#   200 + JSON  -> batch data (saved as-is)
#   404         -> batch not present
#   5xx         -> handler error

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Override with --port or the AIRBENDER_PDH_PORT env var if your handler differs.
default_port="${AIRBENDER_PDH_PORT:-3320}"
out_dir=""

usage() {
  cat <<'EOF'
Usage:
  ./scripts/fetch_airbender_batch.sh --host <HOST[:PORT]> <batch> [<batch>...]
  ./scripts/fetch_airbender_batch.sh --url  <http://HOST:PORT> <batch> [<batch>...]

Options:
  --host <HOST[:PORT]>  Handler host (IP or DNS). Port defaults to 3320
                        (override with --port or AIRBENDER_PDH_PORT).
  --url  <BASE_URL>     Full base URL, e.g. http://10.0.0.5:3320
  --port <PORT>         Port to use with --host (default: 3320).
  --out-dir <DIR>       Where to write JSON files
                        (default: testdata/era_mainnet_batches/json).
  -h, --help            Show this help.

Each batch is saved as <out-dir>/<batch>.json exactly as returned by the handler.

Examples:
  ./scripts/fetch_airbender_batch.sh --host 10.0.0.5 84730
  ./scripts/fetch_airbender_batch.sh --url http://10.0.0.5:3320 84730 84731
EOF
}

base_url=""
host=""
port="$default_port"
declare -a batches=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --host) host="${2:?--host requires a value}"; shift 2 ;;
    --url)  base_url="${2:?--url requires a value}"; shift 2 ;;
    --port) port="${2:?--port requires a value}"; shift 2 ;;
    --out-dir) out_dir="${2:?--out-dir requires a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --*) echo "error: unknown option: $1" >&2; usage; exit 1 ;;
    *) batches+=("$1"); shift ;;
  esac
done

if [ -z "$base_url" ]; then
  if [ -z "$host" ]; then
    echo "error: provide --host <HOST[:PORT]> or --url <BASE_URL>" >&2
    usage
    exit 1
  fi
  # Only append the default port if the host doesn't already carry one.
  if [[ "$host" == *:* ]]; then
    base_url="http://${host}"
  else
    base_url="http://${host}:${port}"
  fi
fi

# Strip any trailing slash for clean URL joining.
base_url="${base_url%/}"

if [ "${#batches[@]}" -eq 0 ]; then
  echo "error: specify at least one batch number" >&2
  usage
  exit 1
fi

if [ -z "$out_dir" ]; then
  out_dir="${repo_root}/testdata/era_mainnet_batches/json"
fi
mkdir -p "$out_dir"

failures=0
for batch in "${batches[@]}"; do
  url="${base_url}/airbender/proof_inputs_no_lock/${batch}"
  out_file="${out_dir}/${batch}.json"
  echo "fetching batch ${batch} from ${url}"

  # -sS: quiet but show errors; -f handled manually so we can report HTTP status.
  http_code="$(curl -sS -o "$out_file" -w '%{http_code}' "$url" || echo "000")"

  case "$http_code" in
    200)
      echo "  saved -> ${out_file}"
      ;;
    404)
      echo "  error: batch ${batch} not present (HTTP 404)" >&2
      rm -f "$out_file"
      failures=$((failures + 1))
      ;;
    000)
      echo "  error: could not reach handler at ${base_url}" >&2
      rm -f "$out_file"
      failures=$((failures + 1))
      ;;
    *)
      echo "  error: handler returned HTTP ${http_code} for batch ${batch}" >&2
      echo "  response body left at ${out_file} for inspection" >&2
      failures=$((failures + 1))
      ;;
  esac
done

if [ "$failures" -ne 0 ]; then
  echo "${failures} batch(es) failed" >&2
  exit 1
fi
