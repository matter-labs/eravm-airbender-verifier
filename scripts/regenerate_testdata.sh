#!/usr/bin/env bash
set -euo pipefail

# Regenerate the Era mainnet batch corpus from a running zksync-era prover data
# handler.
#
# The service (core/node/airbender_proof_data_handler) serves each batch's
# verifier input as JSON via `GET /airbender/proof_inputs_no_lock/{l1_batch_number}`,
# returning the `AirbenderVerifierInput` object (or `null` when unavailable).
# For every requested batch this script:
#   1. fetches the JSON from the endpoint,
#   2. converts it to the hex-text corpus format via the `json_to_batch` bin,
#   3. gzips + Git-LFS-stages it through `import_mainnet_batches.sh`.
#
# The endpoint base URL is required; pass it via --url or the BATCH_API_URL env
# var. Either the bare base (e.g. http://localhost:3124) — the standard route is
# appended automatically — or a template containing `{batch}` for a custom route.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

api_url="${BATCH_API_URL:-}"
# Assign the default separately: a `{batch}` literal inside a `${var:-default}`
# expansion is misparsed by bash (the `}` closes the expansion early).
route_template="${BATCH_API_ROUTE:-}"
[ -n "$route_template" ] || route_template='/airbender/proof_inputs_no_lock/{batch}'
declare -a requested_batches=()

usage() {
  cat <<'EOF'
Usage:
  BATCH_API_URL=http://host:port ./scripts/regenerate_testdata.sh <batch-number> [<batch-number>...]
  ./scripts/regenerate_testdata.sh --url http://host:port 84730 84731 84732
  ./scripts/regenerate_testdata.sh --url http://host:port 84730,84731,84732

Options:
  --url <base|template>   Endpoint base URL, or a full URL template containing
                          `{batch}`. Overrides $BATCH_API_URL.
  -h, --help              Show this help.

Environment:
  BATCH_API_URL    Endpoint base URL (used when --url is not given).
  BATCH_API_ROUTE  Route appended to the base, `{batch}` is substituted.
                   Default: /airbender/proof_inputs_no_lock/{batch}

Batch numbers may be passed as separate arguments or a comma-separated list.
The resulting `<number>.bin.gz` objects are staged (not committed) so you can
review the LFS pointer changes before committing.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --url)
      if [ "$#" -lt 2 ]; then
        echo "error: --url requires a value" >&2
        exit 1
      fi
      api_url="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      # Accept both space-separated args and comma-separated lists.
      IFS=',' read -r -a parts <<< "$1"
      for part in "${parts[@]}"; do
        [ -n "$part" ] && requested_batches+=("$part")
      done
      shift
      ;;
  esac
done

if [ -z "$api_url" ]; then
  echo "error: endpoint URL is required; pass --url or set BATCH_API_URL" >&2
  usage
  exit 1
fi

if [ "${#requested_batches[@]}" -eq 0 ]; then
  echo "error: pass at least one batch number" >&2
  usage
  exit 1
fi

for tool in curl gzip cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: required tool '$tool' not found in PATH" >&2
    exit 1
  fi
done

# Build the full URL for a batch. If the base already contains `{batch}` we use
# it verbatim as a template; otherwise the configured route is appended.
batch_url() {
  local batch_number="$1"
  # Single-quote the `{batch}` pattern so its braces are treated literally and
  # do not prematurely close the parameter expansion.
  if [[ "$api_url" == *"{batch}"* ]]; then
    echo "${api_url/'{batch}'/$batch_number}"
    return
  fi
  local base="${api_url%/}"
  local route="${route_template/'{batch}'/$batch_number}"
  echo "${base}${route}"
}

# Stage a scratch dir for the intermediate `<number>.bin` files. import script
# picks these up and produces the compressed LFS objects.
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# Build the converter once up front so any compile error surfaces before we
# start hitting the network, and per-batch `cargo run` calls are no-ops.
echo "building json_to_batch converter..." >&2
cargo build -q --manifest-path "$repo_root/Cargo.toml" -p zksync_cli_utils --bin json_to_batch

run_converter() {
  cargo run -q --manifest-path "$repo_root/Cargo.toml" -p zksync_cli_utils --bin json_to_batch
}

for batch_number in "${requested_batches[@]}"; do
  if [[ ! "$batch_number" =~ ^[0-9]+$ ]]; then
    echo "error: batch number '$batch_number' must be numeric" >&2
    exit 1
  fi

  url="$(batch_url "$batch_number")"
  echo "fetching batch $batch_number from $url" >&2

  json="$(curl -sSf "$url")" || {
    echo "error: request failed for batch $batch_number ($url)" >&2
    exit 1
  }

  if [ -z "$json" ] || [ "$(printf '%s' "$json" | tr -d '[:space:]')" = "null" ]; then
    echo "error: endpoint returned no data for batch $batch_number (null); is it available yet?" >&2
    exit 1
  fi

  printf '%s' "$json" | run_converter > "$work_dir/${batch_number}.bin"
  echo "converted batch $batch_number -> ${batch_number}.bin" >&2
done

echo "compressing and staging batches into the LFS corpus..." >&2
"$repo_root/scripts/import_mainnet_batches.sh" --source-dir "$work_dir" "${requested_batches[@]}"

echo "done. Review the staged pointer changes with 'git status' before committing." >&2
