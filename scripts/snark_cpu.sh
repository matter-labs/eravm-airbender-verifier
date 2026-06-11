#!/usr/bin/env bash
set -euo pipefail
ulimit -s unlimited
# Fetch a FRI proof from the prover job server (or use a pre-fetched one) and
# wrap it into a SNARK on CPU. No GPU, and nothing is submitted back to the
# server — this is a local test/benchmark of the CPU SNARK wrapper.
#
# Pipeline:
#   1. fetch  : scripts/fetch_prover_input.sh --snark  -> snark input JSON
#               ({ l1_batch_number, fri_proof }). Skipped when --input is given.
#   2. decode : eravm-prover-host decode-fri-input     -> raw fri_proof.json
#               Strips the hex/bincode `Proof` envelope down to the raw proof
#               that `prove-snark` consumes.
#   3. setup  : download the CPU SNARK trusted setup (CRS) if it is not on disk.
#   4. wrap   : eravm-prover-host prove-snark           -> snark_proof.json
#
# The host is built with `--no-default-features`, so the `gpu_fri` (CUDA)
# feature is off and the binary is completely CUDA-free.
#
# NOTE: polling the job server's snark_inputs endpoint LOCKS the job
# server-side (same as a real prover). Pass --input FILE to wrap a proof you
# already have on disk and avoid touching the live server at all.

usage() {
  cat <<'EOF'
Usage:
  ./scripts/snark_cpu.sh [options] [SERVER_URL]

Options:
  --input FILE        Use a pre-fetched snark input JSON instead of polling the
                      server (the body saved by fetch_prover_input.sh --snark).
  --out-dir DIR       Output root for proofs (default: artifacts/snark-cpu).
  --trusted-setup F   CPU SNARK trusted setup / CRS file
                      (default: $SNARK_TRUSTED_SETUP_FILE or ./setup.key).
                      Downloaded automatically if absent.
  --snark-vk FILE     Optional pre-generated SNARK VK JSON (e.g. vks/snark_vk.json)
                      to load once instead of deriving it from the setup chain.
  --use-zk            Produce a zero-knowledge SNARK.
  --save-intermediates  Also write the phase 1/2 wrapper artifacts.
  --debug             Build/run a debug binary instead of --release.
  -h, --help          Show this help.

Server URL resolution (when --input is not given): positional SERVER_URL,
then $PROVER_SERVER_URL, then http://localhost:8080.
EOF
}

input=""
out_dir="artifacts/snark-cpu"
trusted_setup="${SNARK_TRUSTED_SETUP_FILE:-setup.key}"
snark_vk=""
use_zk=0
save_intermediates=0
profile_flag="--release"
server=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --input)             input="${2:?--input needs a file}"; shift 2 ;;
    --out-dir)           out_dir="${2:?--out-dir needs a dir}"; shift 2 ;;
    --trusted-setup)     trusted_setup="${2:?--trusted-setup needs a file}"; shift 2 ;;
    --snark-vk)          snark_vk="${2:?--snark-vk needs a file}"; shift 2 ;;
    --use-zk)            use_zk=1; shift ;;
    --save-intermediates) save_intermediates=1; shift ;;
    --debug)             profile_flag=""; shift ;;
    -h|--help)           usage; exit 0 ;;
    -*) echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)  server="$1"; shift ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "$repo_root"

# CPU host runner: --no-default-features drops the gpu_fri (CUDA) feature.
# RUST_MIN_STACK sizes the SNARK wrapper's worker threads (128 MB); the wrapper
# recursion overflows the default thread stack otherwise.
host() {
  # shellcheck disable=SC2086
  RUST_MIN_STACK="${RUST_MIN_STACK:-134217728}" \
    cargo run $profile_flag --no-default-features -p eravm-prover-host -- "$@"
}

# Extract l1_batch_number from a snark input JSON without slurping the (huge)
# fri_proof field into a shell variable. Prints nothing when the field is
# absent (e.g. the input is already a raw FRI proof).
batch_number_of() {
  local file="$1" n
  if command -v jq >/dev/null 2>&1; then
    n="$(jq -r '.l1_batch_number // empty' "$file" 2>/dev/null)"
  elif command -v python3 >/dev/null 2>&1; then
    n="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("l1_batch_number",""))' "$file" 2>/dev/null)"
  else
    n="$(grep -o '"l1_batch_number"[[:space:]]*:[[:space:]]*[0-9]*' "$file" | grep -o '[0-9]*$' | head -1)"
  fi
  case "$n" in ''|null) ;; *) printf '%s' "$n" ;; esac
}

# True when the file is a snark_inputs envelope ({ l1_batch_number, fri_proof })
# that needs decoding, as opposed to a raw FRI proof that prove-snark accepts
# directly.
is_snark_envelope() {
  local file="$1"
  if command -v jq >/dev/null 2>&1; then
    [ "$(jq -r 'has("l1_batch_number") and has("fri_proof")' "$file" 2>/dev/null)" = "true" ]
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if ("l1_batch_number" in d and "fri_proof" in d) else 1)' "$file" 2>/dev/null
  else
    grep -q '"fri_proof"' "$file"
  fi
}

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# ---- 1. Obtain the snark input -------------------------------------------------
if [ -n "$input" ]; then
  snark_input="$input"
  echo ">> using pre-fetched snark input: ${snark_input}" >&2
else
  snark_input="${work_dir}/snark_input.json"
  echo ">> polling job server for a SNARK input (this LOCKS the job)" >&2
  "${script_dir}/fetch_prover_input.sh" --snark --out "$snark_input" ${server:+"$server"}
fi

# ---- 2. Get a raw FRI proof prove-snark can consume ---------------------------
# A fetched snark_inputs body is an envelope ({ l1_batch_number, fri_proof });
# decode it. A file that is already a raw FRI proof (e.g. a prior decode output
# or a prove-fri export) is fed through unchanged.
if is_snark_envelope "$snark_input"; then
  batch="$(batch_number_of "$snark_input")"
  : "${batch:?could not read l1_batch_number from ${snark_input}}"
  echo ">> batch ${batch}" >&2
  # Lay it out as batch-<n>/fri_proof.json so prove-snark writes
  # snark_proof.json alongside it, matching the prove-fri output layout.
  raw_dir="${out_dir}/batch-${batch}"
  raw_proof="${raw_dir}/fri_proof.json"
  mkdir -p "$raw_dir"
  echo ">> decoding FRI proof envelope -> ${raw_proof}" >&2
  host decode-fri-input --input "$snark_input" --output "$raw_proof"
else
  echo ">> input is already a raw FRI proof; skipping decode" >&2
  raw_proof="$snark_input"
fi

# ---- 3. Ensure the CPU trusted setup is on disk -------------------------------
if [ ! -f "$trusted_setup" ]; then
  echo ">> trusted setup ${trusted_setup} not found; downloading CPU CRS" >&2
  host download-trusted-setup --output "$trusted_setup"
fi

# ---- 4. Wrap to SNARK on CPU ---------------------------------------------------
snark_args=(prove-snark
  --proof-files "$raw_proof"
  --output-dir "$out_dir"
  --trusted-setup "$trusted_setup")
[ -n "$snark_vk" ]        && snark_args+=(--snark-vk "$snark_vk")
[ "$use_zk" -eq 1 ]       && snark_args+=(--use-zk)
[ "$save_intermediates" -eq 1 ] && snark_args+=(--save-intermediates)

echo ">> running CPU SNARK wrapper" >&2
RUST_LOG="${RUST_LOG:-info}" host "${snark_args[@]}"

# Mirror prove-snark's output layout: batch-<n>/fri_proof.json keeps the batch
# dir; any other proof file gets a dir named after its stem.
pf_base="$(basename "$raw_proof")"
pf_parent="$(basename "$(dirname "$raw_proof")")"
if [ "$pf_base" = "fri_proof.json" ] && [ "${pf_parent#batch-}" != "$pf_parent" ]; then
  result_dir="${out_dir}/${pf_parent}"
else
  result_dir="${out_dir}/${pf_base%.*}"
fi
echo ">> done: ${result_dir}/snark_proof.json" >&2
