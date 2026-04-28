#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
batch_glob_root="testdata/era_mainnet_batches/binary"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/fetch_lfs_batches.sh --all
  ./scripts/fetch_lfs_batches.sh <batch-file> [<batch-file>...]
  ./scripts/fetch_lfs_batches.sh <batch-file[,batch-file...]>

This pulls only the requested Git LFS batch objects. The repository default is
to leave the mainnet corpus as small pointer files until you opt in.
EOF
}

if ! git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: $repo_root is not a git repository" >&2
  exit 1
fi

if ! git -C "$repo_root" lfs version >/dev/null 2>&1; then
  echo "error: git-lfs is required to fetch batch data; install it first" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  usage
  exit 1
fi

includes=()

# We keep the CLI deliberately small so CI and local docs can share the same
# fetch primitive without carrying a separate manifest parser.
if [ "$1" = "--all" ]; then
  if [ "$#" -ne 1 ]; then
    echo "error: --all cannot be combined with explicit batch files" >&2
    exit 1
  fi
  includes+=("${batch_glob_root}/**")
else
  # CI stores its curated batch list as one comma-separated env var, while local
  # callers often pass files as separate shell arguments. We accept both forms so
  # the fetch helper stays aligned with the Rust CLIs.
  for batch_file_arg in "$@"; do
    IFS=',' read -r -a batch_file_parts <<< "$batch_file_arg"
    for batch_file in "${batch_file_parts[@]}"; do
      case "$batch_file" in
        *.bin.gz)
          includes+=("${batch_glob_root}/${batch_file}")
          ;;
        *.bin)
          includes+=("${batch_glob_root}/${batch_file}.gz")
          ;;
        *)
          echo "error: batch file '$batch_file' must end with .bin or .bin.gz" >&2
          exit 1
          ;;
      esac
    done
  done
fi

include_arg="$(
  IFS=,
  echo "${includes[*]}"
)"

git -C "$repo_root" lfs pull --include="$include_arg" --exclude=""
