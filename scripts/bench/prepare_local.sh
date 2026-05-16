#!/usr/bin/env bash
# Extract batches.zip into bench-corpus/ so the coordinator can serve them.
#
# Run on the local machine before uploading to vast.ai.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ZIP_PATH="${ZIP_PATH:-$REPO_ROOT/batches.zip}"
CORPUS_DIR="${CORPUS_DIR:-$REPO_ROOT/bench-corpus}"

if [[ ! -f "$ZIP_PATH" ]]; then
    echo "error: $ZIP_PATH not found (set ZIP_PATH=...)." >&2
    exit 1
fi

mkdir -p "$CORPUS_DIR"

# -j drops directory structure, -o overwrites. Explicit positive include
# avoids macOS resource forks (`__MACOSX/._*` — same basename after -j strips
# the prefix, so we'd otherwise clobber the real file).
unzip -j -o "$ZIP_PATH" 'proof_inputs_*.json' -d "$CORPUS_DIR" >/dev/null

# Sanity check.
shopt -s nullglob
files=("$CORPUS_DIR"/proof_inputs_*.json)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "error: no proof_inputs_*.json files extracted to $CORPUS_DIR" >&2
    exit 1
fi

total_bytes=0
for f in "${files[@]}"; do
    total_bytes=$(( total_bytes + $(stat -f%z "$f" 2>/dev/null || stat -c%s "$f") ))
done

echo "extracted ${#files[@]} batches to $CORPUS_DIR (total $(( total_bytes / 1024 / 1024 )) MiB)"
echo
echo "next: rsync to vast.ai, e.g."
echo "  rsync -avz --progress \\"
echo "    scripts/bench/ bench-corpus/ \\"
echo "    <vast-user>@<vast-host>:~/eravm-bench/"
