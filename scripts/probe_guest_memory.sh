#!/usr/bin/env bash
# Optional memory scaffolding: measure the GUEST peak heap demand of a batch
# *during simulation* (the airbender transpiler run), with no guest code change.
#
# It rebuilds the guest with a chosen heap size (`_heap_size`, the only variable)
# and runs the batch through `host run`. Run it at a few sizes to bracket the
# peak: the smallest heap at which the batch reaches the end ≈ its peak demand.
#
#   scripts/probe_guest_memory.sh <batch-file> <heap-MiB>
#   e.g. scripts/probe_guest_memory.sh 67912.bin.gz 952   ->  FITS / OOM(<bytes>)
#
# Notes:
#  - Batch file is looked up under testdata/era_mainnet_batches/binary (LFS);
#    a relative name is resolved there, only an absolute path is used as-is.
#    Encode raw proof_inputs JSON with the `encode_batch` example first.
#  - Building the RISC-V guest needs a riscv-capable clang. In CI's cargo-airbender
#    image it's the default; locally on macOS export
#    CC=/opt/homebrew/opt/llvm/bin/clang AR=/opt/homebrew/opt/llvm/bin/llvm-ar
#  - This rewrites the `_heap_size` defsym in guest/.cargo/config.toml for the
#    build and restores it on exit (production heap is left untouched).
set -euo pipefail

batch="${1:?usage: probe_guest_memory.sh <batch-file> <heap-MiB>}"
heap_mib="${2:?usage: probe_guest_memory.sh <batch-file> <heap-MiB>}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cfg="$repo_root/guest/.cargo/config.toml"
bytes=$(( heap_mib * 1048576 ))

backup="$(mktemp)"; cp "$cfg" "$backup"
restore() { cp "$backup" "$cfg"; rm -f "$backup"; }
trap restore EXIT

# Set the heap for this build. `_heap_size` is `PROVIDE`d (= 768M) by
# riscv_common's link.x, and a `--defsym` overrides that default — so this works
# whether or not the checked-in config pins a size of its own. If it already pins
# one, retarget it; otherwise inject the link-arg next to the linker-script args.
if grep -q -- "--defsym=_heap_size=" "$cfg"; then
  perl -0pi -e "s/--defsym=_heap_size=\d+/--defsym=_heap_size=$bytes/" "$cfg"
else
  perl -0pi -e "s|(\n\s*)(\"-C\",\s*\"link-arg=-Tmemory\.x\",)|\$1\"-C\", \"link-arg=--defsym=_heap_size=$bytes\",\$1\$2|" "$cfg"
fi
grep -q -- "--defsym=_heap_size=$bytes" "$cfg" || {
  echo "error: could not set _heap_size defsym in $cfg" >&2
  echo "       (expected a '-C link-arg=-Tmemory.x' entry in [build].rustflags to anchor to)" >&2
  exit 1
}

echo "[probe] building guest with ${heap_mib} MiB heap ..." >&2
( cd "$repo_root/guest" && cargo airbender build >/dev/null 2>&1 ) \
  || { echo "error: guest build failed (riscv clang? set CC=)" >&2; exit 1; }

echo "[probe] running batch ${batch} ..." >&2
log="$(mktemp)"
set +e
cargo run --release -p eravm-prover-host --locked -- \
  run --batches-dir "$repo_root/testdata/era_mainnet_batches/binary" \
  --batch-files "$batch" >"$log" 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  # The host logs `cycles=N` with ANSI colour escapes between the field name and
  # the `=`, so strip them before matching or the literal pattern never hits.
  cyc=$(sed $'s/\033\\[[0-9;]*m//g' "$log" | grep -m1 -oE 'cycles=[0-9]+' || true)
  echo "RESULT: FITS at ${heap_mib} MiB (${cyc:-cycles=?})"
else
  sz=$(grep -A1 'memory allocation of' "$log" | grep -m1 -oE '[0-9]{3,}' || true)
  if [ -n "$sz" ]; then
    echo "RESULT: OOM at ${heap_mib} MiB (failed allocation: ${sz} bytes)"
  else
    echo "RESULT: run failed at ${heap_mib} MiB (not an OOM); tail of output:" >&2
    tail -15 "$log" >&2
  fi
fi
rm -f "$log"
