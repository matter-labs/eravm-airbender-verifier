#!/usr/bin/env bash
# check_guest_memory_layout.sh — verify the built guest's RAM layout is the one
# we intend to prove.
#
# The guest's heap arena is a LINK-TIME constant: `riscv_common`'s link.x
# `PROVIDE(_heap_size = 768M)`, overridden in guest/.cargo/config.toml with
# `-C link-arg=--defsym=_heap_size=<bytes>`. Two failure modes make that worth
# asserting on every build:
#
#   1. A silent revert to the 768 MiB default. `[build] rustflags` in
#      guest/.cargo/config.toml is REPLACED (not merged) by a RUSTFLAGS /
#      CARGO_ENCODED_RUSTFLAGS env var or a `--config build.rustflags=[...]`
#      override, which drops the `--defsym`. The result is a perfectly valid
#      guest with a DIFFERENT app.bin sha than the registered verification key:
#      every proof it produces is rejected on L1, and nothing before settlement
#      notices. This check turns that into a build failure.
#
#   2. Silent loss of arena to static growth. `.heap` starts at the 2 MiB-aligned
#      end of .bss, so new .rodata/.bss pushes `_sheap` up. Overshooting RAM is
#      already caught by the linker ("section '.heap' will not fit in region
#      'RAM'"), but a heap that merely ends up somewhere unintended is not.
#
# The machine's address space is exactly 1 GiB — `riscv_transpiler`'s
# `jit::RAM_SIZE`/`MAX_RAM_SIZE` and airbender-host's `DEFAULT_RAM_BOUND_BYTES`
# are both `1 << 30`, and the simulator indexes that array with `get_unchecked`
# behind a `debug_assert` only — so `_eheap` above the RAM top would be an
# out-of-bounds host access in a release prover, not a clean error. Hence the
# explicit ceiling assert here as well.
#
# Usage:
#   check_guest_memory_layout.sh <app.elf> [--expect-heap-mib N]
#                               [--ram-top-mib N] [--nm PATH]
#
#   --expect-heap-mib N   require `_eheap - _sheap` to be exactly N MiB.
#                         Omit to report the layout without pinning a size.
#   --ram-top-mib N       top of the RAM region in MiB (default 1024 = the
#                         Airbender machine's address space: memory.x ROM 4M +
#                         RAM 1020M). Only change this alongside an upstream
#                         memory.x / RAM_SIZE change.
#   --nm PATH             llvm-nm to use (default: the guest toolchain's).
#
# Exit codes: 0 = layout as expected, 1 = violation, 2 = usage or environment error.

set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^# Exit codes/p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  echo "error: $*" >&2
  exit 2
}

MIB=$((1024 * 1024))

# --- Argument parsing ---------------------------------------------------------
ELF=""
EXPECT_HEAP_MIB=""
RAM_TOP_MIB=1024
NM="${NM:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-heap-mib)
      [[ $# -ge 2 && -n "$2" ]] || die "--expect-heap-mib requires a number"
      EXPECT_HEAP_MIB="$2"; shift 2 ;;
    --ram-top-mib)
      [[ $# -ge 2 && -n "$2" ]] || die "--ram-top-mib requires a number"
      RAM_TOP_MIB="$2"; shift 2 ;;
    --nm)
      [[ $# -ge 2 && -n "$2" ]] || die "--nm requires a path"
      NM="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *)
      [[ -z "$ELF" ]] || die "unexpected extra argument: $1"
      ELF="$1"; shift ;;
  esac
done

[[ -n "$ELF" ]] || { usage >&2; die "missing <app.elf> argument"; }
[[ -f "$ELF" ]] || die "no such file: $ELF"
[[ -z "$EXPECT_HEAP_MIB" || "$EXPECT_HEAP_MIB" =~ ^[0-9]+$ ]] \
  || die "--expect-heap-mib must be a non-negative integer"
[[ "$RAM_TOP_MIB" =~ ^[0-9]+$ ]] || die "--ram-top-mib must be a non-negative integer"

# --- Tool discovery -----------------------------------------------------------
# Same anchoring as check_guest_riscv_code.sh: resolve llvm-nm from the toolchain
# that BUILT the guest (guest/rust-toolchain.toml declares llvm-tools-preview),
# independent of the invoker's cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_llvm_tool() {
  local tool="$1"
  local guest_dir="$SCRIPT_DIR/../guest" anchor
  if [[ -f "$guest_dir/rust-toolchain.toml" ]]; then
    anchor="$guest_dir"
  else
    anchor="$SCRIPT_DIR"
  fi
  if command -v rustc >/dev/null 2>&1; then
    local sysroot host candidate
    sysroot="$(cd "$anchor" && rustc --print sysroot)"
    host="$(cd "$anchor" && rustc -vV | sed -n 's/^host: //p')"
    candidate="$sysroot/lib/rustlib/$host/bin/$tool"
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  fi
  command -v "$tool" || return 1
}

[[ -n "$NM" ]] || NM="$(find_llvm_tool llvm-nm)" \
  || die "llvm-nm not found; install the llvm-tools-preview rustup component or pass --nm"
echo "using llvm-nm: $NM" >&2

# --- Read the layout symbols --------------------------------------------------
SYMBOLS="$("$NM" --defined-only "$ELF" 2>/dev/null)" || die "llvm-nm failed on $ELF"
[[ -n "$SYMBOLS" ]] \
  || die "$ELF has no defined symbols — this check needs an unstripped ELF (the build ELF and dist app.elf both keep their symtab)"

sym_addr() { # $1 = symbol name -> decimal address on stdout, empty if absent
  local hex
  hex="$(awk -v want="$1" 'NF >= 3 && $3 == want { print $1; exit }' <<<"$SYMBOLS")"
  [[ -n "$hex" ]] || return 1
  echo "$((16#$hex))"
}

for s in _estack _sstack _sheap _eheap; do
  sym_addr "$s" >/dev/null 2>&1 \
    || die "$ELF defines no '$s' — not an Airbender guest linked with riscv_common's link.x?"
done

ESTACK="$(sym_addr _estack)"
SSTACK="$(sym_addr _sstack)"
SHEAP="$(sym_addr _sheap)"
EHEAP="$(sym_addr _eheap)"

HEAP_SIZE=$((EHEAP - SHEAP))
STACK_SIZE=$((SSTACK - ESTACK))
RAM_TOP=$((RAM_TOP_MIB * MIB))

hex() { printf '0x%08x' "$1"; }
mib() { printf '%s MiB' "$(( $1 / MIB ))"; }

cat <<EOF
guest RAM layout ($ELF):
  .stack   $(hex "$ESTACK") .. $(hex "$SSTACK")   $(mib "$STACK_SIZE") (grows down from _sstack)
  .heap    $(hex "$SHEAP") .. $(hex "$EHEAP")   $(mib "$HEAP_SIZE") ($HEAP_SIZE bytes)
  RAM top  $(hex "$RAM_TOP")                 $(mib "$RAM_TOP") — machine address space
  unused   $(mib $((RAM_TOP - EHEAP))) above _eheap
EOF

# --- Assertions ---------------------------------------------------------------
FAILURES=0
fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

# The machine bound. Above this the host simulator's RAM array is indexed out of
# bounds (release builds have no check), so this must never be crossed.
(( EHEAP <= RAM_TOP )) \
  || fail "_eheap $(hex "$EHEAP") is above the RAM top $(hex "$RAM_TOP") — the guest can address memory the prover does not have"

# link.x aligns .heap to 2 MiB; a violation means the layout is not what we think.
(( SHEAP % (2 * MIB) == 0 )) \
  || fail "_sheap $(hex "$SHEAP") is not 2 MiB-aligned (link.x aligns .heap to 2 MiB)"

# boot_sequence::init() asserts this at runtime (_estack must equal
# common_constants::rom::ROM_BYTE_SIZE = 4 MiB); catching it at build time is strictly better.
(( ESTACK == 4 * MIB )) \
  || fail "_estack $(hex "$ESTACK") != 4 MiB — boot_sequence::init() asserts _estack == ROM_BYTE_SIZE and will abort the guest"

(( STACK_SIZE > 0 )) || fail "empty .stack region ($(hex "$ESTACK") .. $(hex "$SSTACK"))"
(( SHEAP >= SSTACK )) \
  || fail "_sheap $(hex "$SHEAP") overlaps the stack region (ends $(hex "$SSTACK"))"

if [[ -n "$EXPECT_HEAP_MIB" ]]; then
  expect_bytes=$((EXPECT_HEAP_MIB * MIB))
  if (( HEAP_SIZE != expect_bytes )); then
    fail "heap is $(mib "$HEAP_SIZE") ($HEAP_SIZE bytes), expected ${EXPECT_HEAP_MIB} MiB ($expect_bytes bytes)"
    if (( HEAP_SIZE == 768 * MIB )); then
      echo "hint: 768 MiB is riscv_common link.x's PROVIDE default — the" >&2
      echo "      '--defsym=_heap_size=...' link-arg in guest/.cargo/config.toml did not reach" >&2
      echo "      the linker. A RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS env var or a" >&2
      echo "      '--config build.rustflags=[...]' override REPLACES that array. This guest" >&2
      echo "      would not match the registered verification key." >&2
    fi
  fi
fi

if (( FAILURES > 0 )); then
  echo "error: $FAILURES memory-layout violation(s)" >&2
  exit 1
fi

if [[ -n "$EXPECT_HEAP_MIB" ]]; then
  echo "OK: heap is exactly ${EXPECT_HEAP_MIB} MiB and the layout is within the 1 GiB machine RAM"
else
  echo "OK: layout is within the 1 GiB machine RAM (no --expect-heap-mib given, size not pinned)"
fi
