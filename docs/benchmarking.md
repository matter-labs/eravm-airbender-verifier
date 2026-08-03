# Benchmarking the verifier

How to measure what the guest actually costs: **peak heap** (it must fit a bounded
guest heap) and **cycles** (a batch that exceeds the per-proof cycle limit cannot
be proved). Both matter because the guest fails hard on either.

Start here, then follow the links for depth:

- [`scripts/cycle_model/README.md`](../scripts/cycle_model/README.md) — fitting and
  re-fitting the cycle cost model, validating on a hold-out, shipping a new table.
- [`scripts/precompile_calibration/README.md`](../scripts/precompile_calibration/README.md)
  — pricing precompiles the mainnet corpus never calls.
- [`testdata/era_mainnet_batches/README.md`](../testdata/era_mainnet_batches/README.md)
  — the corpus, and **which batches decode on which build**.

---

## 0. Prerequisites

```sh
# All cargo commands in this repo, on any machine without CUDA:
export ZKSYNC_USE_CUDA_STUBS=1
# If cargo can't authenticate to the private git deps:
export CARGO_NET_GIT_FETCH_WITH_CLI=true

# Batches live in Git LFS:
git lfs install
```

Building the **guest** (needed for cycle measurement and for the true in-guest heap
peak) requires a clang that can target `riscv32`. On macOS, Apple's clang cannot —
install LLVM and point at it:

```sh
brew install llvm
export CC=/opt/homebrew/opt/llvm/bin/clang
export AR=/opt/homebrew/opt/llvm/bin/llvm-ar
```

CI's `cargo-airbender` image already has a suitable clang. Nothing else here needs
a GPU.

## 1. Get a batch

```sh
./scripts/fetch_lfs_batches.sh 84730.bin.gz
```

`84730` and its neighbours are what CI uses, so they load on a default build.
**Not every batch does** — see the table in the corpus README. In short:

| Set | Loads on a default build? |
| --- | --- |
| `84730`–`84732` | yes |
| `513601`–`513649` (cycle-model hold-out) | needs `--features relax-version-pin` (protocol v29) |
| `506077`–`506204` | no — pre-v31 wire format, fails in `bincode` decode |

## 2. Measure peak heap

Cheapest signal first — native peak-live heap per batch, as CSV:

```sh
cargo run --release -p eravm-prover-host --example mem_peak -- \
    testdata/era_mainnet_batches/binary 84730.bin.gz
# batch_number,native_peak_bytes
# 84730,105279361
```

Treat that as a **lower bound** on the in-guest peak, not the answer. The 32-bit
guest packs pointers and `usize` smaller, but talc fragmentation and transient
realloc doubling push the real peak *up*, and the two effects do not cancel
predictably.

For the number that actually decides whether a batch fits, bisect the guest heap:

```sh
$ scripts/probe_guest_memory.sh 84730.bin.gz 400
RESULT: FITS at 400 MiB (cycles=1052307371)
$ scripts/probe_guest_memory.sh 84730.bin.gz 192
RESULT: FITS at 192 MiB (cycles=1052307371)
$ scripts/probe_guest_memory.sh 84730.bin.gz 128
RESULT: OOM at 128 MiB (failed allocation: 63800000 bytes)
```

So batch 84730's true in-guest peak is between **128 and 192 MiB** — against a
native `mem_peak` proxy of 105 MB. That gap is the point: the proxy understated the
real demand by 25–80% here, so size decisions belong to this tool, not to
`mem_peak`. The smallest heap at which the batch still completes is its peak
demand.

The script overrides `_heap_size` (which riscv_common's `link.x` `PROVIDE`s at
768M), rebuilds the guest, and restores your config on exit — including if it
fails.

### Where the heap goes, not just how much

```sh
cargo run --release -p zksync_airbender_verifier --features mem-markers \
    --example mem_timeline -- testdata/era_mainnet_batches/binary/84730.bin.gz
```

```
[mem] after load+decode (input live)     live=    1.1 MiB   peak=   10.0 MiB
[mem] execute:start                      live=    1.1 MiB   peak=   10.0 MiB
[mem] end setup                          live=    1.1 MiB   peak=   10.0 MiB
[mem] end vm_execution                   live=    0.5 MiB   peak=  100.4 MiB
[mem] after execute returned             live=    0.1 MiB   peak=  100.4 MiB
```

Reading it: `live` barely moves while `peak` jumps to 100.4 MiB across
`vm_execution` — the peak is transient allocation inside the VM run, not state held
across phases. That distinction is what tells you whether to attack a data
structure's size or its lifetime.

`talc_timeline` is the same thing under **talc**, the guest's own allocator, so its
footprint includes allocator metadata and fragmentation — closer to the guest than
the System-allocator sum:

```sh
cargo run --release -p zksync_airbender_verifier --features mem-markers \
    --example talc_timeline -- testdata/era_mainnet_batches/binary/84730.bin.gz
```

Its arena is a 1 GiB static array, just above the guest's real heap ceiling, so an
arena overflow means the guest would overflow too. Note macOS/aarch64 cannot load
the binary at all if you raise it much past 1 GiB (dyld fails to map its shared
region); Linux tolerates more.

Only `execute()`'s three boundaries appear above — the last two markers are in
`verify_commitment()`, which these examples don't call.

## 3. Measure cycles

Cycle measurement needs a guest built with phase markers:

```sh
cargo airbender build --project guest -- --features cycle-markers
```

Then measure features (natively) and ground-truth cycles (through the transpiler)
per batch:

```sh
cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
    --all-batches --batches-dir testdata/era_mainnet_batches/binary \
    --app-bin-dir guest/dist/app --jobs 8 --out artifacts/cycle_model
```

`--check-only` is a fast pre-flight that reports each batch's protocol version
without running a guest — use it before a long run. `--jobs N` parallelises, and
each batch is isolated with `catch_unwind` so one failure doesn't lose the run.

The result is `artifacts/cycle_model/dataset.json`: per batch, the feature vector,
raw cycles, per-phase cycles, and delegation counts. To fit a cost table from it,
or to validate one on a hold-out, follow
[`scripts/cycle_model/README.md`](../scripts/cycle_model/README.md).

To *predict* rather than measure — no RISC-V execution — the estimator applies the
committed table to a vm2 trace; see the same README's Rust API section.

## 4. Flags that must never ship

Three features exist only for the above. Two of them affect the proved guest:

| Feature | What it does | Risk |
| --- | --- | --- |
| `cycle-markers` | emits phase boundaries as `csrrw x0, 0x7ff, x0` | detectable in the guest binary; CI rejects it |
| `relax-version-pin` | **disables the protocol-version pin** | soundness: the verifier would accept any behaviour-compatible protocol version. Leaves no trace in the binary |
| `mem-markers` | exposes heap counters, prints per-phase live/peak | none — host-only; no tool that uses it runs in the guest |

`relax-version-pin` is the dangerous one, and it is invisible in the artifact. It
is therefore wired to require `cycle-markers`, which *is* visible: CSR `0x7ff` is
absent from `ALLOWED_CSRS` in
[`scripts/check_guest_riscv_code.sh`](../scripts/check_guest_riscv_code.sh), which
runs in both `ci-check` and `release-artifacts`. A calibration guest therefore
cannot be released.

**If that check fails on your build, that is the check working.** Fix the build —
do not add `0x7ff` to the allowlist.

## 5. Re-running the accuracy guard

The CI guard needs no corpus: it applies the committed table to a frozen fixture of
49 measured batches.

```sh
cargo test -p zksync-era-airbender-cycles-estimator --test model_regression
```

Refresh that fixture only when a guest change genuinely moves cycle counts — it is
the repo's only tripwire against a cost-table regression, and it degrades if
refreshed from fewer batches than the full 49 (which is why they are in LFS).
