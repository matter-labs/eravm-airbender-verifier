# FRI proving benchmark (vast.ai)

Replays a folder of `proof_inputs_*.json` files through `eravm-prover-server`
on a vast.ai GPU box and summarizes wall time, peak VRAM, and host RSS
per batch.

The server is unmodified: a small Python coordinator stands in for the
real job server, hands out one batch at a time over the same HTTP
protocol, and records timestamps.

## Layout

| file | runs where | purpose |
| --- | --- | --- |
| `prepare_local.sh` | local | unzip `batches.zip` into `bench-corpus/` |
| `coordinator.py` | vast.ai | mock job server; wraps bare V1 payloads into `{"V1": …}` for the server |
| `sample_metrics.sh` | vast.ai | background `nvidia-smi` + `/proc/<pid>/status` sampler |
| `vastai_setup.sh` | vast.ai | one-time build of the toolchain + guest ELF + `eravm-prover-server` |
| `run_fri_bench.sh` | vast.ai | benchmark orchestrator |
| `summarize.py` | either | per-batch table from the run artifacts |

## 1. Local prep

```sh
./scripts/bench/prepare_local.sh
```

Extracts `proof_inputs_*.json` from `batches.zip` (at the repo root) into
`bench-corpus/` (gitignored). ~1 GiB across 11 batches.

## 2. Launch a vast.ai instance

Recommended base image: **`nvidia/cuda:12.9.1-devel-ubuntu22.04`**
(matches the project Dockerfile). The CUDA *devel* tag is required — we
need `nvcc` to build the GPU prover. CUDA 13.x devel works too.

GPU: **≥ 24 GiB VRAM**. Anything from RTX 3090 / 4090 / A100 / H100 will
do; the build sets `CUDAARCHS=80;86;89;90` so the same binary runs on all.

Disk: budget **≥ 60 GiB** — Rust target dir alone is ~25 GiB after a
release build, plus 1 GiB corpus and a few GiB of LLVM/CUDA artifacts.

## 3. Upload

```sh
# from the repo root locally
rsync -avz --progress \
    --exclude target --exclude bench-results --exclude vk-cache --exclude .git \
    ./ <user>@<host>:~/eravm-airbender-verifier/
```

(The repo itself is needed because the build pulls workspace crates.)

## 4. Build the server (once per box)

```sh
ssh <user>@<host>
cd ~/eravm-airbender-verifier
bash scripts/bench/vastai_setup.sh
```

What it does (mirrors the project Dockerfile):

1. apt-get install clang, build-essential, cmake (Kitware ≥ 3.28), …
2. `rustup` + nightly-2026-02-10 + rust-src + llvm-tools-preview
3. `cargo install cargo-binutils`
4. `cargo install cargo-airbender` at the pinned rev
5. `cargo airbender build --project guest` → `guest/dist/app/`
6. `cargo build --release -p eravm-prover-server` → `target/release/eravm-prover-server`

Total: 20–40 min on a 16-core box, dominated by the cargo release build.

## 5. Run the benchmark

```sh
bash scripts/bench/run_fri_bench.sh
```

Defaults: corpus = `./bench-corpus`, results = `./bench-results/<utc-stamp>/`,
VK cache = `./vk-cache` (persisted across runs — the first batch always pays
~10–30 s of VK generation; subsequent batches and subsequent invocations
reuse the cached key).

Override knobs (env vars):

| var | default | purpose |
| --- | --- | --- |
| `CORPUS_DIR` | `./bench-corpus` | where `proof_inputs_*.json` live |
| `RESULTS_DIR` | `./bench-results/<utc-stamp>` | per-run artifact directory |
| `VK_CACHE_DIR` | `./vk-cache` | persisted across runs |
| `PROVER_BIN` | `target/release/eravm-prover-server` | server binary path |
| `GUEST_DIST` | `guest/dist/app` | guest ELF directory |
| `POLL_INTERVAL_MS` | `250` | how fast the server polls the coordinator |
| `MAX_WAIT_SECS` | `14400` (4 h) | overall timeout |
| `RUST_LOG` | `info` | server log level |

Blocks until the coordinator has marked every queued batch as completed,
or until the deadline / a prover crash.

## 6. Summarize

```sh
./scripts/bench/summarize.py bench-results/<utc-stamp>
```

Sample output:

```
 batch  wall(s)  peak_vram(MiB)  peak_gpu%  avg_gpu%  host_vm_hwm(MiB)  proof(bytes)
------  -------  --------------  ---------  --------  ----------------  ------------
 67901    234.5           20480         99      97.3             12345        524288
 67911    198.2           20480         99      96.8             12302        524288
...

runs=11  total_wall=2340.7s  median_wall=210.5s
peak_vram_overall=20480 MiB  median_peak_vram=20480 MiB
```

For machine-readable output: `summarize.py <dir> --format json`.

## Artifacts (per run)

| file | what |
| --- | --- |
| `context.txt` | GPU model, driver, prover version, git rev, CPU/RAM |
| `coordinator.log` | handoff/submission events |
| `coordinator_results.json` | **primary truth** for per-batch wall timing |
| `prover.log` | full server stdout/stderr |
| `gpu_samples.csv` | `nvidia-smi` rows every 250 ms |
| `host_samples.csv` | `/proc/<pid>/status` (`VmRSS`, `VmHWM`, `VmPeak`, threads) every 1 s |
| `sampler.log` | sampler errors, if any |

## Caveats

- **VK is generated on the first batch.** Its wall time will be inflated by 10–30 s on a cold `vk-cache`. Either discard the first row from the summary or run the smallest batch first as a warm-up.
- **VRAM is sampled, not exact peak.** 250 ms gaps can miss a sub-quarter-second spike; tighten via `GPU_INTERVAL_MS=100`.
- **Host RSS is one process** (the server). It handles all batches sequentially, so `host_vm_hwm_kb` ratchets up across batches — for per-batch RAM deltas, look at `host_max_rss_kb` (the current RSS at each sample) rather than the high-water mark.
- **JSON shape.** The captured `proof_inputs_*.json` files are bare `V1AirbenderVerifierInput` payloads; the coordinator stream-wraps them as `{"V1": …}` before sending. Pass `--no-wrap-v1` to the coordinator if your corpus already wraps.
- **vast.ai pricing.** A 24 GiB box at ~$0.50/h, ~30–40 min build + 30–60 min for an 11-batch run ≈ $1.
