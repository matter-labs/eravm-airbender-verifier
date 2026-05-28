# Vast.ai Test Runner

This directory contains the reproducible setup for running the PR #17 GPU-heavy
integration tests on Vast.ai without hand-installing dependencies on the rented
machine.

## Build the Base Image

Build and push from a Linux/amd64 Docker builder:

```bash
scripts/vast/build-and-push-image.sh \
  --image ghcr.io/<owner>/eravm-airbender-verifier-vast:pr17-YYYYMMDD \
  --push
```

The image installs the CUDA/Rust/tooling environment and keeps
`era-bellman-cuda` source at `/opt/era-bellman-cuda`. The runtime script builds
`era-bellman-cuda` for the rented GPU's detected CUDA architecture, exports the
resulting library path, and builds/tests `eravm-prover-server` with
`--features snark_gpu`. This costs a small amount of runtime but avoids
mismatches on newer GPUs.

The preferred path for this branch is the `vast-base-image` GitHub Actions
workflow, which builds on an amd64 runner and pushes to GHCR. Use the printed
digest-pinned reference in the Vast template.

If you know the target GPU architecture and want to prebuild bellman CUDA inside
the image:

```bash
scripts/vast/build-and-push-image.sh \
  --image ghcr.io/<owner>/eravm-airbender-verifier-vast:pr17-YYYYMMDD \
  --prebuild-bellman-cuda \
  --bellman-cuda-archs '80;89;90' \
  --push
```

## Vast Template

Create a Vast template with:

- Docker image: the pushed image tag or digest.
- Launch mode: SSH.
- Disk: at least `300 GB`; `500 GB` gives more room for retries.
- On-start script:

```bash
mkdir -p /workspace/cache /workspace/artifacts
```

Do not put the full test run in the on-start script for the first attempt. SSH
in and run it inside `tmux` so the instance can be inspected if something fails.

## Run on the Instance

After SSH:

```bash
tmux new -s pr17

REPO_REF=main \
EXPECTED_SHA=<expected-commit-sha> \
run-pr17-integration
```

The script defaults to cloning `matter-labs/eravm-airbender-verifier`, where
this branch is pushed. To test a different remote, set `REPO_URL` as well. To protect
against accidentally testing the wrong commit:

```bash
REPO_URL=https://github.com/matter-labs/eravm-airbender-verifier.git \
REPO_REF=main \
EXPECTED_SHA=<expected-commit-sha> \
run-pr17-integration
```

To run only the FRI→SNARK test first:

```bash
TEST_FILTER=prover_server_proves_fri_then_snark \
run-pr17-integration
```

To run the stricter same-process multi-batch `fri-snark` test:

```bash
BATCH_FILES=506093.bin.gz,506094.bin.gz,506095.bin.gz \
TEST_FILTER=prover_server_proves_multi_batch_fri_snark \
run-pr17-integration
```

To generate reusable FRI proof fixtures for later `snark-only` sizing runs:

```bash
BATCH_FILES=506093.bin.gz,506094.bin.gz,506095.bin.gz \
TEST_FILTER=prover_server_generates_fri_fixtures \
run-pr17-integration
```

The fixtures are written to `/workspace/fri-fixtures` by default and archived as
`fri-fixtures.tar.gz` in the run artifact directory.

To replay existing fixtures through a single long-lived `snark-only` prover:

```bash
IT_FRI_FIXTURES_DIR=/workspace/fri-fixtures \
TEST_FILTER=prover_server_replays_snark_only_fixtures \
run-pr17-integration
```

To split the SNARK wrapper across two processes so phase 3 (PLONK SNARK) runs
on a GPU that no longer holds the phase 1/2 buffers — useful on cards where
the resident risc-wrapper pool plus the PLONK setup don't fit together (e.g.
the 5090 at 32 GB):

```bash
IT_FRI_FIXTURES_DIR=/workspace/fri-fixtures \
TEST_FILTER=host_split_compression_then_snark_in_separate_processes \
run-pr17-integration
```

The test runs the `eravm-prover-host` binary as two children: process A does
`prove-compression` (phases 1+2) and exits — exit *is* the GPU memory release
— and process B does `prove-snark-from-compression` on a clean device. The
runner builds the host binary alongside the server when this test is
selected; `--release --features snark_gpu` is required.

Logs are written under `/workspace/artifacts/<timestamp>/run.log`.

`BATCH_FILES` is passed to `scripts/fetch_lfs_batches.sh` and then exposed to
the test binary as `IT_BATCH_FILES`. It defaults to `506093.bin.gz`.

GPU metrics are sampled with `nvidia-smi` once per second by default. Each run
artifact directory includes:

- `gpu-samples.csv` for GPU utilization, memory, power, and temperature.
- `gpu-process-samples.csv` for per-process GPU memory.
- `gpu-summary.txt` with the peak observed GPU memory sample.

For long FRI batches, override the proof wait timeout:

```bash
IT_FRI_PROOF_TIMEOUT_SECS=7200 \
BATCH_FILES=506093.bin.gz,506094.bin.gz,506095.bin.gz \
TEST_FILTER=prover_server_generates_fri_fixtures \
run-pr17-integration
```

The runner defaults FRI fixture generation to `3600` seconds per batch and other
FRI waits to `1200` seconds. `IT_SNARK_PROOF_TIMEOUT_SECS` defaults to `3600`.

The script downloads `setup_compact.key` by default, matching the latest PR's
`snark_gpu` build. Override `SNARK_TRUSTED_SETUP_URL` or set
`IT_SNARK_TRUSTED_SETUP` when you need a different CRS file.

The ignored integration tests run with `--test-threads=1` by default. Each test
can spawn a prover that takes most of the GPU memory, so running both tests in
parallel can fail with `cudaErrorMemoryAllocation`. Override with `TEST_THREADS`
only for subsets that are known not to contend for the same GPU.

## Stop Conditions

- Stop after 15 minutes if the instance cannot pull the image or SSH is unusable.
- Stop after 30 minutes if diagnostics, repository clone, or batch fetch fail.
- Stop after 90 minutes if the build is stuck without meaningful progress.
- Stop after 3 hours unless a test is clearly close to completion.
- Destroy the Vast instance when done.
