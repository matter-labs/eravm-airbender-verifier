# EraVM Airbender Verifier

This repository combines reduced EraVM verifier libraries with an Airbender guest and host proving app.
It is used to reproduce ZKsync Era mainnet batch verification, compare VM execution, generate Airbender
FRI proofs, and wrap those proofs into SNARK proofs.

## Layout

- `crates/`: reduced verifier libraries extracted from `zksync-era` (entrypoint crate: `zksync_airbender_verifier`).
- `guest/`: Airbender guest program that reads `AirbenderVerifierInput` and runs `verify()`.
- `host/`: host runner/prover app for batch execution and proof generation.
- `testdata/era_mainnet_batches/`: compressed mainnet batch corpus tracked via Git LFS.

## Quick Start

Build guest artifacts:

```sh
cargo airbender build --project guest
```

Install Git LFS if `git lfs` is not available yet:

Ubuntu:

```sh
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
sudo apt-get update
sudo apt-get install git-lfs
git lfs install
```

macOS:

```sh
brew install git-lfs
git lfs install
```

Fetch one compressed mainnet batch from Git LFS:

```sh
./scripts/fetch_lfs_batches.sh 506093.bin.gz
```

Compare legacy and fast VM execution on that batch:

```sh
cargo run --release -p zksync_vm_compare --bin vm_compare -- --batch-files 506093.bin.gz
```

## VM Compare Finding Validation

`vm_compare` is the batch-level validator for legacy VM vs FastVM behavior. It
loads full `V1AirbenderVerifierInput` batch files, runs both VMs, and reports
trace or output divergences. It also treats a panic in only one VM as a
divergence instead of aborting the whole run.

Use raw `vm_compare` when you want to inspect one or more concrete batches:

```sh
cargo run --release -p zksync_vm_compare --bin vm_compare -- \
  --batch-files 506093.bin.gz
```

Use `vm_compare_findings` when you have a list of audit findings and want a
repeatable status check for which ones have full-batch reproducers:

```sh
cargo run --release -p zksync_vm_compare --bin vm_compare_findings -- \
  --manifest /path/to/vm-compare-findings.json \
  --batches-dir /path/to/repro-batches \
  --ledger /path/to/found-divergences.md \
  --markdown
```

The manifest is bookkeeping over `vm_compare`; it does not create repros. A
minimal manifest looks like this:

```json
{
  "findings": [
    {
      "id": "D-001",
      "title": "example reachable divergence",
      "vm_compare": {
        "status": "batch_reproducer",
        "batch_files": ["900001.bin"],
        "expected_substrings": ["VM panic mismatch"],
        "reason": "Brief explanation of what the batch exercises"
      }
    },
    {
      "id": "D-002",
      "title": "example non-representable finding",
      "vm_compare": {
        "status": "not_representable",
        "reason": "Requires custom system contract bytecode, so it is outside accepted vm_compare repro rules"
      }
    }
  ]
}
```

Supported statuses:

- `batch_reproducer`: `batch_files` are resolved under `--batches-dir` and must
  make `vm_compare` diverge. `expected_substrings` are optional but recommended
  so the check proves the expected divergence, not just any divergence.
- `needs_batch_reproducer`: tracked as pending; the command prints the reason
  but does not fail.
- `not_representable`: tracked as intentionally not reproducible in
  `vm_compare`; include the reachability or tooling blocker in `reason`.

If `--ledger` is provided, `vm_compare_findings` also checks that every
`## D-...` entry in the ledger has a manifest entry and vice versa. The command
exits non-zero if a `batch_reproducer` does not diverge, if an expected
substring is missing, or if ledger coverage does not match.

For audit validation, prefer full-batch reproducers that keep the real
bootloader, default AA, EVM emulator, and other base system contracts intact.
Reproducer batches and audit-local manifests can live outside the repository
unless the team intentionally wants to track those artifacts.

Run host execution:

```sh
cargo run --release -p eravm-prover-host -- --action run --batch-files 506093.bin.gz
```

Run host proving:

```sh
cargo run --release -p eravm-prover-host -- --action prove --batch-files <number>.bin.gz
```

Process all available batches:

```sh
cargo run --release -p eravm-prover-host -- --action prove --all-batches
```

## Mainnet Batch Corpus

The repository stores reproducible batch inputs in `testdata/era_mainnet_batches/binary/*.bin.gz`.
Those files are tracked via Git LFS and excluded by default via [`.lfsconfig`](.lfsconfig), so a normal clone keeps only small pointer files until you explicitly fetch the batches you want.

If `git lfs` is missing, install it first:

Ubuntu:

```sh
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
sudo apt-get update
sudo apt-get install git-lfs
git lfs install
```

macOS:

```sh
brew install git-lfs
git lfs install
```

Fetch the same curated batches that CI uses:

```sh
./scripts/fetch_lfs_batches.sh 506093.bin.gz,506155.bin.gz,506169.bin.gz
```

Fetch every tracked batch:

```sh
./scripts/fetch_lfs_batches.sh --all
```

The default `--batches-dir` assumes you run these `cargo run -p ...` commands from the workspace root. If you invoke the binaries from another directory, pass `--batches-dir` explicitly.

Import the existing local corpus into the repo as compressed Git LFS objects:

```sh
./scripts/import_mainnet_batches.sh \
  --source-dir /home/popzxc/workspace/airbender/storage/era_mainnet_batches/binary \
  --all
```

More detailed batch-data instructions live in [testdata/era_mainnet_batches/README.md](testdata/era_mainnet_batches/README.md).

## Full e2e proving flow

If you're going to use GPU proving for SNARK, you also need to set up bellman CUDA.

Important: right now, bellman-cuda supports ONLY CUDA 12, while airbender can work with both 12 and 13.
So if you have CUDA 13 installed, your options are either to rely on CPU proving if acceptable, or install CUDA 12 instead.

```bash
# `era-bellman-cuda` & SNARK wrapper use old code that doesn't always respect `CUDA_HOME` and instead
# on linux checks `/usr/local/cuda`
echo $CUDA_HOME
# If your output is not `/usr/local/cuda`, you might want to create a symlink, e.g. `sudo ln -s /opt/cuda /usr/local/cuda`.

if [ ! -d "era-bellman-cuda" ]; then
    git clone https://github.com/matter-labs/era-bellman-cuda.git
else
    echo "era-bellman-cuda repository already exists. Skipping clone."
fi
# Now cmake will find the CUDA compiler (nvcc) via the updated PATH
cmake -Bera-bellman-cuda/build -Sera-bellman-cuda/ -DCMAKE_BUILD_TYPE=Release
cmake --build era-bellman-cuda/build/ -j16

BELLMAN_CUDA_DIR="$(pwd)/era-bellman-cuda"

# === IMPORTANT ===
# Add BELLMAN_CUDA_DIR to your *rc file (e.g. `.bashrc` / `.zshrc`)!
```
Then you can use the following flow:

```bash
# Clone the repo and set up the branch (check out the required branch)
git clone https://github.com/matter-labs/eravm-airbender-verifier.git
cd eravm-airbender-verifier
git checkout <desired_branch> # e.g. popzxc-snark-integrated-properly at the time of writing

# Download artifacts for proving
git lfs install

# Set up CRS key and stack for SNARK proving
# IMPORTANT: CPU/GPU use different keys
curl https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_2\^24.key --output setup.key &
curl https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_compact.key --output setup_gpu.key

ulimit -s unlimited

# Generate FRI proof
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release -p eravm-prover-host --features snark_gpu -- prove-fri --batch-files 506093.bin.gz --output-dir ./artifacts/proofs

# Generate SNARK proof
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release -p eravm-prover-host --features snark_gpu -- prove-snark --proof-files ./artifacts/proofs/batch-506093/fri_proof.json  --output-dir ./artifacts/proofs --trusted-setup setup_gpu.key
```

If you need to save intermediate SNARK artifacts:

```bash
# On CPU
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release -p eravm-prover-host -- prove-snark --proof-files ./artifacts/proofs/batch-506093/fri_proof.json  --output-dir ./artifacts/proofs --trusted-setup setup.key --save-intermediates

# On GPU
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release -p eravm-prover-host --features snark_gpu -- prove-snark --proof-files ./artifacts/proofs/batch-506093/fri_proof.json  --output-dir ./artifacts/proofs --trusted-setup setup_gpu.key --save-intermediates
```

Note: `--features snark_gpu` is not technically required, it enables GPU SNARK proving, without it FRI proving will still be done on GPU, but SNARK wrapping will be done on CPU. If you use CPU, don't forget to use the correct CRS key.

## Policies

- [Security policy](SECURITY.md)
- [Contribution policy](CONTRIBUTING.md)

## License

Licensed under either of:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Official Links

- [Website](https://zksync.io/)
- [GitHub](https://github.com/matter-labs)
- [ZK Credo](https://github.com/zksync/credo)
- [Twitter](https://twitter.com/zksync)
- [Twitter for Developers](https://twitter.com/zkSyncDevs)
- [Discord](https://join.zksync.dev/)
- [Mirror](https://zksync.mirror.xyz/)
- [Youtube](https://www.youtube.com/@zkSync-era)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
