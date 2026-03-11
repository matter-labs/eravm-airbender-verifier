# eravm-airbender-verifier

This repository combines the reduced Era verifier libraries and the Airbender proving app in one workspace.

## Layout

- `crates/`: reduced verifier libraries extracted from `zksync-era` (entrypoint crate: `zksync_tee_verifier`).
- `guest/`: Airbender guest program that reads `TeeVerifierInput` and runs `verify()`.
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
