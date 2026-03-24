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

Run host proving and export the final Airbender proof JSON that `zkos-wrapper` consumes:

```sh
cargo run --release -p eravm-prover-host -- \
  --action prove \
  --batch-files <number>.bin.gz \
  --proof-output-dir /tmp/airbender-proofs
```

Process all available batches:

```sh
cargo run --release -p eravm-prover-host -- --action prove --all-batches
```

## SNARK Wrapping

`eravm-airbender-verifier` now has a thin bridge binary that forwards a final Airbender proof
into the sibling `zkos-wrapper` repository.

The current integration is intentionally file-based:

- `eravm-prover-host` exports a wrapper-compatible `UnrolledProgramProof` JSON file.
- `snark_wrap` shells out to `zkos-wrapper`'s existing `prove-all` CLI flow.
- By default, `snark_wrap` uses this repository's verifier guest `app.bin` and `app.text`
  when computing the wrapper's binary commitment.
- This keeps the integration small while `airbender_host` still keeps the final proof payload
  behind its outer `Proof::Real` wrapper and the wrapper carries its own dependency graph.

Export a raw final proof for a batch:

```sh
cargo run --release -p eravm-prover-host -- \
  --action prove \
  --batch-files 506093.bin.gz \
  --proof-output-dir /tmp/airbender-proofs
```

Wrap that proof into the sibling wrapper SNARK pipeline:

```sh
cargo run --release -p eravm-prover-host --bin snark_wrap -- \
  --proof /tmp/airbender-proofs/506093.json \
  --output-dir /tmp/snark-output \
  --trusted-setup /path/to/setup.key
```

Use `--save-intermediates` to keep the RISC-wrapper and compression outputs, and `--use-zk` to
enable the wrapper's zero-knowledge padding path. If you need to wrap proofs for a different
guest binary, override the default commitment inputs with `--bin ... --text ...`. If
`--trusted-setup` is omitted, the wrapper falls back to its fake testing CRS, which is not
suitable for production.

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
