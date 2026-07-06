# Era Mainnet Batch Corpus

This directory is the repository-owned home for reproducible Era mainnet batch inputs.
Each batch is stored as its own `*.bin.gz` Git LFS object so we can keep the full corpus in the repository without forcing every clone or CI run to download gigabytes of data up front.

## Layout

- `binary/<batch>.bin.gz`: compressed batch payloads, one LFS object per batch.
- CI hardcodes a small curated subset via the `CI_BATCHES` environment variable in `.github/workflows/ci-check.yaml`.

## Why These Files Are Not Pulled By Default

The repository ships [`.lfsconfig`](../../.lfsconfig) with `lfs.fetchexclude = testdata/era_mainnet_batches/binary/**`.
That keeps normal clones lightweight: Git checks out only pointer files until you explicitly request the batches you need.

If `git lfs` is missing, install it first:

Ubuntu:

```sh
sudo apt-get update
sudo apt-get install git-lfs
git lfs install
```

macOS:

```sh
brew install git-lfs
git lfs install
```

Fetch one batch:

```sh
./scripts/fetch_lfs_batches.sh 84730.bin.gz
```

Fetch the curated CI subset:

```sh
./scripts/fetch_lfs_batches.sh 84730.bin.gz,84731.bin.gz,84732.bin.gz
```

Fetch everything tracked in this directory:

```sh
./scripts/fetch_lfs_batches.sh --all
```

## Importing Existing Local Data

If you already have raw `*.bin` files outside the repository, compress and stage them into LFS with:

```sh
./scripts/import_mainnet_batches.sh \
  --source-dir /home/popzxc/workspace/airbender/storage/era_mainnet_batches/binary \
  --all
```

The import script intentionally stages only the batch payloads. It does not auto-commit, because you may want to review the resulting pointer changes before creating a commit.

## Storage-Soundness Regressions (no synthetic fixture needed)

`crates/airbender_verifier/tests/fail_closed.rs` guards the verifier's storage-view
soundness against the ordinary `84730` corpus. All three regressions tamper `84730`
directly and need no special fixture; none is ignored.

`omitted_merkle_path_read_cannot_inject_prestate` originally relied on an honest gap
batch (a fully rolled-back write, mainnet batch 506155, pre-v31). We could not
regenerate that batch on v31 — the batches we produced don't reproduce the gap — so
the test synthesizes the gap adversarially instead.

## Running Tools Against This Corpus

Both the VM compare tool and the host runner accept this directory directly.
They read plain `*.bin` files for backwards compatibility, but the CLI expects one or more concrete filenames via `--batch-files`, such as `84730.bin` or `84730.bin.gz`. The repo-first workflow is the compressed one.
The default `--batches-dir` assumes you run `cargo run -p ...` from the workspace root; otherwise, pass `--batches-dir` explicitly.

Compare one batch:

```sh
cargo run --release -p zksync_vm_compare --bin vm_compare -- --batch-files 84730.bin.gz
```

Run the guest-host simulation for one batch:

```sh
cargo airbender build --project guest
cargo run --release -p eravm-prover-host -- --action run --batch-files 84730.bin.gz
```

Replay every fetched batch in compare mode:

```sh
cargo run --release -p zksync_vm_compare --bin vm_compare -- --all-batches
```

Process every fetched batch in host prove mode:

```sh
cargo run --release -p eravm-prover-host -- --action prove --all-batches
```
