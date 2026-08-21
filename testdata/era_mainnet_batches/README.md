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

## Which Batches Decode On Which Build

The corpus spans several protocol/wire-format eras, and they are **not
interchangeable**. Check this table before wondering why a batch fails to load —
`cargo run -p zksync_cycle_model --bin cycle_bench -- --check-only` reports each
batch's protocol version without running a guest.

| Set | Count | Loads on a default build? | Notes |
| --- | --- | --- | --- |
| `84730`–`84732` etc. | 8 | **yes** | What CI uses (`CI_BATCHES`). The reference set for anything that must work out of the box. |
| `513601`–`513649` | 49 | no — needs `relax-version-pin` | Protocol **v29** payloads in the current wire format: they bincode-decode fine, then the version pin rejects them. The cycle-model hold-out set. |
| `506077`–`506204` | 127 | **no — cannot be loaded at all** | **Pre-v31 wire format.** These fail in `bincode` decode itself (`invalid utf-8 sequence`), which no feature flag can work around. Kept for history; treat them as unreadable by current code. |
| `900065` | 1 | yes | Synthetic read-heavy fixture, see below. |

The practical consequence: the 122-row training dataset behind the committed cost
table was measured from the `506xxx` set, so that **fit is not reproducible from
these batches on current code** — which is exactly why the measured dataset is
committed at `testdata/cycle_model/dataset.json`. Re-measuring a training corpus
today means using `513xxx` (with `relax-version-pin`) or exporting fresh v31 batches
— see [`docs/generating-batches.md`](../../docs/generating-batches.md).

## Cycle-Model Hold-Out Set (`513601`–`513649`)

49 consecutive mainnet batches, ~296 MB total (3.4–8.8 MB each, median 5.8),
reserved as the **hold-out** for the Airbender cycle-cost model: the committed
`cost_table.json` is fit on `506xxx` and validated here, so fitting on these
batches would destroy the only out-of-sample signal the model has.

They are in-repo so the fixture at
`crates/cycle_estimator/tests/fixtures/holdout_513xxx.json` — the frozen
features + measured cycles that `model_regression.rs` guards in CI — stays
regenerable. That test needs no batches; these are for the rarer case of
refreshing it after a guest change moves real cycle counts. Without them a refresh
could only regenerate the batches someone happened to still have, quietly
shrinking the guard's coverage.

Because they are protocol v29, measuring them requires the calibration build
(`--features relax-version-pin`; see `docs/benchmarking.md`).

## Storage-Soundness Regressions (no synthetic fixture needed)

`crates/airbender_verifier/tests/fail_closed.rs` guards the verifier's storage-view
soundness against the ordinary `84730` corpus. All three regressions tamper `84730`
directly and need no special fixture; none is ignored.

`omitted_merkle_path_read_cannot_inject_prestate` originally relied on an honest gap
batch (a fully rolled-back write, mainnet batch 506155, pre-v31). We could not
regenerate that batch on v31 — the batches we produced don't reproduce the gap — so
the test synthesizes the gap adversarially instead.

## Synthetic Read-Heavy Batch (`900065`)

`900065.bin.gz` is **not** a mainnet batch. It is a synthetic v31 batch generated
from a local Era node with 140,059 unique cold storage reads (the `9000xx` prefix
marks it synthetic; `65` is its source batch number) — see
[`docs/generating-batches.md`](../../docs/generating-batches.md) for how to produce
one. It is the regression fixture
for the streaming Merkle-proof verification (the RAM-exhaustion DoS fix): the
pre-fix path expanded every storage proof to full depth at once (~1.15 GiB here),
OOMing the bounded guest heap.

`host/tests/integration_test.rs::host_runs_read_heavy_batch_without_guest_oom`
runs it through the transpiler (the actual compiled guest under its bounded memory
model, CPU only — no GPU), so a regression to eager expansion OOMs the guest there.
Fetch it and run explicitly:

```sh
./scripts/fetch_lfs_batches.sh 900065.bin.gz
cargo airbender build --project guest
cargo test -p eravm-prover-host --test integration_test \
  -- --ignored --nocapture host_runs_read_heavy_batch_without_guest_oom
```

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
