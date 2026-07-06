# gap-fixture

A foundry-zksync project that mints the **rolled-back-write gap** batch shape the
verifier regression `rolled_back_write_gap_is_harmless`
(`crates/airbender_verifier/tests/fail_closed.rs`) needs. See the corpus README
(`testdata/era_mainnet_batches/README.md`) for why the ordinary mainnet corpus
lacks this shape and can't be re-fetched.

`GapMaker.makeGaps(base)` performs, in one committed transaction, three net-zero
storage patterns on distinct slots (`base`, `base+1`, `base+2`): write-then-write-
back, SLOAD-then-net-zero-write, and (for comparison) a reverting write. A gap is a
slot the batch **writes but nets to zero** — excluded from `merkle_paths`
(= net writes ∪ protective reads) yet recorded in `read_storage_key` /
`is_write_initial`. The verifier serves such a slot empty; the test forges its
operator value and asserts the commitment is unchanged.

> A *reverting* write does **not** produce a gap: the fast VM drops a reverted
> write entirely from its world-diff (no net change and no recorded access). The
> write-back must be committed — hence the `netZero*` patterns. `makeGaps` runs all
> three so a single batch reveals which slot the pipeline surfaces as a gap.

## Prerequisites

- [foundry-zksync](https://github.com/matter-labs/foundry-zksync) (`forge`/`cast`
  with EraVM support).
- A running **zksync-era** node that also runs `airbender_proof_data_handler`
  (a plain `anvil-zksync` won't serve verifier inputs — you need the sequencer that
  produces `AirbenderVerifierInput`). Have its RPC URL and a funded private key.

## Setup

```sh
cd tools/gap-fixture
forge install foundry-rs/forge-std --no-commit
```

## Run

```sh
export RPC_URL=http://localhost:3050          # your zksync-era L2 RPC
export PRIVATE_KEY=0x...                       # funded key
# optional: export GAP_BASE=0x...              # defaults to a fixed keccak constant

forge script script/GapMaker.s.sol:DeployAndMakeGap \
    --zksync --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
```

Note the tx hash, then find the **L1 batch** it landed in:

```sh
cast receipt <tx-hash> --rpc-url "$RPC_URL" --field l1BatchNumber
```

## Export the fixture

With the batch number `N`, export its verifier input and name the corpus file after
`N` (set `GAP_BATCH = N` in `fail_closed.rs`):

```sh
# from repo root, against the proof data handler endpoint:
curl -s "$BATCH_API_URL/airbender/proof_inputs_no_lock/N" \
  | cargo run -p zksync_cli_utils --bin json_to_batch > testdata/era_mainnet_batches/binary/N.bin
gzip testdata/era_mainnet_batches/binary/N.bin
git -C testdata/era_mainnet_batches lfs track "binary/N.bin.gz" 2>/dev/null || true
git add testdata/era_mainnet_batches/binary/N.bin.gz
```

## Verify + enable

Confirm a gap is present (this is exactly what the test asserts):

```sh
cargo test -p zksync_airbender_verifier --test fail_closed \
    -- --ignored --nocapture rolled_back_write_gap_is_harmless
```

It prints `gap fixture N gap reads (...): <n>` — `n` must be ≥ 1. Then delete the
`#[ignore]` on `rolled_back_write_gap_is_harmless` and commit both the fixture and
the test change.

> If the read-gap count is 0, inspect which of the three `makeGaps` slots (`base`,
> `base+1`, `base+2`) landed in `read_storage_key`/`is_write_initial` but not
> `merkle_paths`, and keep only that pattern. The committed `netZero*` patterns are
> the ones expected to work; the reverting `revertWrite` is included only for
> contrast (the fast VM drops reverted writes, so it should leave no gap).
