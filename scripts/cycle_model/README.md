# Airbender cycle-cost model

Estimate how many Airbender RISC-V guest cycles a batch will consume when
re-executed by the verifier, from cheap features the sequencer can compute
natively (a `zksync_vm2` execution trace) — **without** running RISC-V during
sequencing. The sequencer uses this to predict whether a batch fits the
per-proof cycle limit.

Two halves, sharing one feature schema (`crates/cycle_model/src/features.rs`):

- **Offline calibration** — measure real batches (features + ground-truth guest
  cycles) and fit a cost table. Rust bench: `crates/cycle_model` (`cycle_bench`).
  Python fit: this directory.
- **Online estimator** — a Rust API (`zksync_cycle_model::estimate`) that applies
  the committed cost table to a live `zksync_vm2` trace. See
  [Using the estimator](#using-the-estimator-rust-api).

The committed, deployed model is `crates/cycle_model/model/cost_table.json`.

---

## Fitting / re-fitting the model

1. **Build the marker-instrumented guest** (calibration only — the `cycle-markers`
   feature emits verify() phase markers and relaxes the protocol-version pin so
   older FastVM-supported batches can be measured; it must NEVER ship in a proved
   guest):

   ```sh
   CC=/opt/homebrew/opt/llvm/bin/clang \
     cargo airbender build --project guest -- --features cycle-markers
   ```

2. **Get a corpus.** Batches must decode at this repo's wire format. `cycle_bench
   --check-only` reports each batch's protocol version (a fast pre-flight, no
   guest run).

3. **Produce the dataset** (native feature run + guest cycle measurement per
   batch; `--jobs N` parallelizes, per-batch `catch_unwind` isolates failures):

   ```sh
   cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
       --all-batches --batches-dir <dir> --app-bin-dir guest/dist/app \
       --jobs 8 --out artifacts/cycle_model
   ```

4. **Fit** (reads `dataset.json`, writes `cost_table.json` + `report.md`):

   ```sh
   python -m pip install -r scripts/cycle_model/requirements.txt
   python scripts/cycle_model/fit_cost_model.py \
       --dataset artifacts/cycle_model/dataset.json --out artifacts/cycle_model
   cat artifacts/cycle_model/report.md
   ```

   Which features drive each phase is declared in `PHASE_FEATURES` in
   `fit_cost_model.py`. `--pinned pinned.json` holds chosen costs fixed (e.g.
   crypto microbenchmarks) instead of fitting them.

## Updating the deployed model

The estimator compiles the cost table in via `include_str!`. To ship a new one:

```sh
cp artifacts/cycle_model/cost_table.json crates/cycle_model/model/cost_table.json
cargo test -p zksync_cycle_model            # unit tests re-parse the embedded table
```

A malformed table or a feature name not in the `FeatureId` enum fails the build /
tests (the JSON deserializes into typed `FeatureId` keys — a drift guard).

## Validating on a hold-out (do NOT fit on the test set)

Measure held-out batches into their own `dataset.json`, then apply the *already
fitted* table with **no refitting** and report out-of-sample error:

```sh
python scripts/cycle_model/eval_holdout.py \
    --cost-table crates/cycle_model/model/cost_table.json \
    --dataset artifacts/holdout/dataset.json --out artifacts/holdout
```

To confirm the **Rust** estimator reproduces those numbers (guards Rust/Python
drift):

```sh
CYCLE_MODEL_DATASET="$PWD/artifacts/holdout/dataset.json" \
  cargo test -p zksync_cycle_model --test estimator_holdout -- --ignored --nocapture
```

## Using the estimator (Rust API)

```rust
use zksync_cycle_model::{estimate, BatchContext, CycleFeatureTracer};

// 1. Attach the passive tracer while executing the batch on the fast VM.
//    It only observes (returns Continue, mutates nothing), so execution is
//    identical to a proved run. Clone it per tx into the tracer dispatcher.
let tracer = CycleFeatureTracer::new();
// ... run all transactions with `tracer.clone()` ...
let finished = vm.finish_batch(pubdata_builder);

// 2. Supply the batch-level drivers the opcode tracer cannot see — the
//    sequencer already has these from its storage view and the bytecodes it
//    is about to prove. (state_diff_count and pubdata_bytes are read from
//    `finished` automatically.)
let ctx = BatchContext {
    transaction_count,
    merkle_leaf_count,   // distinct storage slots touched = what the tree witnesses
    storage_key_count,
    used_bytecode_bytes,
    used_bytecode_count,
};

// 3. Estimate — no RISC-V execution.
let est = estimate(&tracer, &finished, &ctx);
if !est.fits(PER_PROOF_CYCLE_LIMIT) {
    // e.g. seal the batch early / split it
}
// est.total = predicted raw guest cycles; est.phases = per-phase breakdown.
```

`estimate` uses the embedded model; `estimate_with_model` takes a candidate table.
Note `merkle_leaf_count` is the count of distinct slots the batch touched (the
witness does not exist yet at sequencing time), so it is an estimate of the
calibrated witness quantity — validate the deployed path on real batches.

## Model shape & current accuracy

- **Predictors**: an aggregate `total → raw_cycles`, plus one per verify() phase
  (`setup`, `vm_execution`, `merkle_verification`, `commitment`), each
  `cycles = base + Σ coeff·feature`, fit by non-negative least squares.
- **Phase drivers**: `vm_execution` ← opcode-family + crypto counts;
  `merkle_verification` ← merkle_leaf_count + state_diff_count (proof + tree
  update); `setup` ← used_bytecode_bytes/count + storage_key_count (bytecode
  hashing dominates, ~63 cyc/byte); `commitment` ← pubdata_bytes (near-constant).
- **Hold-out accuracy** (fit on 122 batches, validated on 49 disjoint): total
  R²=0.9991, MAPE 0.45%; setup & merkle_verification R²≈1.0000; commitment is
  near-constant so its R² is a low-variance artifact (absolute MAPE ~0.7%).

## Tests

```sh
python -m pytest scripts/cycle_model/test_fit_smoke.py   # fit on synthetic data
cargo test -p zksync_cycle_model                          # schema + model + estimator
```
