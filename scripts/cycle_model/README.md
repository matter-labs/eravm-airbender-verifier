# Airbender cycle-cost model

Estimate how many Airbender RISC-V guest cycles a batch will consume when
re-executed by the verifier, from cheap features the sequencer can compute
natively (a `zksync_vm2` execution trace) — **without** running RISC-V during
sequencing. The sequencer uses this to predict whether a batch fits the
per-proof cycle limit.

Two halves, sharing one feature schema:

- **Online estimator** (`crates/cycle_estimator`, crate
  `zksync-era-airbender-cycles-estimator`) — a lean Rust API (`estimate`) the
  sequencer calls to apply the committed cost table to a live `zksync_vm2` trace.
  See [Using the estimator](#using-the-estimator-rust-api).
- **Offline calibration** (`crates/cycle_model` + this directory) — measure real
  batches (features + ground-truth guest cycles) and fit the cost table. Rust
  bench: `cycle_bench`; Python fit: `fit_cost_model.py`.

The committed, deployed model is `crates/cycle_estimator/model/cost_table.json`.

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
cp artifacts/cycle_model/cost_table.json crates/cycle_estimator/model/cost_table.json
cargo test -p zksync-era-airbender-cycles-estimator   # re-parses the embedded table
```

A malformed table or a feature name not in the `FeatureId` enum fails the build /
tests (the JSON deserializes into typed `FeatureId` keys — a drift guard).

## Validating on a hold-out (do NOT fit on the test set)

Measure held-out batches into their own `dataset.json`, then apply the *already
fitted* table with **no refitting** and report out-of-sample error:

```sh
python scripts/cycle_model/eval_holdout.py \
    --cost-table crates/cycle_estimator/model/cost_table.json \
    --dataset artifacts/holdout/dataset.json --out artifacts/holdout
```

CI guards against regressions with a frozen snapshot: the
`model_regression` test in `crates/cycle_estimator` asserts the embedded model
still predicts a committed set of measured batches within tolerance (no corpus
needed). When you ship a new model, run it and — only if the guest/verifier moved
real cycle counts — refresh the fixture:

```sh
cargo test -p zksync-era-airbender-cycles-estimator --test model_regression
# refresh fixture (rarely): regenerate from a fresh measured dataset.json
```

## Using the estimator (Rust API)

The estimator lives in the lean `zksync-era-airbender-cycles-estimator` crate
(deps: `zksync_vm2` + serde/serde_json/anyhow only), so a sequencer can depend on it without the
proving stack.

```rust
use zksync_era_airbender_cycles_estimator::{estimate, BatchContext, CycleFeatureTracer};

// 1. Attach the passive tracer while executing the batch. Clone it per tx into
//    the VM's tracer dispatcher; it only observes, so execution is unchanged.
let tracer = CycleFeatureTracer::new();
// ... run all transactions with `tracer.clone()` ...
let finished = vm.finish_batch(pubdata_builder);

// 2. Estimate — no RISC-V execution. Pass the two batch scalars from `finished`
//    plus the batch-level drivers the opcode tracer can't see (from the storage
//    view + the bytecodes being proved).
let ctx = BatchContext {
    transaction_count,
    merkle_leaf_count,   // distinct storage slots touched = what the tree witnesses
    storage_key_count,
    used_bytecode_bytes,
    used_bytecode_count,
};
let est = estimate(
    &tracer,
    finished.pubdata_input.map_or(0, |p| p.len() as u64),
    finished.state_diffs.map_or(0, |s| s.len() as u64),
    &ctx,
);

// 3. Decide — fail safe. `fits` rejects the batch if it used a precompile the
//    model can't price (e.g. ec_pairing/modexp), and applies a safety margin.
if !est.is_reliable() { /* unpriced precompile — reject/split, don't trust `total` */ }
if !est.fits(PER_PROOF_CYCLE_LIMIT, /*margin*/ 1.10) { /* seal early / split */ }
// est.total = predicted effective/native cycles; est.conservative(m) = margin-padded; est.phases = breakdown.
```

Notes:
- `estimate` uses the embedded model; `estimate_with_model` takes a candidate table.
- `CycleFeatureTracer` is a **vm2 (fast VM)** tracer. The legacy VM has a
  different tracer interface, so the legacy path needs a sibling tracer filling
  the same `FeatureVector` (the model/estimator are VM-agnostic).
- `merkle_leaf_count` is the distinct-slots-touched count (the witness does not
  exist yet at sequencing time) — an estimate of the calibrated witness
  quantity, so validate the deployed path on real batches.

## Staying on the safe side

Under-estimating is the costly failure (an over-limit batch that can't be
proved), so the estimate is used conservatively:

1. **Coverage guard** — `is_reliable()` / `fits()` fail safe when the batch uses
   a `SAFETY_CRITICAL_FEATURES` precompile the model prices at ~0 (a coefficient
   the corpus never constrained, e.g. ec_pairing/modexp). A margin can't rescue a
   zero coefficient, so such a batch is rejected outright rather than trusted.
2. **Safety margin** — `conservative(margin)` / `fits(limit, margin)` pad the
   prediction. The model systematically under-predicts a couple of percent
   (hold-out: 43/49 batches, worst −1.83%), so ~1.05–1.10 covers ordinary
   variance; pick per risk tolerance.
3. **Pin precompile costs** (below) so the priced set is sound and complete — the
   real fix behind the coverage guard.

### Pinning precompile costs (microbenchmarks)

keccak256/sha256/ecrecover are size-scaled from the trace, but their fitted
coefficients are in-sample/collinear, and secp256r1/modexp/ec_add/ec_mul/
ec_pairing are unpriced (absent from the corpus).

The fastest source is **zksync-os**, which already measured RISC-V-cycle native
costs for every precompile against the same airbender delegations — see
[`native_cost_conversion.md`](native_cost_conversion.md) for the derived costs in
our units and the conversion factor. Alternatively, measure directly and pin:

- Build a synthetic batch that runs N of one precompile (varying input size),
  measure guest cycles with the marker guest (`cycle_bench`), and divide by the
  feature count to get cycles-per-unit.
- Record results in a `pinned.json` (see `pinned.example.json`) and pass
  `--pinned pinned.json` to `fit_cost_model.py`. Features the corpus never
  exercised have no dataset column, so their pinned cost must be written into the
  committed `cost_table.json` directly (they are not fit).

Until pinned, the coverage guard is what keeps unpriced precompiles from silently
producing an under-estimate.

## Model shape & current accuracy

- **Predictors**: an aggregate `total → effective/native cycles` (= raw RISC-V
  cycles + Σ delegation·weight, Blake2 ×16 / keccak ×4 / bigint ×4 per zksync-os),
  plus one per verify() phase (`setup`, `vm_execution`, `merkle_verification`,
  `commitment`) over raw phase cycles, each `cycles = base + Σ coeff·feature`,
  fit by non-negative least squares. The total is the number to gate on.
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
cargo test -p zksync-era-airbender-cycles-estimator -p zksync_cycle_model
```
