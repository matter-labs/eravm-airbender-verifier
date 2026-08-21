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

> ### Status: refit on a reproducible corpus; three scope limits
>
> Refit 2026-08-21 on every batch current code can decode — 49× `513xxx` (v29) +
> `84730`/`84731`/`84732` (v31) + `900065` (v31 synthetic), measured in one run on
> one marker guest that `provenance.guest_sha256` identifies. The dataset is
> committed at `testdata/cycle_model/dataset.json` and the table **refits from it
> byte-identically**; its predecessor was fit on 176 batches of which ~122 were
> `506xxx`, a wire format that fails inside `bincode` decode on any current build,
> so that fit could not be reproduced or re-measured from the tree.
>
> - **Deliberately conservative by ~10%.** Over-predicts all 53 of its corpus,
>   +0.02% to +12.55% (MAPE 10.37%) — that is the cost floors, not error. The
>   unfloored fit scores 7.55%, and leave-one-out CV gives MAPE 8.19%, worst-over
>   +31.20%, **zero** under-predictions.
> - **The corpus is mostly Version29; production runs Version31.** The *guest* is
>   current either way, so the costs are current-guest costs; what is v29 is the
>   batch content of 49 of the 53 rows. The four v31 rows now over-predict +0.02%
>   to +0.77% — the predecessor UNDER-predicted three of them by 2.56%, which is
>   the safety gap this refit closes.
> - **Two gaps need a local era node:** the synthetic precompile set (six crypto
>   coefficients are pinned literals, not measurements) and re-measuring 8 of the 9
>   adversarial fixtures. See **[REFIT-RUNBOOK.md](REFIT-RUNBOOK.md)**.

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
       --dataset artifacts/cycle_model/dataset.json \
       --provenance artifacts/cycle_model/provenance.json \
       --out artifacts/cycle_model
   cat artifacts/cycle_model/report.md
   ```

   Which features drive each phase is declared in `PHASE_FEATURES` in
   `fit_cost_model.py`. `--precompile-dataset` residual-fits the precompile
   coefficients from synthetic precompile-heavy batches (see
   `scripts/precompile_calibration/`); `--tau` sets the asymmetric-loss expectile
   for the total fit.

   The fit **refuses to produce a table it cannot vouch for**. Three guards, each
   of which has a real failure behind it:

   | guard | fires when | why it is an error, not a warning |
   |---|---|---|
   | provenance | no `--provenance`/identity flags and no `--stale-reason` | an unstamped table is a model of an unknown guest; nothing downstream can detect its drift |
   | `REQUIRED_DATASET_FEATURES` | the dataset lacks a feature `PHASE_FEATURES` declares | the fit would silently drop it and re-park its cost on a collinear survivor — how the committed table lost its per-byte bytecode term |
   | precompile identifiability | a residual-fit precompile column has <3 tiers or max <100 units | the residual coefficient REPLACES the organic one, so an unidentifiable column prices that precompile at ~0 on a flood |

   Escape hatches for reference runs only: `--allow-missing-features`,
   `--allow-unidentified-precompiles`. A table produced with either must not be
   committed.

   Two blocks the fit emits besides the coefficients, both enforced downstream:
   `calibration` (the extrapolation envelope — arithmetic share + per-feature
   volume maxima, checked by `CostModel::extrapolated_features`) and `provenance`
   (checked by the estimator's `embedded_table_declares_its_calibration_identity`
   test). `TOTAL_EXCLUDE` keeps the aggregate predictor to features an *online*
   producer supplies; `total_prices_no_offline_only_feature` re-checks it in Rust.

## Updating the deployed model

The estimator compiles the cost table in via `include_str!`. To ship a new one,
FIRST check the candidate against the adversarial invariant (the Rust test only
guards the already-committed table — this is the pre-commit half):

```sh
python scripts/cycle_model/eval_adversarial.py \
    --cost-table artifacts/cycle_model/cost_table.json   # must exit 0
cp artifacts/cycle_model/cost_table.json crates/cycle_estimator/model/cost_table.json
cargo test -p zksync-era-airbender-cycles-estimator   # re-parses + regression-checks
```

A malformed table or a feature name not in the `FeatureId` enum fails the build /
tests (the JSON deserializes into typed `FeatureId` keys — a drift guard).

`eval_adversarial.py` mirrors the Rust gate exactly — both halves of the
envelope, the same `SHARE_EXTRAPOLATION_FACTOR` (1.2) and
`VOLUME_EXTRAPOLATION_FACTOR` (1.8), and the same margin. Keep them in lockstep,
or the pre-commit and post-commit gates can disagree about which tables are safe.

**Fixture vintage — the trap when the guest has moved.** `adversarial.json`'s
`effective_cycles` are measured on whatever guest was current when they were
taken (today: the pre-delegation one). A table refit against a *faster* guest
therefore fails the invariant **spuriously**: the actuals are stale, not the
table. Re-measure `adversarial.json` in the same pass as the refit, and never
reconcile the two by loosening the invariant — a table may only ship once the
invariant passes against **current-guest** actuals. See
[REFIT-RUNBOOK.md](REFIT-RUNBOOK.md).

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

**That test cannot see guest drift, by construction.** Both sides of its
comparison are frozen committed data, so when the guest gets faster the fixture
ages *with* the table and the test stays green while the model's real error grows
— the pre-delegation table reached 2.05× that way, with this test passing
throughout. Read it as "the table did not change unexpectedly", not as "the model
is accurate". Note also that its fixture is **in-sample by construction** for the
current table: it *is* the corpus, all 53 rows, so it is a tripwire, not a
validation. At this corpus size no hold-out is possible — every row is needed to
identify the coefficients — so leave-one-out CV is the honest generalization
number.

The check that separates *the model changed* from *the thing being modelled
changed* is the nightly drift job,
`.github/workflows/cycle-model-drift.yaml`: it re-measures with the **current**
guest and fails on excess *signed* error — under-prediction is the safety gate,
over-prediction the staleness gate. It is nightly, not per-PR, because it builds a
guest and runs real batches.

## Using the estimator (Rust API)

The model/estimator lives in the lean `zksync-era-airbender-cycles-estimator`
crate (deps: serde/serde_json only — no VM), so a sequencer can depend on it
without the proving stack; the passive vm2 tracer that fills the feature vector
is the sibling `zksync-era-airbender-cycles-tracer` crate.

```rust
use zksync_era_airbender_cycles_estimator::{estimate_from_features, BatchContext};
use zksync_era_airbender_cycles_tracer::CycleFeatureTracer;

// 1. Attach the passive tracer while executing the batch. Clone it per tx into
//    the VM's tracer dispatcher; it only observes, so execution is unchanged
//    (clones share one recorder).
let tracer = CycleFeatureTracer::new();
// ... run all transactions with `tracer.clone()` ...
let finished = vm.finish_batch(pubdata_builder);

// 2. Estimate — no RISC-V execution. Pass the two batch scalars from `finished`
//    plus the batch-level drivers the opcode tracer can't see.
let ctx = BatchContext {
    transaction_count,
    merkle_leaf_count,   // distinct storage slots touched = what the tree witnesses
};
let est = estimate_from_features(
    tracer.snapshot(),
    finished.pubdata_input.map_or(0, |p| p.len() as u64),
    finished.state_diffs.map_or(0, |s| s.len() as u64),
    &ctx,
);

// 3. Decide — fail safe. `fits` rejects the batch if it used a precompile the
//    model can't price or if it falls outside the calibration envelope, and
//    applies a safety margin.
if !est.is_reliable() { /* unpriced precompile — reject/split, don't trust `total` */ }
if !est.fits(PER_PROOF_CYCLE_LIMIT, /*margin*/ 1.10) { /* seal early / split */ }
// est.total = predicted effective/native cycles; est.conservative(m) = margin-padded;
// est.phases_insight = diagnostic breakdown — NEVER gate on it.
```

Notes:
- `estimate_from_features` uses the embedded model; to evaluate a candidate
  table, call `model.estimate(&assemble_feature_vector(...))` directly.
- `CycleFeatureTracer` is a **vm2 (fast VM)** tracer. The legacy VM has a
  different tracer interface, so the legacy path needs a sibling tracer filling
  the same `FeatureVector` (the model/estimator are VM-agnostic).
  **Forgetting to attach one is not silent**: a batch that claims transactions
  with an all-zero VM trace sets `trace_missing`, which makes `is_reliable()`
  false. Without that, the missing-tracer case looks exactly like a legitimately
  tiny batch (no crypto ⇒ nothing unpriced, zero arithmetic ⇒ inside the
  envelope) and every gate passes unconditionally.
- `merkle_leaf_count` is the distinct-slots-touched count (the witness does not
  exist yet at sequencing time). If you feed `FeatureId::StorageApplication`
  (`1·reads + 2·writes` over distinct slots — what both tracers accumulate), you
  are feeding **1.74×** the calibrated `|reads ∪ writes|` (measured over the
  49-batch corpus, range 1.64–1.81), which inflates the prediction **+3.0%**. It
  can never under-count, so it is safe — but it means the advertised MAPE does
  not describe the deployed path.
- `est.phases_insight` is diagnostic only. Besides the weak `setup` fit, its
  drivers are offline-only features, so on the deployed path they are
  structurally 0 — the `setup` number is not a rough estimate of setup cost, it
  is not an estimate of it at all.
- **The estimator is not a memory control.** On every measured decommit-flood
  shape the guest heap is exhausted at roughly a third of the gas the cycle
  budget binds at, with `fits()` still true. Peak memory needs its own criterion.

## Staying on the safe side

Under-estimating is the costly failure (an over-limit batch that can't be
proved), so the estimate is used conservatively:

1. **Coverage guard** — `is_reliable()` / `fits()` fail safe when the batch uses
   a `SAFETY_CRITICAL_FEATURES` precompile the model prices at ~0 (a coefficient
   the corpus never constrained, e.g. ec_pairing/modexp). A margin can't rescue a
   zero coefficient, so `fits()` reports no fit for such a batch rather than
   trusting it. Note what it does *not* catch: a precompile that IS present with
   a *meaningless* coefficient (see `ec_recover` above) sails through.

   > ⚠️ "Reports no fit" is not "is rejected" — refusing is the consumer's job,
   > and today's consumer does not. zksync-era's `CyclesCriterion` never calls
   > `fits()`, gates `ProofWillFail` on the estimate being *trusted*, and answers
   > distrust with `IncludeAndSeal`. A new consumer must implement the refusal
   > itself.
2. **Missing-trace guard** — an all-zero VM trace on a batch that claims work
   makes `is_reliable()` false (`trace_missing`), so an unwired tracer produces a
   loud signal instead of a small trustworthy-looking number. On era's current
   consumer that signal means *seal this batch now*, not *reject this tx* — see
   the warning above.
3. **Calibration envelope** — `is_within_calibration()` / `fits()` also decline a
   batch outside the corpus: by arithmetic *share* (the compute vector) and by
   raw *volume* on the fenced counters (`decommit_cycles`, `far_call`, `decommit`,
   `storage_write`, `uma_write`). The volume half declines to certify the
   bytecode/decommit shapes — a fresh flood sits 8.2× beyond the organic
   `decommit_cycles` max, a repeat-decode thrash 3.6× — where a linear model has
   nothing to say. A bare far-call flood it covers only at batch scale — ~437k
   calls per 80M-gas tx against a 859,529 trip, so two such txs trip it and one
   does not; below that the `far_call` floor over-prices the shape 2.4–4.0×. Do
   **not** retire the arithmetic-share half
   until the frame-churn / stack-clear vector has a cost feature of its own: that
   guard is the only thing rejecting it today, and it does so incidentally.
4. **Safety margin** — `conservative(margin)` / `fits(limit, margin)` pad the
   prediction. The model systematically under-predicts a couple of percent
   (hold-out: 43/49 batches, worst −1.83%), so ~1.05–1.10 covers ordinary
   variance; pick per risk tolerance.
5. **Calibrate precompile costs from synthetic batches** so the priced set is
   sound and complete — the real fix behind the coverage guard.

The invariant these add up to — *no batch is both trusted and materially
under-predicted* — is **conditional on host-side properties** of the verifier
(bytecode decoded once per batch, stack clearing not attacker-amplifiable,
`decommit_code` not repeat-hammered) and empirically scoped to the adversarial
fixtures. The premises are enumerated in `crates/cycle_estimator/src/lib.rs`;
each is a constraint on future verifier/vm2 changes, not a proven property.

### Calibrating precompile costs (synthetic batches)

Precompiles are ~0 in the organic mainnet corpus, so a joint fit lets collinear
generic-opcode features absorb their cost. Instead, drive precompile-dominated
batches on a local node (`scripts/precompile_calibration/`), measure their true
cycles with `cycle_bench`, and pass the resulting dataset to
`fit_cost_model.py --precompile-dataset`: the precompile coefficients are fit on
the RESIDUAL with the organic model frozen. The committed `cost_table.json` was
produced this way — every safety-critical precompile is priced.
([`native_cost_conversion.md`](native_cost_conversion.md) documents the
alternative zksync-os-derived costs used as a cross-check.)

For a precompile the corpus (organic + synthetic) has never exercised, the
coverage guard is what keeps it from silently producing an under-estimate.

## Model shape & current accuracy

- **Predictors**: an aggregate `total → effective/native cycles` (= raw RISC-V
  cycles + Σ delegation·weight, Blake2 ×16 / keccak ×4 / bigint ×4 per zksync-os),
  plus one per verify() phase (`setup`, `vm_execution`, `merkle_verification`,
  `commitment`) over raw phase cycles, each `cycles = base + Σ coeff·feature`,
  fit by non-negative least squares. The total is the number to gate on.
- **Phase drivers** *as declared* in `PHASE_FEATURES`: `vm_execution` ←
  opcode-family + crypto counts; `merkle_verification` ← merkle_leaf_count +
  state_diff_count (proof + tree update); `setup` ← used_bytecode_bytes/count +
  storage_key_count (bytecode hashing dominates, ~63 cyc/byte measured);
  `commitment` ← pubdata_bytes (near-constant).
- **A history worth knowing before the next refit.** An earlier table's `setup`
  block silently lost all three bytecode/storage-key columns, because the fit
  intersected its declared feature list with the dataset's columns and continued
  without them. The per-byte cost did not vanish, it changed **carrier**: `total`
  priced `decommit_cycles` at 9,732 (= 152.1 cyc/byte) where it had priced
  `used_bytecode_bytes` at 152.4. Those two are collinear over the corpus
  (`decommit_cycles × 64 / used_bytecode_bytes ∈ [0.987, 0.996]`, corr 1.0000), so
  NNLS was free to pick either — and it happened to pick the one an online
  producer can supply. Luck, not design. `TOTAL_EXCLUDE` +
  `total_prices_no_offline_only_feature` now make that outcome mandatory, and
  `REQUIRED_DATASET_FEATURES` makes the silent drop impossible to repeat. The
  current table carries all three drivers again.
- **Why `phases_insight` still must never gate.** Not because `setup` fits badly —
  offline it is near-exact (R² = 0.9999995, MAPE 0.02%) — but because it fits well
  *on features no online producer supplies*. All three drivers are
  `OFFLINE_ONLY_FEATURES`, so on the deployed path `setup` collapses to
  `base + 2110·merkle_leaf_count`. The offline precision is what makes the online
  number look credible; it is not an estimate of setup cost at all.
- **Accuracy, and which guest each number describes.** In-sample on the 53-batch
  corpus (current guest): total R² = 0.9999, MAPE 10.37%, every batch
  over-predicted +0.02%..+12.55% — the cost-floor bias, not error. Per phase,
  `merkle_verification` and `setup` R² = 1.00000, `vm_execution` 0.99962,
  `commitment` 0.83106 (near-constant, so its R² is a low-variance artifact).
  Out-of-sample, leave-one-out: MAPE 8.19%, worst-over +31.20% (that is `900065`,
  the only batch constraining the merkle-leaf axis), zero under-predictions.
  Separating the two effects: `cross_validate.py` does **not** apply the floors,
  and its 5-fold CV puts the *organic* fit at MAPE 0.85%, 38% of batches
  under-predicted, worst −2.51%. So the underlying fit is near-unbiased with a
  ±2.5% spread and everything that makes the shipped table strictly conservative
  is the floors — read both numbers together, since either alone misleads. Older
  figures quoted for this model (MAPE 0.45% on a 49-batch split, or 15.13% on 176)
  describe different tables *and* in one case a different guest. The deployed path
  adds a further ~+0.4% from the `merkle_leaf_count` proxy.

## Tests

```sh
python -m pytest scripts/cycle_model/test_fit_smoke.py   # fit on synthetic data
cargo test -p zksync-era-airbender-cycles-estimator -p zksync_cycle_model
```
