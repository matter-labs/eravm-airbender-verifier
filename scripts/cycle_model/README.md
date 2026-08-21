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
> - **The crypto coefficients are now measured**, not pinned literals: a synthetic
>   set (three volume tiers per precompile, driven on a local era node) was
>   residual-fit in the same pass, and it is committed at
>   `testdata/cycle_model/precompile_dataset.json`. Delegation had made five of the
>   carried-forward values 2–16× too high; `ec_recover` went the other way.
>   **One gap still needs a node:** re-measuring 8 of the 9 adversarial fixtures.
>   See **[REFIT-RUNBOOK.md](REFIT-RUNBOOK.md)**.

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
produced this way (2026-08-21) — every safety-critical precompile is priced, and
priced from a measurement.
([`native_cost_conversion.md`](native_cost_conversion.md) documents the
alternative zksync-os-derived costs used as a cross-check.)

Note what a residual coefficient means: the cost of one call **net of what the
frozen model already charges for it** — each precompile invocation drags ~1.0
`far_call` and 56–107 arithmetic ops with it, and those are priced separately. A
gross per-call slope is therefore *larger* than the coefficient, and the two must
not be compared directly.

What that pass found, against the literals it replaced: `secp256r1` was 16.0× too
high, `mod_exp` 15.6×, `sha256` 7.3×, `ec_pairing` 5.3×, `ec_mul` 2.6×, `ec_add`
2.0× — delegation made all of them cheaper, and with the old floors still in place
the synthetic batches were over-predicted up to 14×.

**`ec_recover` moved the other way**: 368,000 → 467,178, because 41,022 bigint
delegations per call at weight 4 add ~164k effective cycles that its derivation
assumed away. The old table under-predicted the two ecrecover batches by 8.3% and
17.0%; the new one is +0.7% and +1.6%. So "delegated ⇒ cheaper" holds for the raw
trace but not necessarily for the *effective* total — do not assume it per-axis.

Cost on organic traffic: MAPE 10.37% → 10.90%, still 0/53 under-predicted. The
held-out five-precompile mixed batch, in neither fit, goes +290.8% → +3.9%.

For a precompile the corpus (organic + synthetic) has never exercised, the
coverage guard is what keeps it from silently producing an under-estimate — but
note it fires on a coefficient being ABSENT, and all eight are now present, so
`is_reliable()` cannot fire today. That is a smaller concern than it was (these are
measurements now, not guesses) but it is unchanged.

### The arithmetic split, and why featurization beat flooring

Until 2026-08-21 every arithmetic opcode shared one coefficient,
`rich_addressing_op`. Isolated measurement showed why that could not work: the
bucket spans **67×** internally.

| class | opcodes | measured cyc/op | cyc/erg | 200M ergs buys |
|---|---|---:|---:|---:|
| `arith_div_op` | `Div` | **9,188** | 1,526 | **4.44× the ceiling** |
| `arith_mul_op` | `Mul` | 871 | 145 | 0.42× |
| `arith_ptr_op` | `PointerAdd`/`Sub`/`Pack`/`Shrink` | 601 (fitted) | 120 | 0.35× |
| `arith_cheap_op` | `Nop`/`Add`/`Sub`/`Jump`/`Xor`/`And`/`Or` | 137 | 27 | 0.08× |
| `arith_shift_op` | `ShiftLeft`/`Right`, `Rotate*` | 137 (assumed) | 27 | 0.08× |

Classes are grouped by **measured cost**, not by opcode taxonomy: two opcodes
share a feature only when they cost about the same. Adding a new arithmetic opcode
to the tracer therefore means deciding which class it *measures* into — do not
default it to the cheap one.

Three things follow, and they are the argument for featurizing rather than
flooring an aggregate:

1. **Only `div` can reach the proving ceiling** — 4.44× within the stock 200M-erg
   batch budget, and 1.78× from a single transaction at the bootloader's hard 80M cap. Every class draws from the same
   per-batch erg budget, so moving ergs from a dear class into a cheap one strictly
   *lowers* the true total — a cheap class cannot be combined with `div` to exceed
   what `div` alone reaches. That makes the floor decision per-class and cheap:
   floor `div`, leave the rest to the fit. Measured on the organic fit alone, so the
   configurations are comparable: flooring all five costs **14.73%** MAPE against
   **5.97%** for `div`-only, and buys nothing — the residual exposure from leaving
   the cheap classes zero-priced is ~1% of the ceiling, inside the 1.05 margin. (The
   shipped table reads 8.85%; the difference is the precompile residual pass, not the
   floor choice.)
2. **The split made `div` identifiable from organic data.** Averaged into 196M cheap
   ops it was invisible; as its own column it has real variance (0–92,730 per batch)
   and the organic fit prices it at 5,746 unaided. The floor raises that to the
   measured 9,188 — organic divs mix in the cheap `numerator < divisor` path while
   an attacker picks operands that sustain Knuth D. Fit for organic accuracy, floor
   for adversarial safety; the 1.6× gap between them is that distinction, not error.
3. **Organic accuracy improved.** MAPE 10.90% → 8.85%, still 0/53 under-predicted.
   The aggregate was not merely unsafe, it was *inaccurate*: forcing one coefficient
   onto a 67× spread cost real precision on ordinary batches. `div` is 0.85% of
   organic arithmetic *ops* but 31% of arithmetic *cycles*, which is precisely the
   structure a single coefficient cannot represent.

The extrapolation guard follows the same logic. It now sums the **weighted**
contribution of all arithmetic classes rather than watching one count, so a `div`
flood trips it far faster than an equal-length `add` flood — the discrimination an
aggregate count could not express — and it reports which class pushed the batch
out. Volume fences are deliberately *not* applied to arithmetic: organic traffic
already runs within 1.23× of the arithmetic count that reaches 2^36 with `div`, so
any fence with practical slack admits an unprovable batch while a tighter one
rejects real ones.

### The isolation corpus

Rates come from designed experiments, not from regression on traffic. The organic
corpus sets the intercept and the envelope and serves as validation; per-op rates
come from single-axis synthetic batches, because a near-singular design matrix
stays singular however much organic data you add (`far_call` had multiple R² =
0.999988 against the other features).

What makes an isolated rate trustworthy, each rule having caught a real error:

- **Three volume tiers**, so the result is a slope and per-batch fixed cost cancels.
- **Check each family's fitted intercept against the empty-batch baseline.** Free
  falsification — a sha256 intercept of 2.27e9 against a 9.4e8 baseline is how the
  size/arithmetic collinearity in that family announced itself.
- **A matched control per family.** The `div` unroll-64 vs unroll-1 pair — 86.4% and
  16.7% div purity, two quite different loop shapes — agrees to 5.4% (8,689 and
  9,188 cyc/op), which is why that number is believed to be the opcode and not the
  loop. Note the split *improved the measurement itself*: with one aggregate column
  those loops read 7,515 (diluted by their own cheap ops) and had to be reconciled
  by hand-netting; per-class counts remove that step entirely.
- **A decorrelation batch** moving two co-scaling axes in opposite directions — the
  most generalizable trick here, and what separated sha256's per-round from its
  per-call cost.
- **A held-out mix.** The five-precompile batch was worth more than any in-sample
  statistic: +290.8% → +3.9% across the precompile refit.
- **Record ergs, not just cycles.** Cycles per erg is what decides safety, since
  ergs are what bound an attacker. The table above only exists because of this.

Isolate the axes an attacker can drive *independently*. Not every collinearity is
worth breaking: `merkle_leaf_count` and `storage_application` move together at
1.0001 on a cold-read flood because they are causally linked, and an attacker
cannot separate them either — their joint identification is harmless, and the axis
sum is what gets paid.

Inputs are committed as `.bin.gz` fixtures rather than as measured numbers, so
re-measuring after a guest change is a CI job. That is the lesson of the eight
stale adversarial actuals: `build_adversarial_fixture.py` now rebuilds that fixture
from a measured dataset, and the rows carry their delegation counts so a weight
revision can re-scale them instead of invalidating them.

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
