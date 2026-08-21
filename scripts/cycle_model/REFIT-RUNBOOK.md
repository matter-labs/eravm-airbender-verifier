# Refitting the cost table on the current guest — runbook

The committed `crates/cycle_estimator/model/cost_table.json` is calibrated against a
**pre-delegation guest** and says so in its own `provenance.stale_reason`. This is the
procedure that replaces it. Everything here is a *measurement* task: the code-side
work (envelope guard, provenance schema, fail-loud fit guards, the `ecRecover`
hammer family) is already in the tree, and each of those guards will **abort** a
refit that skips a step below — that is deliberate.

## What you need that a sandbox does not have

| requirement | why | check |
|---|---|---|
| **Git-LFS credentials** for this repo | the 122-batch training corpus (`testdata/era_mainnet_batches/binary/5060*.bin.gz`) is LFS-tracked; an unauthenticated `git lfs pull` **no-ops silently** (`git lfs env` shows `auth=none`, files stay 133-byte pointers) | `git lfs pull --include='testdata/era_mainnet_batches/binary/506077.bin.gz' && ls -l` → ~MB, not 133 B |
| **A local zksync-era node** with the airbender components | the precompile + adversarial synthetic batches can only be produced by executing transactions and exporting proof inputs | `zkstack server --components api,tree,eth,state_keeper,commitment_generator,vm_runner_bwip,airbender_proof_data_handler` up on :3050/:4320 |
| **The airbender guest toolchain** | ground truth = guest cycles | `cargo airbender build --project guest -- --features cycle-markers` |
| ~10 GiB free disk, a few hours | 141 batch measurements + two builds | |

The era-node half is the **safe-ship gate**; the LFS half only improves fit
robustness. Ranked that way because without current-guest adversarial actuals the
safety invariant cannot be *evaluated at all*, whereas without the 122-batch
training set you can still fit (on a smaller corpus) — you just lose the
independent hold-out.

## Steps

### 1. Corpus (LFS)

```sh
git lfs pull --include='testdata/era_mainnet_batches/binary/*'
cargo run --release -p zksync_cycle_model --bin cycle_bench -- --all-batches --check-only
```

Keep the split the committed table used: **train** on 506077–506204 (122 measured of
127 present — five did not decode; `--check-only` shows which), **hold out**
513601–513649 (49). Do not fit on the hold-out: an earlier reference refit had to,
because the training set was unfetchable without LFS credentials, and that alone is
why its output is reference-only rather than shippable.

### 2. Guest + organic measurement

```sh
cargo airbender build --project guest -- --features cycle-markers   # NEVER ship this guest
cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
    --all-batches --batches-dir <train-dir> --app-bin-dir guest/dist/app \
    --jobs 8 --out artifacts/cycle_model/train
```

`cycle_bench` now writes `provenance.json` next to `dataset.json` (guest `app.bin`
sha256, verifier commit, locked `zksync_vm2` rev, protocol version, corpus range).
Pass it to the fit — the fit refuses to emit an unstamped table.

Two toolchain traps that have produced wrong numbers before:

- **Build the bench from the same tree as the guest.** An `airbender-host`
  simulator from a different release measuring a guest built by another is not a
  matched pair. (Cross-checked once and found benign — max |Δ| 0.000%, because
  cycles are retired RISC-V instructions of a fixed ELF — but do not rely on that.)
- **Isolate `CARGO_TARGET_DIR` per arm** if you measure two variants; a shared
  target dir can hand you a stale unsuffixed binary and you silently measure the
  wrong build.

### 3. Synthetic sets, on the era node (the safe-ship gate)

```sh
cd scripts/precompile_calibration
python3 gen_inputs.py                 # needs `cryptography` for the P-256 + ecrecover vectors
# confirm each vector on the live node before mass runs (see README "To confirm")
HAMMER=<deployed PrecompileHammer> bash run_calibration.sh
```

Then measure the produced fixtures with the same `cycle_bench` into a precompile
`dataset.json`.

Three things this pass **must** deliver, each enforced:

1. **An `ecrecover` family.** `ec_recover_cycles` is now in `PRECOMPILE_FEATURES`,
   and `fit_cost_model.py` **aborts** while the synthetic set cannot identify it
   (the committed set has 1–8 units — incidental tx signatures). The organic corpus
   cannot identify it either (near-constant column ⇒ collinear with the intercept:
   11.47M shipped vs 119k on a refit, a 100× swing that predicts organic batches
   equally well and mis-prices an ecrecover flood by that factor).
2. **Re-measured precompile coefficients.** Delegations made crypto cheaper, so
   every committed crypto coefficient is a software-guest value (`keccak256`
   measured 38k → 8k cyc/unit). Over-priced ⇒ safe ⇒ still wrong.
3. **Re-measured `adversarial.json` actuals.** They are pre-delegation, so a
   current-guest table fails the adversarial invariant *spuriously* against them.
   No table may ship until the invariant passes on current-guest actuals.

While you are there, add the three fixtures the set is missing (its 9 rows are all
one neighbourhood — `decommit_cycles` ∈ [4.7k, 5.3k], `far_call` ∈ [245, 461]):

- fresh-decommit flood, 512 KiB contracts, `gas_to_pass = 0` (must be refused by
  the `decommit_cycles` envelope);
- bare far-call flood over a cyclic large working set (`far_call` envelope);
- frame-churn + stack-dirtying loop (must be refused by the arithmetic-share
  guard — this is what pins that guard as load-bearing).

Watch for **delegation ids outside `{1991, 1994, 1995}`** in the new measurements:
`effective_cycles()` fails closed on an unknown id, and a new one needs its native
weight added to `DELEGATION_WEIGHTS`.

### 4. Fit

```sh
python scripts/cycle_model/fit_cost_model.py \
    --dataset artifacts/cycle_model/train/dataset.json \
    --provenance artifacts/cycle_model/train/provenance.json \
    --precompile-dataset artifacts/cycle_model/precompile/dataset.json \
    --tau 0.9 --out artifacts/cycle_model/fit
```

No `--allow-*` flags. If either guard fires, the corresponding measurement step is
incomplete — fix the data, not the flag.

### 5. Validate before swapping anything in

```sh
# (a) out-of-sample accuracy on the untouched hold-out
python scripts/cycle_model/eval_holdout.py --cost-table artifacts/cycle_model/fit/cost_table.json \
    --dataset artifacts/cycle_model/holdout/dataset.json --out artifacts/cycle_model/holdout
# (b) the adversarial invariant, against RE-MEASURED current-guest actuals
python scripts/cycle_model/eval_adversarial.py --cost-table artifacts/cycle_model/fit/cost_table.json
```

Ship only if: **no batch is under-predicted** (that is the safety criterion — the
current table under-predicts 0/176, and its MAPE of 15.13% is the `OPCODE_FLOORS`
bias, so do NOT gate on a small MAPE; a 1.2% target would reject the correct
table); the adversarial invariant holds on current-guest actuals; `provenance` is
fully stamped with no `stale_reason`; and `calibration.feature_value_max` came
from *this* fit's corpus. On the fence, note what a narrow sample costs: fences
derived from the 49-batch fixture flagged **52/176 = 29.5%** of ordinary training
batches as out-of-envelope, and hollowed out an adversarial row by making it
untrusted. Derive it from the widest organic corpus you fit on.

```sh
cp artifacts/cycle_model/fit/cost_table.json crates/cycle_estimator/model/cost_table.json
# refresh both fixtures from the re-measured data, then:
cargo test -p zksync-era-airbender-cycles-estimator
```

Expect to re-tune `MAX_MAPE_PCT` / `MAX_SINGLE_ERR_PCT` / `MAX_UNDER_PCT` in
`tests/model_regression.rs`, the `MAX_UNDER_PCT` / `MAX_OVER_PCT` defaults in
`.github/workflows/cycle-model-drift.yaml`, and re-check
`organic_holdout_is_inside_the_calibration_envelope` (a refit changes the fence).
Note that test cannot catch a *too-tight* fence today: it checks the same 49 rows
the fence is derived from, so it only binds once the fence comes from a corpus
wider than the fixture.

### 6. Re-derive the numbers that depended on the old table

The ~2× organic over-prediction disappears with the refit. It was never a safety
margin — it is hashing work that moved into delegated circuits — and it did not
protect the flood vector anyway (margin there is 1.03×). After the refit, confirm
explicitly that what refuses a flood is the **envelope**, not the margin, and
update the magnitudes recorded in `cycle-estimator-gaps/GAPS.md` (flood margin,
frame-churn numbers, envelope maxima).

## Order, and what may follow

The refit, the envelope guard, the provenance stamp and the fixtures belong
together: the guard is the principled replacement for the cushion the refit
removes, so **never land the refit without the envelope**. (The reverse is fine —
the envelope alone only adds refusals, which is why it is already in the tree.)

Genuinely out of scope for this repo: wiring the sequencer-side gate (a real
`max_cycles_per_batch` budget and a fast-VM tracer, both in zksync-era) and peak
guest memory, which binds before cycles on every flood shape and needs its own
criterion.
