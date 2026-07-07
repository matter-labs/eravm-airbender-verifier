# Airbender cycle-cost calibration

Offline tooling to estimate how many Airbender RISC-V cycles a batch will consume
when re-executed by the verifier guest, from cheap features the sequencer can
compute natively (a `zksync_vm2` execution trace) — **without** running RISC-V
during sequencing.

See the design/plan under `docs/superpowers/` for the full rationale.

## Workflow

1. Build the marker-instrumented guest (calibration only — never for a proved guest):

   ```sh
   cargo airbender build --project guest --features cycle-markers
   ```

2. Fetch the calibration corpus (rich pre-v31 batches live at this commit):

   ```sh
   ./scripts/fetch_lfs_batches.sh --all
   ```

3. Produce the dataset (native feature run + guest cycle measurement per batch):

   ```sh
   cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
       --all-batches --app-bin-dir guest/dist/app --out artifacts/cycle_model
   ```

4. Fit the cost model and read the report:

   ```sh
   python -m pip install -r scripts/cycle_model/requirements.txt
   python scripts/cycle_model/fit_cost_model.py \
       --dataset artifacts/cycle_model/dataset.csv --out artifacts/cycle_model
   # optionally pin crypto costs from microbenchmarks:
   #   --pinned artifacts/cycle_model/pinned.json
   cat artifacts/cycle_model/report.md
   ```

## Model shape

- **Inputs** (`f_*` columns): vm2 opcode-family counts, crypto complexity, size
  features, batch-level counts — everything computable natively.
- **Target**: effective guest cycles (raw `cycles_executed` for the first cut;
  fold in Airbender per-delegation weights once pinned).
- **Fit**: non-negative least squares with intercept; per-feature confidence
  flags in `report.md` show which costs the corpus identifies well.

## Tests

`test_fit_smoke.py` verifies the fit on synthetic data (no corpus/guest needed):

```sh
python -m pytest scripts/cycle_model/test_fit_smoke.py
```
