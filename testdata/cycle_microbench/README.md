# Crypto isolation microbenchmarks

The mainnet calibration corpus is small and its opcodes co-occur, so the
regression cannot cleanly separate the cost of the expensive **delegated** crypto
operations (keccak256, sha256, ecrecover, modexp, ecadd, ecmul, ecpairing) from
everything else. These microbenchmarks isolate one crypto op at a time so its
per-call effective-cycle cost can be measured directly and then **pinned** in the
fit (`fit_cost_model.py --pinned`).

## What each input should be

One `AirbenderVerifierInput` (v-envelope, same on-disk framing as the corpus,
i.e. `<name>.bin[.gz]`) whose single transaction calls exactly one precompile in
a tight loop, with everything else minimized. Suggested set:

| file                     | stresses            | feature pinned        |
|--------------------------|---------------------|-----------------------|
| `keccak256.bin.gz`       | keccak256 precompile| `keccak256_cycles`    |
| `sha256.bin.gz`          | sha256 precompile   | `sha256_cycles`       |
| `ecrecover.bin.gz`       | ecrecover           | `ecrecover_cycles`    |
| `modexp.bin.gz`          | modexp              | `modexp_cycles`       |
| `ecadd.bin.gz`           | bn254 ecadd         | `ecadd_cycles`        |
| `ecmul.bin.gz`           | bn254 ecmul         | `ecmul_cycles`        |
| `ecpairing.bin.gz`       | bn254 ecpairing     | `ecpairing_cycles`    |

## Procedure

1. Generate each input from zksync-era's witness generator (or a hand-built
   minimal batch) so it deserializes as the current `AirbenderVerifierInput`.
   Drop the `.bin.gz` files in this directory.
2. Run the bench over just these files:

   ```sh
   cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
       --batch-files keccak256.bin.gz,sha256.bin.gz,ecrecover.bin.gz,modexp.bin.gz,ecadd.bin.gz,ecmul.bin.gz,ecpairing.bin.gz \
       --batches-dir testdata/cycle_microbench \
       --app-bin-dir guest/dist/app --out artifacts/cycle_model/micro
   ```

3. For each op, marginal cost ≈ `raw_cycles / <the op's feature count>` (subtract
   a baseline empty-batch run to remove fixed overhead). Collect these into a
   `pinned.json` (`{ "keccak256_cycles": <cost>, ... }`) and pass it to the fit.

> Status: procedure + schema defined here; the `.bin.gz` inputs are added when
> generated (they depend on zksync-era witness generation and are not produced in
> this repo). Until then the fit runs corpus-only with confidence flags.
