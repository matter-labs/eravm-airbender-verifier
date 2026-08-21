# Cycle-model calibration dataset

`dataset.json` is the measured corpus behind
`crates/cycle_estimator/model/cost_table.json`: per batch, the native feature
vector, raw guest cycles, per-phase cycles, and delegation counts. It exists so
the committed cost table is **reproducible** — refit it and you get the shipped
table back:

```sh
python scripts/cycle_model/fit_cost_model.py \
    --dataset testdata/cycle_model/dataset.json --out artifacts/refit --tau 0.9
diff <(jq -S . artifacts/refit/cost_table.json) \
     <(jq -S . crates/cycle_estimator/model/cost_table.json)
```

## Provenance

| | |
| --- | --- |
| rows | 53 |
| measured | 2026-08-21 |
| verifier | `main` @ `82d7ca7` (zksync_vm2 v0.6.3, zksync-protocol v0.153.14) |
| guest | `cargo airbender build --project guest -- --features cycle-markers` |
| tool | `cycle_bench --jobs 6` (transpiler, no JIT) |

The guest is phase-marker-instrumented, so its checksum will not match a
shipping guest — it identifies the measurement build, not the release artifact.

## Composition, and why it is only 53 batches

This is **every batch current code can decode** (see
[`../era_mainnet_batches/README.md`](../era_mainnet_batches/README.md)):

| set | rows | protocol | note |
| --- | ---: | --- | --- |
| `513601`–`513649` | 49 | v29 | needs the calibration build's relaxed version pin |
| `84730`–`84732` | 3 | v31 | the CI batches; one workload measured three times, not three data points |
| `900065` | 1 | v31 | synthetic cold-slot flood, 140,059 leaves — the only batch that constrains the merkle-leaf axis |

The 127 `506xxx` batches are **not** here: they are a pre-v31 wire format and
fail inside `bincode` decode, which no feature flag works around. The table this
one replaced was fit on 176 batches of which ~122 were `506xxx`, i.e. 69% of that
fit rests on payloads no current build can re-measure. Dropping them costs corpus
breadth and buys reproducibility plus vintage consistency — every row here was
measured by one build on one day.

## Known gaps

- **No hold-out.** At n=53 every row is needed to identify the coefficients, so
  the CI guard (`model_regression`) is in-sample. The honest generalization number
  is the leave-one-out CV quoted in that test: MAPE 8.19%, worst-over +31.20%,
  zero under-predictions.
- **Two protocol versions, 4 v31 rows.** Production is v31. Real v31 traffic at
  scale is the corpus this most needs — see
  [`../../docs/generating-batches.md`](../../docs/generating-batches.md).
- **The merkle-leaf axis rests on one batch.** Organic leaf counts span 3.8k–18k;
  `900065` is 140k. Held out, it is over-predicted +31.2%.
- **Five crypto features have zero volume here** (`mod_exp`, `ec_add`, `ec_mul`,
  `ec_pairing`, `secp256r1`), so their coefficients are pinned literals rather
  than fits — see `OPCODE_FLOORS` in `scripts/cycle_model/fit_cost_model.py`.
