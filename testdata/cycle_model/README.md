# Cycle-model calibration dataset

`dataset.json` is the measured corpus behind
`crates/cycle_estimator/model/cost_table.json`: per batch, the native feature
vector, raw guest cycles, per-phase cycles, and delegation counts. It exists so
the committed cost table is **reproducible** — refit it and you get the shipped
table back:

```sh
python scripts/cycle_model/fit_cost_model.py \
    --dataset testdata/cycle_model/dataset.json \
    --precompile-dataset testdata/cycle_model/precompile_dataset.json \
    --tau 0.9 --envelope-from <the 176-batch table> \
    --guest-sha256 8b9436a8… --verifier-commit f936458 \
    --vm2-rev be1e50b5… --protocol-version … --fit-date 2026-08-21 \
    --out artifacts/refit
diff <(jq -S . artifacts/refit/cost_table.json) \
     <(jq -S . crates/cycle_estimator/model/cost_table.json)
```

Two datasets, two jobs. `dataset.json` is organic traffic and sets every generic
coefficient. `precompile_dataset.json` is 25 synthetic batches — three volume tiers
each for `mod_exp`, `ec_add`, `ec_mul`, `ec_pairing`, `secp256r1`, `ec_recover` and
`sha256`, plus three near-empty baselines — and its only job is the residual fit for
those seven, which organic traffic cannot identify (five have zero volume, and the
other two are near-constant columns collinear with the intercept). Batch `1062` is a
five-precompile mix held out of both fits as an independent check; it predicts to
+3.9%.

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

## The isolation corpus

`dataset.json` is organic traffic; it sets the intercept, the extrapolation
envelope, and every axis an attacker cannot drive independently. It cannot set
per-op *rates* — organic batches move all their features together, so the design
matrix is near-singular (`far_call` had multiple R² = 0.999988 against the rest) and
no amount of additional organic data fixes that.

Rates therefore come from single-axis synthetic batches, committed here as datasets
with their `.bin.gz` inputs in `../era_mainnet_batches/binary/` so re-measuring
after a guest change is a CI job rather than an expedition to a local era node.
`precompile_dataset.json` is the first such family set; the arithmetic classes and
the remaining attacker-drivable opcode axes follow the same shape — three volume
tiers plus a matched control per family, ergs recorded alongside cycles, because
cycles *per erg* is what decides safety.

Isolate the axes an attacker can drive independently, and only those.
`merkle_leaf_count` and `storage_application` move together at a ratio of 1.0001 on
a cold-read flood because they are causally linked; an attacker cannot separate
them either, so their joint identification is harmless and the axis sum is what
gets paid. See `scripts/cycle_model/README.md` for the design rules and what each
one caught.

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
- **The crypto coefficients come from the synthetic set, not from here** — five of
  the seven have zero volume in organic traffic. They are measurements as of
  2026-08-21; the pinned literals they replaced were 2–16× too high, except
  `ec_recover`, which was 1.3× too low.
