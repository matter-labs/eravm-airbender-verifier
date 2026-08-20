//! CI guard: the embedded cost model must keep predicting a frozen set of real,
//! measured batches within tolerance. Runs in normal CI — the ground-truth
//! effective cycles are baked into the committed fixture, so no batch corpus or
//! guest execution is needed.
//!
//! This is a regression tripwire, not a re-validation: it catches an accidental
//! (or accuracy-worsening) change to `model/cost_table.json` or to the prediction
//! code. Genuine model improvements still pass (thresholds, not exact pins).
//!
//! The fixture is a frozen snapshot of the 513xxx set (features + measured
//! effective/native cycles = raw + weighted delegations). Refresh it only when
//! the guest/verifier changes enough to move real cycle counts (see
//! `scripts/cycle_model/README.md`).
//!
//! Re-measured 2026-08-19 on the delegation-enabled guest (zksync_vm2 v0.6.3).
//! The measured binary was build/guest-markers/app.bin, sha256 9228b6e2… — a
//! PHASE-MARKER-INSTRUMENTED guest, so a shipping guest will NOT match that
//! checksum; it identifies the measurement build, not the release artifact.
//!
//! The feature counts are byte-identical to the previous fixture — only the
//! cycle counts moved, by 1.54–2.44× (median 2.06×),
//! as blake2/keccak work moved into delegated circuits. NOTE: these 49 batches
//! are a subset of the 176 the table is fit on, so this is a
//! table-did-not-change tripwire, NOT an out-of-sample accuracy check.

use serde::Deserialize;
use zksync_era_airbender_cycles_estimator::{CostModel, FeatureVector};

const FIXTURE: &str = include_str!("fixtures/holdout_513xxx.json");

// Current accuracy on this fixture is MAPE 12.79% / max 16.41%, and it is
// ENTIRELY over-prediction. That figure is dominated by the adversarial
// opcode-cost floors, not by fit error: the unfloored fit scores 0.58% here.
// The floors (see fit_cost_model OPCODE_FLOORS) deliberately over-price buckets
// that NNLS zeroes out through collinearity. Measured on THIS table: far_call
// contributes a median 8.90% of an organic batch's prediction (max 13.09%), all
// four opcode floors together a median 10.06% (max 14.34%), and adding the two
// precompile floors raised organic MAPE by 1.13pp (14.00% -> 15.13%) — in
// exchange for not pricing an attacker's flood far below its true cost.
//
// Because the absolute-error bound therefore has to be loose, it is no longer a
// meaningful safety check on its own: a 12%-UNDER-predicting table would pass
// it. MAX_UNDER_PCT is the assertion that actually matters — under-prediction is
// the only unsafe direction for a seal gate. It is set to 0.0 (assert STRICT
// over-prediction) rather than a tolerance: this table over-predicts all 49 by
// >= 9.69% and all 176 corpus batches without exception, so any tolerance large
// enough to matter could never bind, and the τ=0.9 asymmetric fit plus
// monotone-raising floors make strict conservatism the design intent, not luck.
//
// KNOWN LIMITATION: this fixture is 513xxx (Version29) only, and it is the
// LOW-error family — the 506xxx half of the same corpus runs to +20.45%, median
// +15.84%. Of the 4 available v31 batches, 84730/84731/84732 are UNDER-predicted
// by 2.56% and so would fail MAX_UNDER_PCT — but those three are one ~1.28e9-cycle
// workload measured three times, not three data points, and the only LARGE real
// v31 batch (900065, 26.6e9 cyc) OVER-predicts by 2.61%. All four stay covered by
// the seal gate's 1.05 margin (1.246e9 * 1.05 = 1.309e9 > 1.279e9 actual), so this
// is a fit-accuracy gap on out-of-distribution batches, not a live
// seal-then-cannot-prove vector. It does mean the assertion below is only verified
// on the family in the fixture: widen the fixture (and re-check both bounds) when
// a real v31 corpus exists.
const MAX_MAPE_PCT: f64 = 13.5;
const MAX_SINGLE_ERR_PCT: f64 = 17.5;
const MAX_UNDER_PCT: f64 = 0.0;

#[derive(Deserialize)]
struct Row {
    batch_number: u64,
    /// Effective/native cycles = raw cycles + weighted delegation-circuit cost —
    /// the target the TOTAL model predicts and the sequencer gates on.
    effective_cycles: u64,
    features: FeatureVector,
}

#[test]
fn embedded_model_does_not_regress_on_frozen_holdout() {
    let rows: Vec<Row> = serde_json::from_str(FIXTURE).expect("parse fixture");
    assert_eq!(rows.len(), 49, "fixture size changed unexpectedly");

    let model = CostModel::embedded();
    let mut sum_ape = 0.0;
    let mut worst = (0u64, 0.0_f64); // (batch, ape%)
    let mut worst_under = (0u64, 0.0_f64); // (batch, shortfall%)
    for r in &rows {
        let actual = r.effective_cycles as f64;
        let pred = model.predict_total(&r.features) as f64;
        let ape = 100.0 * (pred - actual).abs() / actual;
        sum_ape += ape;
        if ape > worst.1 {
            worst = (r.batch_number, ape);
        }
        // Signed shortfall: positive only when the model predicts LESS than the
        // batch actually costs, i.e. the batch could seal and then fail to prove.
        let under = 100.0 * (actual - pred) / actual;
        if under > worst_under.1 {
            worst_under = (r.batch_number, under);
        }
    }
    let mape = sum_ape / rows.len() as f64;
    println!(
        "frozen hold-out: MAPE={mape:.3}%  worst=batch {} at {:.3}%  worst-under=batch {} at {:.3}%",
        worst.0, worst.1, worst_under.0, worst_under.1
    );

    assert!(
        worst_under.1 <= MAX_UNDER_PCT,
        "batch {} is UNDER-predicted by {:.3}% (limit {MAX_UNDER_PCT}%) — under-prediction \
         is the unsafe direction: such a batch can seal and then be unprovable",
        worst_under.0,
        worst_under.1
    );

    assert!(
        mape <= MAX_MAPE_PCT,
        "total-cycle MAPE {mape:.3}% regressed past {MAX_MAPE_PCT}% — model or prediction code changed"
    );
    assert!(
        worst.1 <= MAX_SINGLE_ERR_PCT,
        "batch {} error {:.3}% regressed past {MAX_SINGLE_ERR_PCT}%",
        worst.0,
        worst.1
    );
}
