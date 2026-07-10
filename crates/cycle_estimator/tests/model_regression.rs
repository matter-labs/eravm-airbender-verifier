//! CI guard: the embedded cost model must keep predicting a frozen set of real,
//! measured batches within tolerance. Runs in normal CI — the ground-truth
//! effective cycles are baked into the committed fixture, so no batch corpus or
//! guest execution is needed.
//!
//! This is a regression tripwire, not a re-validation: it catches an accidental
//! (or accuracy-worsening) change to `model/cost_table.json` or to the prediction
//! code. Genuine model improvements still pass (thresholds, not exact pins).
//!
//! The fixture is a frozen snapshot of the 513xxx hold-out set (features +
//! measured effective/native cycles = raw + weighted delegations). Refresh it
//! only when the guest/verifier changes enough to move real cycle counts (see
//! `scripts/cycle_model/README.md`).

use serde::Deserialize;
use zksync_era_airbender_cycles_estimator::{CostModel, FeatureVector};

const FIXTURE: &str = include_str!("fixtures/holdout_513xxx.json");

// Current out-of-sample accuracy is MAPE 0.34% / max 1.36% (asymmetric τ=0.9 fit,
// which leans conservative); these thresholds leave headroom for improvements but
// trip on a real regression.
const MAX_MAPE_PCT: f64 = 0.60;
const MAX_SINGLE_ERR_PCT: f64 = 2.5;

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
    for r in &rows {
        let pred = model.predict_total(&r.features) as f64;
        let ape = 100.0 * (pred - r.effective_cycles as f64).abs() / r.effective_cycles as f64;
        sum_ape += ape;
        if ape > worst.1 {
            worst = (r.batch_number, ape);
        }
    }
    let mape = sum_ape / rows.len() as f64;
    println!(
        "frozen hold-out: MAPE={mape:.3}%  worst=batch {} at {:.3}%",
        worst.0, worst.1
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
