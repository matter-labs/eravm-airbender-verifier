//! Adversarial safety regression: no attacker-controlled batch is ever both judged
//! trustworthy by the gate AND materially under-predicted.
//!
//! Each fixture batch was produced on a local era node (see
//! scripts/precompile_calibration — CycleHammer / SlotReader), maximizing one
//! opcode/feature the fitted model under-prices, and its TRUE guest cycles were
//! measured with cycle_bench. Left unhardened, the worst under-predicted ~9×
//! (transient storage, priced 0) and ~3× (pure arithmetic). The gate must, for
//! every batch, EITHER cover it within the seal margin OR refuse to price it
//! (unpriced precompile / out-of-calibration), so it can never silently ship an
//! over-budget batch. This locks in the OPCODE_FLOORS + calibration-envelope guard.

use serde::Deserialize;
use zksync_era_airbender_cycles_estimator::{CostModel, FeatureVector};

const FIXTURE: &str = include_str!("fixtures/adversarial.json");
/// The seal-gate cushion this test holds the model to (see `CycleEstimate::conservative`).
const GATE_MARGIN: f64 = 1.05;

#[derive(Deserialize)]
struct Row {
    label: String,
    /// True effective/native guest cycles measured by cycle_bench.
    effective_cycles: u64,
    features: FeatureVector,
}

#[test]
fn no_adversarial_batch_both_fits_and_underpredicts() {
    let rows: Vec<Row> = serde_json::from_str(FIXTURE).expect("parse adversarial fixture");
    assert_eq!(rows.len(), 9, "fixture size changed unexpectedly");
    let model = CostModel::embedded();

    for r in &rows {
        let est = model.estimate(&r.features);
        let trustworthy = est.is_reliable() && est.is_within_calibration();
        let covered = est.conservative(GATE_MARGIN) >= r.effective_cycles;
        println!(
            "{:>24}: actual={:>13} pred={:>13} reliable={} in_cal={} covered={}",
            r.label,
            r.effective_cycles,
            est.total,
            est.is_reliable(),
            est.is_within_calibration(),
            covered
        );

        // The core invariant: any batch the gate would TRUST (reliable + within the
        // calibration envelope) must be covered by conservative(margin). A batch
        // the gate distrusts (extrapolated / unpriced) is allowed to under-predict
        // because fits() refuses it anyway.
        assert!(
            !trustworthy || covered,
            "{}: gate trusts it yet conservative(margin)={} < actual={} — live under-estimation vector",
            r.label,
            est.conservative(GATE_MARGIN),
            r.effective_cycles
        );

        // And the gate function must actually fail safe on the ones it can't cover.
        if !covered {
            assert!(
                !est.fits(u64::MAX, GATE_MARGIN),
                "{}: under-predicts past the margin yet fits() reports a fit",
                r.label
            );
        }
    }
}
