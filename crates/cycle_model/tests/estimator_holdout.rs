//! End-to-end check that the embedded Rust cost model reproduces the offline
//! (Python-validated) hold-out accuracy on a real measured dataset.
//!
//! `#[ignore]` because it needs a measured `dataset.json` (features +
//! ground-truth `raw_cycles`) produced by the `cycle_bench` harness — not
//! present in CI. Point it at one and run:
//!
//! ```text
//! CYCLE_MODEL_DATASET=artifacts/cycle_model_test_v2/dataset.json \
//!   cargo test -p zksync_cycle_model --test estimator_holdout -- --ignored --nocapture
//! ```
//!
//! It asserts the aggregate MAPE stays under 1% — the same predictor the Python
//! hold-out reported at ~0.45% — guarding against Rust/Python prediction drift.

use zksync_cycle_model::{CostModel, DatasetRow};

#[test]
#[ignore = "needs a measured dataset.json (set CYCLE_MODEL_DATASET)"]
fn embedded_model_matches_holdout_accuracy() {
    let path = std::env::var("CYCLE_MODEL_DATASET")
        .unwrap_or_else(|_| "artifacts/cycle_model_test_v2/dataset.json".to_string());
    let rows: Vec<DatasetRow> =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read dataset")).unwrap();
    assert!(!rows.is_empty(), "empty dataset at {path}");

    let model = CostModel::embedded();
    let mut sum_ape = 0.0;
    let mut max_ape = 0.0_f64;
    for r in &rows {
        let pred = model.predict_total(&r.features) as f64;
        let actual = r.raw_cycles as f64;
        let ape = (pred - actual).abs() / actual;
        sum_ape += ape;
        max_ape = max_ape.max(ape);
    }
    let mape = 100.0 * sum_ape / rows.len() as f64;
    println!(
        "embedded model over {} batches: MAPE={:.3}%  max={:.3}%",
        rows.len(),
        mape,
        100.0 * max_ape
    );
    assert!(
        mape < 1.0,
        "aggregate MAPE {mape:.3}% exceeds 1% — model/Rust drift?"
    );
}
