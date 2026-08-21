//! CI guard: **the table did not change unexpectedly** — NOT "the model is
//! accurate".
//!
//! Both sides of the comparison are frozen committed data — the embedded
//! `cost_table.json` and a fixture with its `effective_cycles` baked in — so this
//! catches an accidental or accuracy-worsening edit to the table or the
//! prediction code, and nothing else. It **cannot see guest drift**: the fixture
//! ages with the table. The pre-delegation table reached 2.05× over-prediction
//! with this test green throughout, and it did not notice the reweight that fixed
//! it either. That job is `.github/workflows/cycle-model-drift.yaml`, which
//! re-measures with the *current* guest.
//!
//! ⚠️ The fixture is **in-sample by construction**: it is the WHOLE corpus the
//! table is fit on — every batch current code can decode. 49 × `513xxx`
//! (protocol v29), the three v31 CI batches `84730`/`84731`/`84732`, and the
//! synthetic v31 slot-flood `900065`. So this is a tripwire, not a validation,
//! and no train/hold-out split describes this table. The honest generalization
//! number is leave-one-out CV over these same 53 rows: MAPE 8.19%, worst-over
//! +31.20% (900065, the leaf-axis extrapolation), and **zero** under-predictions.
//!
//! Measured 2026-08-21 on a guest built from `main` (`82d7ca7`, zksync_vm2 v0.6.3,
//! zksync-protocol v0.153.14) with `--features cycle-markers`; the table's
//! `provenance` block carries its sha256. Because that build is
//! phase-marker-instrumented, its checksum will NOT match a shipping guest — it
//! identifies the measurement build, not the release artifact.
//!
//! That re-measurement reproduced the previous fixture's cycle counts to within
//! 6e-7 relative on all 49 shared rows, which is what establishes that the table
//! is current with `main` rather than merely unchanged. The dataset behind it is
//! committed at `testdata/cycle_model/dataset.json`, so the table refits from it
//! exactly. Refresh only when the guest moves real cycle counts.

use serde::Deserialize;
use zksync_era_airbender_cycles_estimator::{CostModel, FeatureVector};

const FIXTURE: &str = include_str!("fixtures/measured_corpus.json");

// MAPE here is 10.37% / max 12.55%, entirely OVER-prediction (min +0.02%), and
// dominated by the cost floors rather than fit error — the unfloored fit scores
// 7.55%, and the two batch-level floors added on 2026-08-21 (transaction_count,
// state_diff_count) account for the difference.
//
// So the absolute bound has to be loose, which makes it useless as a safety
// check: a 10%-UNDER table would pass it. MAX_UNDER_PCT is the one that matters,
// under-prediction being the only unsafe direction, and it is 0.0 — strict
// over-prediction — because this table over-predicts all 53 rows without
// exception. The τ=0.9 fit plus monotone floors make that the design intent, not
// luck.
//
// The predecessor table (176 batches, ~122 of them `506xxx` payloads that fail
// inside `bincode` decode on any current build) UNDER-predicted 84730/84731/84732
// by 2.56%, so it could not carry this assertion across the v31 family at all.
// Including those batches in both the fit and this fixture is what closed that
// gap: they now over-predict by 0.77%.
//
// KNOWN LIMITATION: real v31 traffic at scale is still absent. 84730/1/2 are one
// ~1.28e9-cycle workload measured three times, not three data points, and 900065
// is synthetic. Widen the fixture when a real v31 corpus exists
// (docs/generating-batches.md).
const MAX_MAPE_PCT: f64 = 11.5;
const MAX_SINGLE_ERR_PCT: f64 = 14.0;
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
fn embedded_model_does_not_regress_on_measured_corpus() {
    let rows: Vec<Row> = serde_json::from_str(FIXTURE).expect("parse fixture");
    assert_eq!(rows.len(), 53, "fixture size changed unexpectedly");

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
        "measured corpus: MAPE={mape:.3}%  worst=batch {} at {:.3}%  worst-under=batch {} at {:.3}%",
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

/// The calibration envelope must not fence real traffic out.
///
/// The envelope fails closed (an out-of-envelope batch is sealed, never
/// silently trusted), so a fence that is too TIGHT costs throughput on ordinary
/// batches instead of admitting an attack. That failure mode is invisible in
/// the accuracy numbers, so pin it: every batch of the measured corpus must be
/// inside the envelope. If a refit narrows `feature_value_max` (a smaller or
/// less varied training corpus) this is what notices — and it very nearly did:
/// re-deriving the fence from this 53-batch corpus rather than carrying the
/// wider one forward would have tightened `far_call` 7.6× (477,516 → 62,464).
/// That is why the fit takes `--envelope-from`.
///
/// `900065` is synthetic rather than organic, and it stays inside because the
/// fence covers volume counters (bytecode, far-call, writes), not the slot axis
/// it floods. The arithmetic-share half is what would catch a compute flood.
#[test]
fn measured_corpus_is_inside_the_calibration_envelope() {
    let rows: Vec<Row> = serde_json::from_str(FIXTURE).expect("parse fixture");
    let model = CostModel::embedded();
    for r in &rows {
        let est = model.estimate(&r.features);
        assert!(
            est.is_within_calibration(),
            "corpus batch {} was flagged out-of-envelope on {:?} — the fence is \
             tighter than real traffic",
            r.batch_number,
            est.extrapolated
        );
        assert!(
            !est.trace_missing,
            "corpus batch {} has a full trace; the missing-trace guard must stay quiet",
            r.batch_number
        );
    }
}
