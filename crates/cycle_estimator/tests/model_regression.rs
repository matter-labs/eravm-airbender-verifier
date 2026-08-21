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
//! ⚠️ The fixture is **in-sample**: all 49 rows (513601-513649) are in the
//! 176-batch corpus the table was fit on, so this is a tripwire, not a
//! validation. The historical "122 train / 49 hold-out" split does not describe
//! this table. Refresh only when the guest moves real cycle counts.
//!
//! Re-measured 2026-08-19 on the delegation-enabled guest (zksync_vm2 v0.6.3).
//! The measured binary was build/guest-markers/app.bin, sha256 9228b6e2… — a
//! PHASE-MARKER-INSTRUMENTED guest, so a shipping guest will NOT match that
//! checksum; it identifies the measurement build, not the release artifact.
//!
//! The feature counts are byte-identical to the previous fixture — only the cycle
//! counts moved, by 1.54–2.44× (median 2.06×), as blake2/keccak work moved into
//! delegated circuits.

use serde::Deserialize;
use zksync_era_airbender_cycles_estimator::{CostModel, FeatureVector};

const FIXTURE: &str = include_str!("fixtures/holdout_513xxx.json");

// MAPE here is 12.79% / max 16.41%, entirely OVER-prediction, and dominated by
// the opcode floors rather than fit error — the unfloored fit scores 0.58%.
// Measured on this table: far_call is a median 8.90% of a batch's prediction (max
// 13.09%), all four opcode floors 10.06% (max 14.34%), and the two precompile
// floors cost 1.13pp of organic MAPE (14.00% -> 15.13%) in exchange for not
// pricing a flood far below its true cost.
//
// So the absolute bound has to be loose, which makes it useless as a safety
// check: a 12%-UNDER table would pass it. MAX_UNDER_PCT is the one that matters,
// under-prediction being the only unsafe direction, and it is 0.0 — strict
// over-prediction — because this table over-predicts all 49 rows by >= 9.69% and
// all 176 corpus batches without exception. The τ=0.9 fit plus monotone floors
// make that the design intent, not luck.
//
// KNOWN LIMITATION: the fixture is 513xxx (Version29) only, and the LOW-error
// half — 506xxx runs to +20.45%, median +15.84%. Of the 4 v31 batches,
// 84730/84731/84732 UNDER-predict by 2.56% and would fail MAX_UNDER_PCT, but they
// are one ~1.28e9-cycle workload measured three times; the only large v31 batch
// (900065, 26.6e9) over-predicts 2.61%. All four stay inside the 1.05 seal margin
// (1.246e9 * 1.05 > 1.279e9), so this is an out-of-distribution accuracy gap, not
// a seal-then-cannot-prove vector. Widen the fixture when a v31 corpus exists.
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

/// The calibration envelope must not fence organic traffic out.
///
/// The envelope fails closed (an out-of-envelope batch is sealed, never
/// silently trusted), so a fence that is too TIGHT costs throughput on ordinary
/// batches instead of admitting an attack. That failure mode is invisible in
/// the accuracy numbers, so pin it: every batch of the organic hold-out must be
/// inside the envelope. If a refit narrows `feature_value_max` (a smaller or
/// less varied training corpus) this is what notices.
#[test]
fn organic_holdout_is_inside_the_calibration_envelope() {
    let rows: Vec<Row> = serde_json::from_str(FIXTURE).expect("parse fixture");
    let model = CostModel::embedded();
    for r in &rows {
        let est = model.estimate(&r.features);
        assert!(
            est.is_within_calibration(),
            "organic batch {} was flagged out-of-envelope on {:?} — the fence is \
             tighter than real traffic",
            r.batch_number,
            est.extrapolated
        );
        assert!(
            !est.trace_missing,
            "organic batch {} has a full trace; the missing-trace guard must stay quiet",
            r.batch_number
        );
    }
}
