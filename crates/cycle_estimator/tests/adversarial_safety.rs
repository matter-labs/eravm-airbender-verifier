//! Adversarial safety regression: no attacker-controlled batch is ever both judged
//! trustworthy by the gate AND materially under-predicted.
//!
//! ## The fixture is now a build product
//!
//! Every row is a **single-axis synthetic batch from the isolation corpus**
//! (`testdata/era_mainnet_batches/binary/9001xx` plus the precompile families),
//! measured on the CURRENT guest under the CURRENT feature schema, and rebuilt by
//! `scripts/cycle_model/build_adversarial_fixture.py` from a `cycle_bench`
//! measurement plus `testdata/cycle_model/isolation_manifest.json`. Re-measuring
//! after a guest change is therefore a CI job, not an expedition to a local era
//! node.
//!
//! That replaced a hand-maintained fixture of nine rows whose batch *inputs* were
//! never committed. Eight of those were measured on the pre-delegation guest
//! (2026-07-09) and could not be refreshed; the 2026-08-21 arithmetic split then
//! made them unusable outright, because a single `rich_addressing_op` count cannot
//! be reinterpreted across the split in either direction — attributing it to the
//! dear class raises the prediction and makes `covered` *easier* (a weaker test),
//! and attributing it to the cheap class makes the test fail spuriously. Three of
//! them (`compute_mem_low`, `context_ops`, `pure_compute`) did fail, with every
//! row's arithmetic share reading 0.000 because the schema mismatch left the guard
//! blind rather than merely wrong. Coverage went 9 rows -> 27.
//!
//! Rows carry their `delegations` counts, so a future revision of
//! `DELEGATION_WEIGHTS` can RE-SCALE these actuals instead of invalidating them.
//! The old fixture stored only `effective_cycles`, which is exactly why a
//! delegation-weight sensitivity sweep once compared a re-weighted model against a
//! w=16 actual and produced margins that did not mean what they appeared to.
//!
//! ## What the rows are
//!
//! One saturated member per family: the five arithmetic cost classes (including
//! both `div` operand regimes — `div_fast` at 1,186 cyc/op and `div_worst2` at
//! 7,667, a 6.5x spread inside one opcode), transient read and write, context ops,
//! far-call, near-call, events, heap read and write, all seven crypto precompiles,
//! and the 140k-slot cold-read flood.
//!
//! ## ⚠️ The arithmetic rows are now REJECTED rather than covered
//!
//! Read the verdict column before concluding anything from it. With the arithmetic
//! classes pinned at measured rates the model prices these batches WELL —
//! `add_flood` is over-predicted 7% — yet the arithmetic-share guard still rejects
//! them, because a pure-arithmetic batch reaches a share of 0.51-0.98 against a
//! 0.315 trip point. The guard is firing on batches it no longer needs to protect
//! against, which is a pure liveness cost.
//!
//! It is kept anyway, deliberately: per the note on
//! `Calibration::rich_addressing_share_max`, the share guard is the ONLY thing
//! covering the frame-churn / pooled-stack-clear vector (36.5x under-predicted per
//! iteration), and it covers it *incidentally*, via the cheap arithmetic that
//! attack must run rather than via anything modelled. Retiring it needs that vector
//! to get a cost feature of its own. Until then this fixture cannot distinguish
//! "rejected because the guard is load-bearing" from "rejected for nothing", and
//! the arithmetic rows are in the second category.

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
    assert_eq!(
        rows.len(),
        27,
        "fixture size changed unexpectedly — it is a BUILD PRODUCT of the isolation \
         corpus (build_adversarial_fixture.py + isolation_manifest.json), so a size \
         change means a family was added, dropped, or failed to measure. Dropping one \
         silently retires that invariant."
    );
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
        // here, because `fits()` would refuse it.
        //
        // The exemption is NOT a claim that a distrusted batch is handled safely
        // downstream — the deployed consumer does not take the `fits()` path, it
        // answers distrust with IncludeAndSeal. This asserts that the ESTIMATOR does
        // not lie, not that the sequencer is protected; tightening it needs the
        // consumer to refuse a distrusted tx-level estimate.
        //
        // Since the arithmetic pinning, the exemption is doing much less work than
        // it looks: every exempt row is OVER-predicted (the arithmetic floods by
        // 7-540%), so nothing under-priced hides behind it. That was not true of the
        // fixture this replaced, where the worst exempt row was 2.19x under.
        assert!(
            !trustworthy || covered,
            "{}: gate trusts it yet conservative(margin)={} < actual={} — live under-estimation vector",
            r.label,
            est.conservative(GATE_MARGIN),
            r.effective_cycles
        );

        // And the gate function must actually fail safe on the ones it can't cover.
        // NB this is the contrapositive of the assertion above, not extra coverage:
        // `fits(u64::MAX, m)` reduces to `trustworthy` because conservative(m) is a
        // u64 and so always <= u64::MAX. Kept deliberately — it pins fits()' own
        // wiring, so a refactor that stopped consulting the two trust signals
        // inside fits() would fail here rather than pass silently.
        if !covered {
            assert!(
                !est.fits(u64::MAX, GATE_MARGIN),
                "{}: under-predicts past the margin yet fits() reports a fit",
                r.label
            );
        }
    }
}
