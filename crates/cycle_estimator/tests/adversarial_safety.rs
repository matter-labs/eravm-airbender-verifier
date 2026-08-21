//! Adversarial safety regression: no attacker-controlled batch is ever both judged
//! trustworthy by the gate AND materially under-predicted.
//!
//! Each fixture batch was produced on a local era node (see
//! scripts/precompile_calibration — CycleHammer / SlotReader), maximizing one
//! opcode/feature the fitted model under-prices, and its TRUE guest cycles were
//! measured with cycle_bench. Left unhardened, the worst under-predicted ~9×
//! (transient storage, priced 0) and ~3× (pure arithmetic). The gate must, for
//! every batch, EITHER cover it within the seal margin OR refuse to price it
//! (unpriced precompile / out-of-calibration). This locks in the OPCODE_FLOORS +
//! calibration-envelope guard.
//!
//! ⚠️ SCOPE. This shows the estimator never *silently* under-prices — not that
//! an over-budget batch cannot ship. Declining to certify only helps if the
//! consumer refuses, and era's `CyclesCriterion` answers distrust with
//! `IncludeAndSeal` (see `CycleEstimate::fits`). The five rows exempted below
//! are therefore the shapes production keeps rather than refuses.
//!
//! ⚠️ MIXED VINTAGES — read before adding or re-tuning a row. Each row carries an
//! informational `guest` field. Eight were measured on the PRE-DELEGATION guest
//! (2026-07-09, cd46640); only `storage_reads_140k` is on the guest the committed
//! table is fit against. A stale actual is INFLATED, which makes `covered` harder
//! to satisfy — over-strict for work the delegation guest made cheaper, lenient
//! only for work it made dearer, which is not the observed direction. Arithmetic
//! and transient-storage rows are ~guest-invariant; a merkle-dominated row is not.
//!
//! That retired one row. `storage_reads_80k` (80,065 leaves, 344,807 cyc/leaf
//! pre-delegation) became uncoverable by any correct current-guest table: the
//! delegation guest does that work at 189,924 cyc/leaf (1.816×) while the
//! slot-axis coefficients fell 1.776×, and coverage needs 1.632×. Replaced by
//! batch 900065 — same cold-slot-flood shape at 1.75× the volume, measured on the
//! fit guest. Its job is a tripwire against a refit draining the storage/merkle
//! coefficients: 93.8% of its prediction is the slot axis, and it trips on a
//! ≥5.10% drain of those three. That figure is arithmetic on today's
//! coefficients — recompute after any refit — and it catches gross
//! re-attribution, not drift (the 2026-08-19 reweight moved coefficients >40%).
//!
//! ⚠️ NO LONGER HELD OUT (2026-08-21). It was held out of the 176-batch fit; the
//! reproducible refit that replaced that table FITS ON IT, because it is the only
//! batch current code can decode that constrains the merkle-leaf axis at all
//! (140,059 leaves against a 3.8k–18k organic range). Held out, that axis is
//! unidentified and this row is over-predicted +31.2%; fit on, +0.02%. The
//! tripwire function survives being in-sample — it is a sensitivity check on the
//! slot coefficients, not an accuracy claim — but it can no longer be cited as
//! out-of-sample evidence, and a refit cannot be validated against it. The honest
//! generalization number is the leave-one-out CV quoted in model_regression.rs,
//! where this row is exactly the +31.2% worst case. A real held-out high-leaf
//! batch (docs/generating-batches.md) is what restores the separation.
//!
//! DELEGATION WEIGHTS, checked not assumed. `effective_cycles = raw + 16·blake2 +
//! 4·bigint + 4·keccak`, and those weights have no authoritative in-tree source.
//! This row is the most exposed available (blake2 = 22.25% of its effective cycles
//! vs 3.60–12.82% across the reproducible corpus). Re-checked 2026-08-21 with the
//! ACTUAL re-scaled at the same w as the target — the earlier sweep varied w in
//! the model while leaving the fixture's w=16 `effective_cycles` fixed, which
//! compares mismatched units, so its 1.2048 → 1.1531 margins do not mean what
//! they appear to. Re-scaling both, w(blake2) ∈ {8,16,24,40} leaves this row
//! covered at margin 1.0501–1.0503 and the whole corpus strictly over-predicted
//! (worst signed +0.01% to +0.02%) at every value. NOTE the other eight rows
//! cannot be swept at all: the fixture stores only `effective_cycles`, not the
//! delegation counts needed to re-scale an actual — add `delegations` when any of
//! them is re-measured. The robustness is structural: blake2 tracks slot count
//! (r = 0.9977), so heavier weight lands on the coefficient this row saturates,
//! and at ~2,566 blake2/leaf it sits below the corpus's 3,287 — the refit
//! over-charges it. What a revision does move is absolute headroom against 2^36
//! (23.6e9 at w=8 to 35.5e9 at w=40), which is a question about the seal
//! threshold, not this assertion.
//!
//! Re-measure the other eight when an era node is available. Until then do NOT
//! "fix" a failure here by moving a coefficient or fencing a feature without first
//! checking whether the row's actual predates the table's guest.
//!
//! **Coverage gap.** All 9 rows sit in one neighbourhood — `decommit_cycles` ∈
//! [4.7k, 5.3k], `far_call` ∈ [245, 461] — so the invariant is scoped to
//! transient-storage / compute / memory / context / storage-read shapes. Two axes
//! are untested and NOT equally guarded: the volume envelope fences the decommit
//! shapes (fresh flood 8.2× beyond the organic max, thrash 3.6×), while a bare
//! far-call flood is fenced only at batch scale (~437k calls/tx vs a 859,529
//! trip) and rests on the `far_call` floor below that. `model.rs` unit-tests the
//! mechanisms; no fixture pins them end-to-end. See
//! `scripts/cycle_model/REFIT-RUNBOOK.md`.

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
        // here, because `fits()` would refuse it.
        //
        // That exemption covers 5 of the 9 rows (worst: `pure_compute`, 2.19x
        // under) and is NOT a claim that they are handled safely downstream — the
        // deployed consumer does not take the `fits()` path. This asserts that the
        // ESTIMATOR does not lie, not that the sequencer is protected; tightening
        // it needs the consumer to refuse a distrusted tx-level estimate.
        //
        // `mem_high` joined the exempt set when SHARE_EXTRAPOLATION_FACTOR moved
        // 1.8 -> 1.2: its arithmetic share is 0.181, above the 0.1385 trip point.
        // It is over-predicted 1.32x, so nothing under-priced is hidden — the
        // assertion simply no longer applies to it. Recovering that row means a
        // fixture built below the new trip point, not a looser factor.
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
