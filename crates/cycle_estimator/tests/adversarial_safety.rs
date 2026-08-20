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
//!
//! ⚠️ MIXED MEASUREMENT VINTAGES — read before adding or re-tuning a row. Each
//! row carries a `guest` field (ignored by the deserializer, informational). Eight
//! rows were measured on the PRE-DELEGATION guest (2026-07-09, cd46640); only
//! `storage_reads_140k` was measured on the guest the committed table is fit
//! against. An actual measured on a slower guest is INFLATED, which makes
//! `covered` harder to satisfy — so a stale row is conservative (over-strict) for
//! work the delegation guest made cheaper, and would be lenient only for work it
//! made dearer, which is not the observed direction. The arithmetic and
//! transient-storage rows are approximately guest-invariant (plain VM
//! interpretation, no delegated crypto); a merkle-dominated row is NOT.
//!
//! That distinction retired one row. `storage_reads_80k` — 80,065 merkle leaves /
//! 80,085 storage_application, 27,606,969,375 effective cycles = 344,807 cyc/leaf
//! on the pre-delegation guest — became uncoverable by ANY correct current-guest
//! table: the delegation guest does that same work at 189,924 cyc/leaf (1.816×)
//! while the slot-axis coefficients fell only 1.776×, and coverage needs 1.632×.
//! It is replaced by batch 900065 (`testdata/era_mainnet_batches/binary/`, declared
//! synthetic in that directory's README): the same cold-slot-flood shape
//! (storage_application/leaf 1.0001) at 1.75× the volume, measured on the fit
//! guest, and held OUT of the 176-batch fit. The row's job — a tripwire against a
//! re-attribution refit draining the storage/merkle coefficients (see the
//! OPCODE_FLOORS notes in scripts/cycle_model/fit_cost_model.py) — is preserved
//! and now rests on a measurement: 95.5% of this row's prediction is the slot
//! axis, and against the CURRENTLY COMMITTED table it trips on a ≥7.53% drain of
//! those three coefficients. That percentage is arithmetic on today's
//! coefficients, not a durable property of the fixture — recompute it after any
//! refit. It is also coarse: it catches a gross re-attribution, not drift (the
//! 2026-08-19 reweight itself moved coefficients by >40%). The retired row's
//! equivalent sensitivity cannot be stated at all, because it needs a
//! current-guest actual that was never measured — two reconstructions of it
//! disagree (7.5% vs 15.5%), which is precisely why a measured row is worth more
//! than a derived one.
//!
//! DELEGATION-WEIGHT EXPOSURE, checked. `effective_cycles` is
//! `raw + 16·blake2 + 4·bigint + 4·keccak`, and those weights have no
//! authoritative in-tree source (see DELEGATION_WEIGHTS in fit_cost_model.py;
//! native_cost_conversion.md suggests a delegation may be ~2.5× heavier). This
//! row is the most weight-exposed batch available — blake2 is 22.25% of its
//! effective cycles versus a 1.90–6.70% range across the 176-batch corpus — so
//! its verdict was tested against that uncertainty rather than assumed. Refitting
//! with w(blake2) ∈ {8, 16, 24, 40} leaves it COVERED at every value, with the
//! margin moving only 1.2048 → 1.1531 (safe direction as w falls). The reason is
//! structural, not luck: blake2 is bound to slot count (r = 0.9977 against
//! merkle_leaf_count; blake2 ≈ 10.55e6 + 3,287·leaves + 0.029·bytecode_bytes,
//! R² = 0.9954), so a heavier weight lands on the very coefficient this row
//! saturates — and at ~2,566 blake2/leaf marginal it sits BELOW the corpus's
//! 3,287, so the refit over-charges it. Keep this row if the weights are revised;
//! what a revision does move is absolute headroom against the fixed 2^36 budget
//! (this batch spans 23.6e9 at w=8 to 35.5e9 at w=40), which is a question about
//! the seal threshold, not about this assertion.
//!
//! Re-measure the remaining eight when an era node is available; until then, do
//! NOT "fix" a failure here by moving a coefficient or fencing a feature without
//! first checking whether the row's actual predates the table's guest.

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
