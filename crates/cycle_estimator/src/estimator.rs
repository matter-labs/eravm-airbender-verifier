//! Cycle-count estimation inputs and result.
//!
//! Defines the two batch-level pieces the VM trace cannot observe — the
//! [`BatchContext`] inputs the sequencer supplies, and the [`CycleEstimate`]
//! result the model produces. A tracer (the sibling
//! `zksync-era-airbender-cycles-tracer` crate for the fast VM, or zksync-era's
//! in-tree legacy-VM tracer) fills a [`crate::FeatureVector`] with opcode/crypto
//! counts; [`estimate_from_features`] merges in these scalars and runs
//! [`CostModel::estimate`].
//!
//! The API takes scalars rather than a `FinishedL1Batch` on purpose: it keeps
//! this crate free of the VM-interface types (which are versioned per protocol),
//! so a sequencer on any compatible version can call it by passing
//! `pubdata_input.len()` and `state_diffs.len()` directly.
//!
//! Feature provenance:
//! - `vm_execution` opcode/crypto features — from the tracer (exact). If the
//!   caller supplies none of them for a batch that ran transactions, the
//!   estimate is flagged [`CycleEstimate::trace_missing`] and fails closed.
//! - `pubdata_bytes`, `state_diff_count` — from the finished batch (exact).
//! - [`BatchContext`] — the sequencer derives these from data it already holds.
//!   At sequencing time the merkle witness does not exist yet, so
//!   `merkle_leaf_count` is the count of distinct storage slots the batch
//!   touched (what the tree will witness) — an over-approximation of the
//!   calibrated witness quantity, not a byte-identical copy (see the field's
//!   docs for the measured 1.74× / +3.0% consequence).
//!
//! [`BatchContext`] deliberately carries ONLY inputs the committed model prices.
//! Offline calibration collects a wider vector (see `zksync_cycle_model`), but
//! exposing unpriced inputs here would invite integrators to wire up values the
//! model ignores — or worse, leave a field 0 forever and silently under-estimate
//! the day a refit starts pricing it. If a refit prices a new batch-level
//! feature, extend this struct so every integrator is forced to supply it.

use std::collections::BTreeMap;

use crate::features::{FeatureId, FeatureVector};
use crate::model::CostModel;

/// Batch-level model inputs the sequencer supplies from data it already holds.
/// These drive the setup / merkle phases and a vm2 opcode tracer cannot observe
/// them directly.
#[derive(Debug, Clone, Default)]
pub struct BatchContext {
    /// Total transactions in the batch.
    pub transaction_count: u64,
    /// Distinct storage slots the batch touched (read ∪ write) — what the merkle
    /// tree will witness. Drives the `merkle_verification` and `setup` phases.
    ///
    /// **Deployed-path proxy, documented not fixed** — the exact quantity does not
    /// exist before the tree runs. Calibration measures `|reads ∪ writes|` from
    /// the finished verifier input; consumers feed the closest thing they have,
    /// typically [`FeatureId::StorageApplication`] = `|reads| + 2·|writes|`. So it
    /// is always ≥ the calibrated quantity and cannot under-count: measured 1.74×
    /// (1.64–1.81), inflating the prediction +3.0%. The crate's quoted accuracy
    /// therefore describes the calibrated quantity, not the deployed path, which
    /// runs ~3% more conservative.
    pub merkle_leaf_count: u64,
}

/// A cycle-cost estimate: the headline `total` (compare this to the per-proof
/// limit) plus a per-phase breakdown for insight.
#[derive(Debug, Clone)]
pub struct CycleEstimate {
    /// Predicted effective (native-computational) cycles — main RISC-V cycles +
    /// weighted delegation-circuit cost; incl. guest prologue/epilogue.
    /// This is the model's raw output — apply [`Self::conservative`] before
    /// comparing to a hard limit.
    pub total: u64,
    /// Predicted cycles per verify() phase — **diagnostic only**. Never gate on
    /// these: only `total` / [`Self::conservative`] / [`Self::fits`] are
    /// validated, and the `setup` entry is both weakly fit and structurally 0 on
    /// the deployed path (see [`CostModel::predict_phases`]).
    pub phases_insight: BTreeMap<String, u64>,
    /// Safety-critical precompiles the batch used that the model does not price
    /// (see [`CostModel::unpriced_used`]). Non-empty ⇒ `total` omits real work
    /// and is an under-estimate; treat the estimate as unusable.
    pub unpriced: Vec<FeatureId>,
    /// Features that push the batch outside the model's calibration envelope, so
    /// the linear prediction is untrustworthy (see
    /// [`CostModel::extrapolated_features`]). Non-empty ⇒ compute-dominated /
    /// out-of-distribution batch; the estimate may be a large under-prediction.
    pub extrapolated: Vec<FeatureId>,
    /// The batch claims work but its VM trace is empty — no tracer ran (see
    /// [`CostModel::trace_missing`]). The estimate is then `base` plus batch
    /// scalars, i.e. a small number that no other signal contradicts, so it is
    /// folded into [`Self::is_reliable`] to fail closed.
    pub trace_missing: bool,
}

impl CycleEstimate {
    /// True when the estimate rests on real, priced work: every safety-critical
    /// precompile the batch used is priced by the model, AND the batch's VM
    /// trace actually exists. When false, `total` is a lower bound, not an
    /// estimate.
    ///
    /// The missing-trace case is folded in here, not only into [`Self::fits`],
    /// because consumers branch on the trust signals directly — a signal that
    /// reached only `fits` would leave those paths trusting an un-traced batch.
    pub fn is_reliable(&self) -> bool {
        self.unpriced.is_empty() && !self.trace_missing
    }

    /// True when the batch is inside the model's calibration envelope. When false,
    /// the batch is out-of-distribution (e.g. compute-dominated — see
    /// [`CostModel::extrapolated_features`]) and `total` may under-predict
    /// substantially, so [`Self::fits`] refuses to report a fit.
    pub fn is_within_calibration(&self) -> bool {
        self.extrapolated.is_empty()
    }

    /// `total` scaled by a safety `margin` and rounded up — the number to compare
    /// against the per-proof limit. The model is fit with an *asymmetric* loss
    /// (expectile τ=0.9) that penalizes under-prediction more than over-prediction,
    /// so `total` already leans conservative (out-of-sample it is no longer
    /// systematically low; residual worst-case under-prediction ~1.4%). A `margin`
    /// of ~1.05 comfortably covers that tail plus ordinary variance (pick per your
    /// risk tolerance; a bigger cushion trades throughput for safety). A margin
    /// does NOT compensate for unpriced precompiles — see [`Self::is_reliable`].
    pub fn conservative(&self, margin: f64) -> u64 {
        ((self.total as f64) * margin.max(1.0)).ceil() as u64
    }

    /// Whether the batch fits under `limit` after applying `margin`. **Fails
    /// safe**: an unreliable estimate (unpriced precompiles, or a missing VM
    /// trace) OR an out-of-envelope batch (compute-dominated / extrapolating)
    /// never reports a fit.
    ///
    /// ⚠️ A property of this function, not of any deployed gate. era's
    /// `CyclesCriterion` never calls it: it reads [`Self::is_reliable`] /
    /// [`Self::is_within_calibration`] directly, gates `ProofWillFail` on the
    /// estimate being TRUSTED, and answers distrust with `IncludeAndSeal` — so
    /// distrust removes the only path that would exclude the tx. That is why
    /// `trace_missing` folds into [`Self::is_reliable`] and not into this
    /// function; a new fail-safe signal must reach one of the two trust
    /// predicates to have any effect.
    pub fn fits(&self, limit: u64, margin: f64) -> bool {
        self.is_reliable() && self.is_within_calibration() && self.conservative(margin) <= limit
    }
}

/// Merge the batch-level features a VM trace cannot observe into a feature vector
/// (the tracer's opcode/crypto counts, or a hand-built vector). `pubdata_bytes` and
/// `state_diff_count` come from the finished batch; [`BatchContext`] carries the
/// sequencer-derived drivers. This is the VM-agnostic assembly step — shared by
/// the fast-VM tracer, a legacy-VM tracer, or any other consumer, so the online
/// estimator always feeds the model exactly the calibrated features.
pub fn assemble_feature_vector(
    mut vm_features: FeatureVector,
    pubdata_bytes: u64,
    state_diff_count: u64,
    ctx: &BatchContext,
) -> FeatureVector {
    // From the finished batch (exact).
    vm_features.add(FeatureId::PubdataBytes, pubdata_bytes);
    vm_features.add(FeatureId::StateDiffCount, state_diff_count);
    // From the sequencer-supplied context.
    vm_features.add(FeatureId::TransactionCount, ctx.transaction_count);
    vm_features.add(FeatureId::MerkleLeafCount, ctx.merkle_leaf_count);
    vm_features
}

/// Estimate guest cycles from `vm_features` (opcode/crypto counts) plus the batch
/// scalars, using the embedded cost model. **Tracer-agnostic**: any consumer — the
/// fast-VM tracer, zksync-era's legacy-VM tracer, or a hand-built vector — can call
/// this without pulling a VM dependency, so there is one implementation of the
/// assemble-then-predict path and no need to reimplement it downstream.
///
/// To evaluate a candidate (non-embedded) table, call
/// `model.estimate(&assemble_feature_vector(...))` directly.
pub fn estimate_from_features(
    vm_features: FeatureVector,
    pubdata_bytes: u64,
    state_diff_count: u64,
    ctx: &BatchContext,
) -> CycleEstimate {
    CostModel::embedded().estimate(&assemble_feature_vector(
        vm_features,
        pubdata_bytes,
        state_diff_count,
        ctx,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::SAFETY_CRITICAL_FEATURES;

    /// A minimal but *real-shaped* VM trace: enough opcode traffic that the
    /// missing-trace guard treats it as an actual execution.
    fn traced_vector() -> FeatureVector {
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::RichAddressingOp, 1_000_000);
        fv.add(FeatureId::AverageOp, 50_000);
        fv.add(FeatureId::FarCall, 500);
        fv.add(FeatureId::UmaRead, 20_000);
        fv.add(FeatureId::UmaWrite, 15_000);
        fv
    }

    #[test]
    fn conservative_margin_scales_and_never_shrinks() {
        let est = CycleEstimate {
            total: 1_000_000,
            phases_insight: BTreeMap::new(),
            unpriced: vec![],
            extrapolated: vec![],
            trace_missing: false,
        };
        assert_eq!(est.conservative(1.10), 1_100_000);
        assert_eq!(est.conservative(1.0), 1_000_000);
        // a margin below 1.0 is clamped — the safe value is never below `total`.
        assert_eq!(est.conservative(0.5), 1_000_000);
    }

    #[test]
    fn extrapolated_batch_fails_safe() {
        let est = CycleEstimate {
            total: 1_000_000,
            phases_insight: BTreeMap::new(),
            unpriced: vec![],
            extrapolated: vec![FeatureId::RichAddressingOp],
            trace_missing: false,
        };
        assert!(!est.is_within_calibration());
        assert!(
            !est.fits(u64::MAX, 1.0),
            "an out-of-envelope (compute-dominated) batch must never report a fit"
        );
    }

    #[test]
    fn untraced_batch_that_claims_work_fails_safe() {
        // The shape a consumer produces when it forgets to wire a tracer: real
        // batch scalars, zero VM features. It must NOT read as a small, healthy
        // batch — `is_reliable` (not just `fits`) has to go false, because
        // consumers branch on the trust signals directly.
        let ctx = BatchContext {
            transaction_count: 370,
            merkle_leaf_count: 0,
        };
        let est = estimate_from_features(FeatureVector::default(), 42_065, 0, &ctx);
        assert!(est.trace_missing);
        assert!(
            !est.is_reliable(),
            "an empty VM trace must not read as reliable"
        );
        assert!(
            !est.fits(u64::MAX, 1.0),
            "a batch with no VM trace must never report a fit"
        );
    }

    #[test]
    fn traced_batch_is_not_flagged_as_untraced() {
        let ctx = BatchContext {
            transaction_count: 370,
            merkle_leaf_count: 4_000,
        };
        let est = estimate_from_features(traced_vector(), 42_065, 1_500, &ctx);
        assert!(!est.trace_missing);
        assert!(est.is_reliable());
    }

    #[test]
    fn empty_batch_without_claimed_work_is_not_flagged() {
        // No transactions and no touched slots: an all-zero vector is a truthful
        // description, not a missing tracer, so the guard must stay quiet.
        let est = estimate_from_features(FeatureVector::default(), 0, 0, &BatchContext::default());
        assert!(!est.trace_missing);
    }

    #[test]
    fn assembled_vector_merges_vm_finished_and_context() {
        let mut vm = FeatureVector::default();
        vm.add(FeatureId::StorageWrite, 3);
        let ctx = BatchContext {
            transaction_count: 7,
            merkle_leaf_count: 1000,
        };
        let fv = assemble_feature_vector(vm, /*pubdata*/ 4096, /*state_diffs*/ 42, &ctx);
        assert_eq!(fv.get(FeatureId::StorageWrite), 3); // tracer
        assert_eq!(fv.get(FeatureId::PubdataBytes), 4096); // finished
        assert_eq!(fv.get(FeatureId::StateDiffCount), 42); // finished
        assert_eq!(fv.get(FeatureId::TransactionCount), 7); // context
        assert_eq!(fv.get(FeatureId::MerkleLeafCount), 1000); // context
    }

    #[test]
    fn estimate_produces_total_and_phases() {
        let ctx = BatchContext {
            merkle_leaf_count: 2000,
            transaction_count: 50,
        };
        let est = estimate_from_features(traced_vector(), 10_000, 1500, &ctx);
        assert!(est.total > 0);
        for phase in ["setup", "vm_execution", "merkle_verification", "commitment"] {
            assert!(est.phases_insight.contains_key(phase));
        }
        assert!(est.is_reliable(), "no unpriced precompiles used");
        assert!(est.fits(u64::MAX, 1.10));
        assert!(!est.fits(0, 1.0));
    }

    #[test]
    fn unpriced_precompile_fails_safe() {
        // A batch that runs a precompile the model does NOT price must be flagged
        // unreliable and never report a fit — even under a huge limit and no margin.
        // The embedded model now prices every safety-critical precompile (they were
        // all calibrated), so exercise the guard against a table that omits one.
        let model = CostModel::from_json(
            r#"{"batches":1,"phases":{},"total":{"features":{"storage_write":100.0},"base":1000.0}}"#,
        )
        .unwrap();
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::EcPairingCycles, 5);
        let est = model.estimate(&fv);
        assert!(!est.is_reliable());
        assert_eq!(est.unpriced, vec![FeatureId::EcPairingCycles]);
        assert!(
            !est.fits(u64::MAX, 1.0),
            "unpriced precompile must fail safe"
        );
    }

    #[test]
    fn priced_precompile_is_reliable() {
        // keccak IS priced (size-scaled), so using it does not trip the guard.
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::Keccak256Cycles, 100_000);
        let est = CostModel::embedded().estimate(&fv);
        assert!(est.is_reliable());
        assert!(est.total > 0);
    }

    #[test]
    fn calibrated_but_zero_coeff_feature_is_reliable() {
        // sha256 is calibrated (present in the corpus) but the fit found it
        // cheap/near-constant → zero coefficient. It must NOT be flagged unpriced,
        // otherwise every real batch (all use a little sha256) is falsely rejected.
        // Guards the guard's presence-not-sign semantics.
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::Sha256Cycles, 2_000);
        let est = CostModel::embedded().estimate(&fv);
        assert!(
            est.is_reliable(),
            "sha256 is calibrated (present-with-0); must not be flagged unpriced"
        );
    }

    /// The coverage guard is INERT against the currently committed table, and this
    /// test exists to make that visible rather than let it read as protection.
    ///
    /// `unpriced_used` keys on a safety-critical feature being ABSENT from the
    /// table. The committed table prices all eight — and six of those (mod_exp,
    /// ec_add, ec_mul, ec_pairing, secp256r1, ec_recover) are pinned literals
    /// carried forward or derived, not measured on the delegation guest, because
    /// five have zero volume in the whole reproducible corpus. So `is_reliable()`
    /// is unconditionally true on precompile grounds and precompile mispricing has
    /// no backstop.
    ///
    /// That is a deliberate liveness trade (absence would reject every batch
    /// touching a pairing — see the precompile note in
    /// `scripts/cycle_model/README.md`), not an oversight. If a future table drops
    /// one of these coefficients, this test fails and the guard becomes live again
    /// — which is the signal to re-check what `fits()`'s consumer does with a
    /// distrusted estimate, since era's `CyclesCriterion` answers distrust with
    /// `IncludeAndSeal`.
    ///
    /// NB the vector is `traced_vector()`-based: since #107, an all-zero trace
    /// trips `trace_missing` and would make `is_reliable()` false for an unrelated
    /// reason, masking what this asserts.
    #[test]
    fn coverage_guard_is_currently_inert_by_construction() {
        let model = CostModel::embedded();
        for id in SAFETY_CRITICAL_FEATURES {
            let mut fv = traced_vector();
            fv.add(*id, 1_000_000);
            assert!(
                model.estimate(&fv).is_reliable(),
                "{id:?} is absent from the committed table, so the coverage guard \
                 now fires on it. That is a behaviour change, not a bug — update \
                 this test, and re-check that the gate's consumer actually refuses \
                 a distrusted estimate."
            );
        }
    }
}
