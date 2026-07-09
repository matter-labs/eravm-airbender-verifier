//! Online cycle-count estimation for the sequencer.
//!
//! The sequencer attaches a [`CycleFeatureTracer`] while it executes a batch on
//! the fast VM (it is passive — no VM-state mutation, so execution is identical
//! to a proved run). After the batch finishes it calls [`estimate`] with two
//! scalars from the batch output plus a small [`BatchContext`], and gets a
//! predicted guest cycle count to compare against the per-proof limit — with no
//! RISC-V execution.
//!
//! The API takes scalars rather than a `FinishedL1Batch` on purpose: it keeps
//! this crate free of the VM-interface types (which are versioned per protocol),
//! so a sequencer on any compatible version can call it by passing
//! `pubdata_input.len()` and `state_diffs.len()` directly.
//!
//! Feature provenance:
//! - `vm_execution` opcode/crypto features — from the tracer (exact).
//! - `pubdata_bytes`, `state_diff_count` — from the finished batch (exact).
//! - the rest ([`BatchContext`]) — the sequencer derives these from its storage
//!   view and the bytecodes it is about to prove. At sequencing time the merkle
//!   witness does not exist yet, so `merkle_leaf_count` is the count of distinct
//!   storage slots the batch touched (what the tree will witness) — an estimate
//!   of the calibrated witness quantity, not a byte-identical copy.

use std::collections::BTreeMap;

use crate::features::FeatureId;
#[cfg(feature = "vm2-tracer")]
use crate::features::FeatureVector;
#[cfg(feature = "vm2-tracer")]
use crate::model::CostModel;
#[cfg(feature = "vm2-tracer")]
use crate::tracer::CycleFeatureTracer;

/// Batch-level model inputs the sequencer supplies from data it already holds
/// (storage view + the bytecodes it will prove). These drive the setup / merkle
/// phases and a vm2 opcode tracer cannot observe them directly.
#[derive(Debug, Clone, Default)]
pub struct BatchContext {
    /// Total transactions in the batch.
    pub transaction_count: u64,
    /// Distinct storage slots the batch touched (read ∪ write) — what the merkle
    /// tree will witness. Drives the `merkle_verification` and `setup` phases.
    pub merkle_leaf_count: u64,
    /// Distinct storage keys materialized into the pre-state view (≈ leaves).
    pub storage_key_count: u64,
    /// Total bytes across the bytecodes used by the batch (hashed in `setup`).
    pub used_bytecode_bytes: u64,
    /// Number of distinct bytecodes used by the batch.
    pub used_bytecode_count: u64,
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
    /// Predicted cycles per verify() phase.
    pub phases: BTreeMap<String, u64>,
    /// Safety-critical precompiles the batch used that the model does not price
    /// (see [`CostModel::unpriced_used`]). Non-empty ⇒ `total` omits real work
    /// and is an under-estimate; treat the estimate as unusable.
    pub unpriced: Vec<FeatureId>,
}

impl CycleEstimate {
    /// True when every safety-critical precompile the batch used is priced by the
    /// model. When false, `total` is a lower bound, not an estimate.
    pub fn is_reliable(&self) -> bool {
        self.unpriced.is_empty()
    }

    /// `total` scaled by a safety `margin` and rounded up — the number to compare
    /// against the per-proof limit. The model systematically under-predicts by a
    /// couple of percent, so a `margin` of ~1.05–1.10 is a reasonable cushion for
    /// ordinary variance (pick per your risk tolerance; a bigger cushion trades
    /// throughput for safety). A margin does NOT compensate for unpriced
    /// precompiles — see [`Self::is_reliable`].
    pub fn conservative(&self, margin: f64) -> u64 {
        ((self.total as f64) * margin.max(1.0)).ceil() as u64
    }

    /// Whether the batch fits under `limit` after applying `margin`. **Fails
    /// safe**: an unreliable estimate (unpriced precompiles) never reports a fit,
    /// so a precompile the model can't price forces the caller to reject/split
    /// rather than silently ship an over-limit batch.
    pub fn fits(&self, limit: u64, margin: f64) -> bool {
        self.is_reliable() && self.conservative(margin) <= limit
    }
}

/// Assemble the full model feature vector from the passive tracer's counts plus
/// the batch-level features the tracer cannot see. This is the online mirror of
/// the offline `zksync_cycle_model::extract_features`, so the estimator consumes
/// exactly the features the model was calibrated on. `pubdata_bytes` and
/// `state_diff_count` come from the finished batch (`pubdata_input.len()` and
/// `state_diffs.len()`).
#[cfg(feature = "vm2-tracer")]
pub fn features_for_estimate(
    tracer: &CycleFeatureTracer,
    pubdata_bytes: u64,
    state_diff_count: u64,
    ctx: &BatchContext,
) -> FeatureVector {
    let mut fv = tracer.snapshot();

    // From the finished batch (exact).
    fv.add(FeatureId::PubdataBytes, pubdata_bytes);
    fv.add(FeatureId::StateDiffCount, state_diff_count);

    // From the sequencer-supplied context.
    fv.add(FeatureId::TransactionCount, ctx.transaction_count);
    fv.add(FeatureId::MerkleLeafCount, ctx.merkle_leaf_count);
    fv.add(FeatureId::StorageKeyCount, ctx.storage_key_count);
    fv.add(FeatureId::UsedBytecodeBytes, ctx.used_bytecode_bytes);
    fv.add(FeatureId::UsedBytecodeCount, ctx.used_bytecode_count);

    fv
}

/// Estimate guest cycles for a batch using the embedded cost model.
#[cfg(feature = "vm2-tracer")]
pub fn estimate(
    tracer: &CycleFeatureTracer,
    pubdata_bytes: u64,
    state_diff_count: u64,
    ctx: &BatchContext,
) -> CycleEstimate {
    estimate_with_model(
        CostModel::embedded(),
        tracer,
        pubdata_bytes,
        state_diff_count,
        ctx,
    )
}

/// Like [`estimate`], but against a caller-supplied model (e.g. a candidate table
/// under evaluation). Most callers want [`estimate`].
#[cfg(feature = "vm2-tracer")]
pub fn estimate_with_model(
    model: &CostModel,
    tracer: &CycleFeatureTracer,
    pubdata_bytes: u64,
    state_diff_count: u64,
    ctx: &BatchContext,
) -> CycleEstimate {
    let fv = features_for_estimate(tracer, pubdata_bytes, state_diff_count, ctx);
    CycleEstimate {
        total: model.predict_total(&fv),
        phases: model.predict_phases(&fv),
        unpriced: model.unpriced_used(&fv),
    }
}

#[cfg(all(test, feature = "vm2-tracer"))]
mod tests {
    use super::*;

    fn tracer_add(t: &CycleFeatureTracer, id: FeatureId, n: u64) {
        // exercise the shared recorder without a live VM
        t.recorder().lock().unwrap().add(id, n);
    }

    #[test]
    fn assembled_vector_merges_tracer_finished_and_context() {
        let tracer = CycleFeatureTracer::new();
        tracer_add(&tracer, FeatureId::StorageWrite, 3);
        let ctx = BatchContext {
            transaction_count: 7,
            merkle_leaf_count: 1000,
            storage_key_count: 900,
            used_bytecode_bytes: 50_000,
            used_bytecode_count: 12,
        };
        let fv = features_for_estimate(
            &tracer, /*pubdata*/ 4096, /*state_diffs*/ 42, &ctx,
        );
        assert_eq!(fv.get(FeatureId::StorageWrite), 3); // tracer
        assert_eq!(fv.get(FeatureId::PubdataBytes), 4096); // finished
        assert_eq!(fv.get(FeatureId::StateDiffCount), 42); // finished
        assert_eq!(fv.get(FeatureId::MerkleLeafCount), 1000); // context
        assert_eq!(fv.get(FeatureId::UsedBytecodeBytes), 50_000); // context
        assert_eq!(fv.get(FeatureId::TransactionCount), 7); // context
    }

    #[test]
    fn estimate_produces_total_and_phases() {
        let tracer = CycleFeatureTracer::new();
        let ctx = BatchContext {
            merkle_leaf_count: 2000,
            storage_key_count: 2000,
            used_bytecode_bytes: 5_000_000,
            used_bytecode_count: 150,
            transaction_count: 50,
        };
        let est = estimate(&tracer, 10_000, 1500, &ctx);
        assert!(est.total > 0);
        for phase in ["setup", "vm_execution", "merkle_verification", "commitment"] {
            assert!(est.phases.contains_key(phase));
        }
        assert!(est.is_reliable(), "no unpriced precompiles used");
        assert!(est.fits(u64::MAX, 1.10));
        assert!(!est.fits(0, 1.0));
    }

    #[test]
    fn conservative_margin_scales_and_never_shrinks() {
        let est = CycleEstimate {
            total: 1_000_000,
            phases: BTreeMap::new(),
            unpriced: vec![],
        };
        assert_eq!(est.conservative(1.10), 1_100_000);
        assert_eq!(est.conservative(1.0), 1_000_000);
        // a margin below 1.0 is clamped — the safe value is never below `total`.
        assert_eq!(est.conservative(0.5), 1_000_000);
    }

    #[test]
    fn unpriced_precompile_fails_safe() {
        // A batch that runs an ec_pairing (which the embedded model prices at 0)
        // must be flagged unreliable and never report a fit — even under a huge
        // limit and no margin.
        let tracer = CycleFeatureTracer::new();
        tracer_add(&tracer, FeatureId::EcPairingCycles, 5);
        let est = estimate(&tracer, 0, 0, &BatchContext::default());
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
        let tracer = CycleFeatureTracer::new();
        tracer_add(&tracer, FeatureId::Keccak256Cycles, 100_000);
        let est = estimate(&tracer, 0, 0, &BatchContext::default());
        assert!(est.is_reliable());
        assert!(est.total > 0);
    }

    #[test]
    fn calibrated_but_zero_coeff_feature_is_reliable() {
        // sha256 is calibrated (present in the corpus) but the fit found it
        // cheap/near-constant → zero coefficient. It must NOT be flagged unpriced,
        // otherwise every real batch (all use a little sha256) is falsely rejected.
        // Guards the guard's presence-not-sign semantics.
        let tracer = CycleFeatureTracer::new();
        tracer_add(&tracer, FeatureId::Sha256Cycles, 2_000);
        let est = estimate(&tracer, 0, 0, &BatchContext::default());
        assert!(
            est.is_reliable(),
            "sha256 is calibrated (present-with-0); must not be flagged unpriced"
        );
    }
}
