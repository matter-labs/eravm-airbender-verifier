//! Online cycle-count estimation from a live vm2 execution.
//!
//! After driving a batch through the passive [`CycleFeatureTracer`], call
//! [`estimate`] with two scalars from the batch output plus a small
//! [`BatchContext`] to get a predicted guest cycle count — with no RISC-V
//! execution. These are the `zksync_vm2` convenience wrappers over the
//! VM-agnostic [`CostModel`] in `zksync-era-airbender-cycles-estimator`.

use zksync_era_airbender_cycles_estimator::{
    assemble_feature_vector, estimate_from_features_with_model, BatchContext, CostModel,
    CycleEstimate, FeatureVector,
};

use crate::tracer::CycleFeatureTracer;

/// Assemble the full model feature vector from the passive tracer's counts plus
/// the batch-level features the tracer cannot see. This is the online mirror of
/// the offline `zksync_cycle_model::extract_features`, so the estimator consumes
/// exactly the features the model was calibrated on. `pubdata_bytes` and
/// `state_diff_count` come from the finished batch (`pubdata_input.len()` and
/// `state_diffs.len()`).
pub fn features_for_estimate(
    tracer: &CycleFeatureTracer,
    pubdata_bytes: u64,
    state_diff_count: u64,
    ctx: &BatchContext,
) -> FeatureVector {
    // Delegate to the VM-agnostic assembly step so the fast VM and any other
    // consumer share one implementation.
    assemble_feature_vector(tracer.snapshot(), pubdata_bytes, state_diff_count, ctx)
}

/// Estimate guest cycles for a batch using the embedded cost model.
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
pub fn estimate_with_model(
    model: &CostModel,
    tracer: &CycleFeatureTracer,
    pubdata_bytes: u64,
    state_diff_count: u64,
    ctx: &BatchContext,
) -> CycleEstimate {
    estimate_from_features_with_model(
        model,
        tracer.snapshot(),
        pubdata_bytes,
        state_diff_count,
        ctx,
    )
}

#[cfg(test)]
mod tests {
    use zksync_era_airbender_cycles_estimator::FeatureId;

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
    fn unpriced_precompile_fails_safe() {
        // A batch that runs a precompile the model does NOT price must be flagged
        // unreliable and never report a fit — even under a huge limit and no margin.
        // The embedded model now prices every safety-critical precompile (they were
        // all calibrated), so exercise the guard against a table that omits one.
        let model = CostModel::from_json(
            r#"{"batches":1,"phases":{},"total":{"features":{"storage_write":100.0},"base":1000.0}}"#,
        )
        .unwrap();
        let tracer = CycleFeatureTracer::new();
        tracer_add(&tracer, FeatureId::EcPairingCycles, 5);
        let est = estimate_with_model(&model, &tracer, 0, 0, &BatchContext::default());
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
