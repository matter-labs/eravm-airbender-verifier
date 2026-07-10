//! Cycle-count estimation inputs and result.
//!
//! Defines the two batch-level pieces the VM trace cannot observe — the
//! [`BatchContext`] inputs the sequencer supplies, and the [`CycleEstimate`]
//! result the model produces. A tracer (the sibling
//! `zksync-era-airbender-cycles-tracer` crate for the fast VM, or zksync-era's
//! in-tree legacy-VM tracer) assembles a [`crate::FeatureVector`] and feeds it,
//! together with these scalars, to [`crate::CostModel`].
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
    /// safe**: an unreliable estimate (unpriced precompiles) never reports a fit,
    /// so a precompile the model can't price forces the caller to reject/split
    /// rather than silently ship an over-limit batch.
    pub fn fits(&self, limit: u64, margin: f64) -> bool {
        self.is_reliable() && self.conservative(margin) <= limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
