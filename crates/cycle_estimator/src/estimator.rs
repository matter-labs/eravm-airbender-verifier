//! The API a sequencer calls: assemble a feature vector, apply the cost table, and
//! decide.
//!
//! The estimate is `base + Σ rate · count` (see [`crate::model`]) — arithmetic, not
//! a fit. What this module adds is the decision surface: the two signals that say
//! whether the number can be trusted, and the margin that covers the residual.

use crate::features::{FeatureId, FeatureVector};
use crate::model::CostTable;

/// A cycle-cost estimate, and whether to believe it.
#[derive(Debug, Clone)]
pub struct CycleEstimate {
    /// Predicted effective cycles. Compare [`Self::conservative`] against the
    /// per-proof budget, not this.
    pub total: u64,
    /// `total` without the per-batch base — the number a PER-TRANSACTION screen must use.
    ///
    /// `total` includes a per-batch constant of ~1.15e9 cycles, so using it to price a
    /// single transaction charges that transaction for the whole batch's fixed cost. See
    /// [`CostTable::predict_marginal`].
    pub marginal: u64,
    /// The safety factor the table declares, carried with the estimate so no caller can
    /// substitute its own. See [`Self::conservative`].
    pub margin: f64,
    /// Predicted RAW main-trace cycles, excluding delegation-circuit cost.
    ///
    /// **Not** the gate quantity — the 2^36 ceiling applies to [`Self::total`]. This is
    /// reported so the consumer has a prediction it can check: `total` depends on
    /// `effective = raw + 16*blake2 + 4*bigint + 4*keccak`, and those weights have no
    /// authoritative source in this tree, while `raw` is what the prover reports
    /// directly. Logging predicted-vs-actual on this field is how the table gets
    /// corrected from production feedback instead of from another offline campaign.
    ///
    /// The two are not proportional: the delegation share runs from 11.6% of
    /// `mod_exp_cycles` to 42.0% of `secp256r1_verify_cycles`, so a revision of the
    /// weights re-ranks the table rather than rescaling it. That is precisely why both
    /// numbers are worth carrying.
    pub raw: u64,
    /// Operations the batch uses that the table cannot price — see
    /// [`CostTable::untrusted_pricing`].
    ///
    /// With the `Fitted` provenance gone there is no present-but-guessed case left, so
    /// this now keys purely on absence: an axis with no rate and no deliberate-unpriced
    /// entry. Empty on every batch the committed table can price, which is all of them.
    pub untrusted: Vec<FeatureId>,
    /// Operations whose count is beyond the range their rate was calibrated over.
    ///
    /// Renamed from `extrapolated`, and now one uniform check over per-entry
    /// domains rather than an arithmetic-share cap plus a volume cap.
    pub extrapolating: Vec<FeatureId>,
    /// The batch claims work but its VM trace is empty — nobody wired a tracer.
    pub trace_missing: bool,
}

impl CycleEstimate {
    /// Every operation the batch used is priced by a measurement or a deliberate
    /// bound, and a tracer actually ran.
    pub fn is_reliable(&self) -> bool {
        self.untrusted.is_empty() && !self.trace_missing
    }

    /// Every count is inside the range its rate was calibrated over.
    pub fn is_within_calibration(&self) -> bool {
        self.extrapolating.is_empty()
    }

    /// `total` padded by a safety factor and rounded up — the number to compare
    /// against the per-proof budget.
    ///
    /// The margin covers residual error in the base and in the rates, and nothing
    /// else. It is not a substitute for a missing rate: no margin rescues an
    /// operation whose price is a guess, which is what [`Self::is_reliable`] is for.
    ///
    /// Takes no argument on purpose. It used to, and the margin then existed in three
    /// values at once — 1.30 calibrated in the table, 1.15 quoted in a test comment, and
    /// 1.05 hard-coded in the deployed consumer, the last of those below the 1.0955 floor
    /// the calibration derives. The calibrated number now travels with the estimate and
    /// no caller can substitute its own.
    pub fn conservative(&self) -> u64 {
        ((self.total as f64) * self.margin.max(1.0)).ceil() as u64
    }
}

/// Estimate a batch: a traced feature vector plus the four quantities no VM trace can
/// observe. VM-agnostic, so a fast-VM tracer, a legacy-VM tracer or a hand-built vector
/// all feed the model the same way.
///
/// The batch-level scalars are named arguments rather than a struct. They used to arrive
/// through two channels at once — two bare arguments and a two-field `BatchContext` —
/// residue of a five-field struct whose other three fields no online producer could
/// supply. One channel is enough for four numbers.
pub fn estimate_from_features(
    mut vm_features: FeatureVector,
    pubdata_bytes: u64,
    state_diff_count: u64,
    transaction_count: u64,
    merkle_leaf_count: u64,
) -> CycleEstimate {
    vm_features.add(FeatureId::PubdataBytes, pubdata_bytes);
    vm_features.add(FeatureId::StateDiffCount, state_diff_count);
    vm_features.add(FeatureId::TransactionCount, transaction_count);
    vm_features.add(FeatureId::MerkleLeafCount, merkle_leaf_count);
    CostTable::embedded().estimate(&vm_features)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but real-shaped trace: enough opcode traffic that the
    /// missing-trace signal treats it as an actual execution.
    fn traced() -> FeatureVector {
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::ArithCheapOp, 1_000_000);
        fv.add(FeatureId::AverageOp, 50_000);
        fv.add(FeatureId::FarCall, 500);
        fv.add(FeatureId::UmaRead, 20_000);
        fv
    }

    #[test]
    fn conservative_scales_and_never_shrinks() {
        let est = CostTable::embedded().estimate(&traced());
        assert!(
            est.conservative() > est.total,
            "the margin must pad the estimate"
        );

        // The `.max(1.0)` clamp now guards the TABLE's own margin rather than a caller's
        // argument, so that is where it has to be exercised: a table shipping a margin
        // below 1 must not be able to shrink an estimate below its own prediction.
        let shrinking = CycleEstimate {
            margin: 0.5,
            ..est.clone()
        };
        assert_eq!(
            shrinking.conservative(),
            shrinking.total,
            "a table margin below 1 must not shrink an estimate"
        );
    }

    #[test]
    fn an_untraced_batch_that_claims_work_is_not_reliable() {
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::TransactionCount, 40);
        fv.add(FeatureId::PubdataBytes, 200_000);
        let est = CostTable::embedded().estimate(&fv);
        assert!(est.trace_missing);
        assert!(!est.is_reliable());
    }

    #[test]
    fn a_real_trace_is_not_flagged_as_untraced() {
        assert!(!CostTable::embedded().estimate(&traced()).trace_missing);
    }

    #[test]
    fn an_empty_batch_is_not_flagged_as_untraced() {
        // No claimed work, so nothing to be missing — otherwise every empty batch
        // would read as a wiring bug.
        assert!(
            !CostTable::embedded()
                .estimate(&FeatureVector::default())
                .trace_missing
        );
    }

    /// Every batch-level scalar must actually influence the estimate.
    ///
    /// Stronger than the previous version, which read the four counts back out of the
    /// assembled vector — that only proved the map had been written to. What matters is
    /// that the number reaches a PRICED axis: a scalar plumbed into a feature the table
    /// does not price is silently ignored, which is exactly what happened to
    /// `merkle_leaf_count` (era computes a careful proxy for it and the table prices it at
    /// zero). This test fails in that case; the old one passed.
    #[test]
    fn every_batch_scalar_moves_the_estimate() {
        let base = estimate_from_features(traced(), 4_096, 42, 370, 3_782).total;
        for (name, est) in [
            (
                "pubdata_bytes",
                estimate_from_features(traced(), 8_192, 42, 370, 3_782),
            ),
            (
                "state_diff_count",
                estimate_from_features(traced(), 4_096, 84, 370, 3_782),
            ),
            (
                "transaction_count",
                estimate_from_features(traced(), 4_096, 42, 740, 3_782),
            ),
            (
                "merkle_leaf_count",
                estimate_from_features(traced(), 4_096, 42, 370, 7_564),
            ),
        ] {
            if name == "merkle_leaf_count" {
                // Known and deliberate: charged through `storage_application`, which it
                // never exceeds, so pricing it too would double-charge. It is on the
                // table's `unpriced` list. Left in the signature because era supplies it
                // and a memory model will want it; asserted here so that if it ever gains
                // a rate, this exemption is what fails first.
                assert_eq!(est.total, base, "{name} is expected to be unpriced");
                continue;
            }
            assert!(
                est.total > base,
                "doubling {name} did not change the estimate, so it reaches no priced axis"
            );
        }
    }

    #[test]
    fn a_bounded_price_still_counts_as_reliable() {
        // The point of the Provenance split: a deliberate upper bound cannot cause
        // an under-estimate, so it must not make the gate refuse. Only a guess does.
        let mut fv = traced();
        fv.add(FeatureId::ModExpCycles, 10_000);
        let est = CostTable::embedded().estimate(&fv);
        assert!(
            est.is_reliable(),
            "mod_exp is bounded, not guessed — untrusted={:?}",
            est.untrusted
        );
    }
}
