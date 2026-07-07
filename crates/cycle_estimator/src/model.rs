//! The fitted cost model and cycle-count prediction.
//!
//! The model is a set of non-negative linear predictors (one per verify() phase,
//! plus an aggregate `total`) of the form `cycles = base + Σ coeff_i · feature_i`,
//! learned offline by `scripts/cycle_model/fit_cost_model.py`. The canonical
//! fitted table is committed at `model/cost_table.json` and compiled into the
//! binary via `include_str!`, so a deployed sequencer needs no model file on disk.
//!
//! To ship a new model: refit, drop the resulting `cost_table.json` into
//! `crates/cycle_estimator/model/`, and rebuild (see `scripts/cycle_model/README.md`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::features::{FeatureId, FeatureVector, SAFETY_CRITICAL_FEATURES};

/// The committed cost table, embedded at compile time.
const EMBEDDED_COST_TABLE: &str = include_str!("../model/cost_table.json");

/// One linear predictor: `base + Σ features[i] · counts[i]`. Coefficients are
/// keyed by [`FeatureId`] (the JSON uses the same snake_case names), so a table
/// that references an unknown feature fails to parse — a built-in drift guard.
#[derive(Debug, Clone, Deserialize)]
pub struct LinearModel {
    pub features: BTreeMap<FeatureId, f64>,
    pub base: f64,
    #[serde(default)]
    pub r2: f64,
}

impl LinearModel {
    /// Predict cycles for a feature vector. Missing features count as 0. The
    /// result is clamped at 0 and rounded (cycle counts are non-negative integers).
    pub fn predict(&self, fv: &FeatureVector) -> u64 {
        let mut acc = self.base;
        for (id, coeff) in &self.features {
            acc += coeff * fv.get(*id) as f64;
        }
        acc.max(0.0).round() as u64
    }
}

/// The full fitted cost model: an aggregate `total` predictor over effective cycles
/// plus a per-phase predictor for each verify() phase.
#[derive(Debug, Clone, Deserialize)]
pub struct CostModel {
    /// Number of batches the model was fit on (provenance only).
    #[serde(default)]
    pub batches: u64,
    pub phases: BTreeMap<String, LinearModel>,
    pub total: LinearModel,
}

impl CostModel {
    /// Parse a cost table from JSON (as emitted by `fit_cost_model.py`).
    pub fn from_json(s: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// The canonical model committed in this crate, parsed once.
    pub fn embedded() -> &'static CostModel {
        static MODEL: OnceLock<CostModel> = OnceLock::new();
        MODEL.get_or_init(|| {
            CostModel::from_json(EMBEDDED_COST_TABLE).expect(
                "embedded cost_table.json is malformed — regenerate it with fit_cost_model.py",
            )
        })
    }

    /// Aggregate prediction of **effective (native-computational) cycles** — the
    /// main RISC-V trace plus the weighted delegation-circuit cost (Blake2 ×16,
    /// keccak/bigint ×4) that the raw cycle count omits. Includes the guest
    /// prologue/epilogue (absorbed by the base). This is the number to compare
    /// against the per-proof native budget.
    pub fn predict_total(&self, fv: &FeatureVector) -> u64 {
        self.total.predict(fv)
    }

    /// Per-phase predictions (setup / vm_execution / merkle_verification /
    /// commitment), for insight into where the cycles go.
    pub fn predict_phases(&self, fv: &FeatureVector) -> BTreeMap<String, u64> {
        self.phases
            .iter()
            .map(|(name, m)| (name.clone(), m.predict(fv)))
            .collect()
    }

    /// Safety-critical precompile/crypto features (see
    /// [`SAFETY_CRITICAL_FEATURES`]) the batch uses but that the model **never
    /// calibrated** — i.e. absent from the aggregate predictor because the
    /// corpus never exercised that precompile (e.g. ec_pairing, modexp). A
    /// non-empty result means the prediction omits an unbounded, un-priced cost
    /// and must not be trusted (fail safe); no safety multiplier rescues it.
    ///
    /// A feature that IS in the model but with a zero coefficient is *not*
    /// flagged: it was calibrated and found cheap/near-constant (e.g. sha256,
    /// which the corpus contains at low volume), so the base already covers it.
    /// Its only risk is linear extrapolation to volumes far beyond the corpus —
    /// that is the safety-margin's job, not the unknown-op guard's. (Presence,
    /// not coefficient sign, is the signal — else every batch, which all use a
    /// little sha256, would be falsely rejected.)
    pub fn unpriced_used(&self, fv: &FeatureVector) -> Vec<FeatureId> {
        SAFETY_CRITICAL_FEATURES
            .iter()
            .copied()
            .filter(|id| fv.get(*id) > 0 && !self.total.features.contains_key(id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_model_parses_and_has_all_phases() {
        let m = CostModel::embedded();
        for phase in ["setup", "vm_execution", "merkle_verification", "commitment"] {
            assert!(m.phases.contains_key(phase), "missing phase {phase}");
        }
        // The total predictor must have learned coefficients (its base may be 0
        // once per-feature terms absorb the offset).
        assert!(!m.total.features.is_empty());
    }

    #[test]
    fn predict_is_base_plus_weighted_features() {
        let model = LinearModel {
            features: BTreeMap::from([
                (FeatureId::MerkleLeafCount, 100.0),
                (FeatureId::StateDiffCount, 10.0),
            ]),
            base: 1000.0,
            r2: 1.0,
        };
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::MerkleLeafCount, 5);
        fv.add(FeatureId::StateDiffCount, 2);
        // 1000 + 100*5 + 10*2
        assert_eq!(model.predict(&fv), 1520);
    }

    #[test]
    fn embedded_model_features_are_all_known_ids() {
        // from_json already enforces this (FeatureId keys); this documents intent
        // and fails loudly if the committed table drifts from the enum.
        let _ = CostModel::embedded();
    }
}
