//! Airbender guest cycle-count model.
//!
//! Predicts how many Airbender RISC-V guest cycles a batch will cost when
//! re-executed by the verifier, from a feature vector — with no RISC-V
//! execution. Intended for the sequencer, to decide whether a batch fits the
//! per-proof cycle limit while it is being built.
//!
//! This crate is VM-agnostic: it defines the [`FeatureVector`] schema and the
//! fitted [`CostModel`], and exposes the batch-level inputs ([`BatchContext`])
//! and result ([`CycleEstimate`]). It does NOT observe a VM — the vm2 tracer
//! that fills the feature vector lives in the sibling
//! `zksync-era-airbender-cycles-tracer` crate, and zksync-era has its own
//! in-tree legacy-VM tracer. Both feed the SAME calibrated model here.
//!
//! The cost table is calibrated offline (see the `zksync_cycle_model` crate) and
//! committed at `model/cost_table.json`.
pub mod estimator;
pub mod features;
pub mod model;

pub use estimator::{assemble_feature_vector, estimate_from_features, BatchContext, CycleEstimate};
pub use features::{FeatureId, FeatureVector, SAFETY_CRITICAL_FEATURES};
pub use model::{CostModel, LinearModel, EMBEDDED_COST_TABLE};
