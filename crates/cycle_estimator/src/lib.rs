//! Airbender guest cycle-count estimator.
//!
//! Predicts how many Airbender RISC-V guest cycles a batch will cost when
//! re-executed by the verifier, from a live `zksync_vm2` execution trace — with
//! no RISC-V execution. Intended for the sequencer, to decide whether a batch
//! fits the per-proof cycle limit while it is being built.
//!
//! - [`CycleFeatureTracer`] — passive vm2 tracer; attach it during execution.
//! - [`estimate`] — combine the tracer's counts with a few batch-level scalars
//!   ([`BatchContext`]) and the embedded [`CostModel`] into a [`CycleEstimate`].
//!
//! The cost table is calibrated offline (see the `zksync_cycle_model` crate) and
//! committed at `model/cost_table.json`.
pub mod estimator;
pub mod features;
pub mod model;
pub mod tracer;

pub use estimator::{
    estimate, estimate_with_model, features_for_estimate, BatchContext, CycleEstimate,
};
pub use features::{FeatureId, FeatureVector, SAFETY_CRITICAL_FEATURES};
pub use model::{CostModel, LinearModel};
pub use tracer::CycleFeatureTracer;
