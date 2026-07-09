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
#[cfg(feature = "vm2-tracer")]
pub mod tracer;

// VM-agnostic surface — usable without the vm2 tracer (e.g. from zksync-era's
// in-tree legacy-VM tracer). `EMBEDDED_COST_TABLE` lets a consumer source the
// calibrated constants from this repo without vendoring them.
pub use estimator::{BatchContext, CycleEstimate};
pub use features::{FeatureId, FeatureVector, SAFETY_CRITICAL_FEATURES};
pub use model::{CostModel, LinearModel, EMBEDDED_COST_TABLE};

// Fast-VM (vm2) tracer + its convenience wrappers. Gated so consumers that only
// need the cost model / feature schema / cost table do not pull `zksync_vm2`.
#[cfg(feature = "vm2-tracer")]
pub use estimator::{estimate, estimate_with_model, features_for_estimate};
#[cfg(feature = "vm2-tracer")]
pub use tracer::CycleFeatureTracer;
