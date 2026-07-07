//! Airbender cycle-cost calibration harness (offline).
//!
//! Measures real batches — cheap `zksync_vm2` features paired with ground-truth
//! Airbender RISC-V guest cycles — and produces the dataset the cost model is fit
//! from. The feature schema, passive tracer, cost model, and online estimator
//! live in the lean [`zksync_era_airbender_cycles_estimator`] crate (which the
//! sequencer uses); this crate builds the labelled dataset on top of it.
pub mod dataset;
pub mod runner;

pub use dataset::{extract_features, write_dataset, DatasetRow};
pub use runner::{run_guest, GuestMeasurement};

// Re-export the shared schema/model so existing `zksync_cycle_model::{FeatureId,
// CostModel, ...}` paths keep working and callers need only this crate.
pub use zksync_era_airbender_cycles_estimator::{
    estimate, BatchContext, CostModel, CycleEstimate, CycleFeatureTracer, FeatureId, FeatureVector,
    LinearModel,
};
