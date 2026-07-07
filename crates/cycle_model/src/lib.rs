//! Airbender cycle-cost calibration harness + online estimator.
//!
//! Two halves that share one feature schema:
//! - **Offline calibration** ([`dataset`], [`runner`]): correlate cheap,
//!   natively-computable vm2 execution features with ground-truth Airbender
//!   RISC-V guest cycles, producing the fitted cost table.
//! - **Online estimation** ([`model`], [`estimator`]): the sequencer attaches
//!   [`CycleFeatureTracer`] while executing a batch and calls [`estimate`] to
//!   predict the batch's proving cost — no RISC-V execution — using the cost
//!   table committed at `model/cost_table.json`.
pub mod dataset;
pub mod estimator;
pub mod features;
pub mod model;
pub mod runner;
pub mod tracer;

pub use dataset::{extract_features, write_dataset, DatasetRow};
pub use estimator::{estimate, features_for_estimate, BatchContext, CycleEstimate};
pub use features::{FeatureId, FeatureVector};
pub use model::{CostModel, LinearModel};
pub use runner::{run_guest, GuestMeasurement};
pub use tracer::CycleFeatureTracer;
