//! Airbender cycle-cost calibration harness.
//!
//! Offline tooling that correlates cheap, natively-computable vm2 execution
//! features with ground-truth Airbender RISC-V guest cycles, so the sequencer
//! can later predict a batch's proving cost without any RISC-V execution.
pub mod dataset;
pub mod features;
pub mod runner;
pub mod tracer;

pub use dataset::{extract_features, write_dataset, DatasetRow};
pub use features::{FeatureId, FeatureVector};
pub use runner::{run_guest, GuestMeasurement};
pub use tracer::CycleFeatureTracer;
