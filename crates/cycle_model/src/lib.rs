//! Airbender cycle-cost calibration harness.
//!
//! Offline tooling that correlates cheap, natively-computable vm2 execution
//! features with ground-truth Airbender RISC-V guest cycles, so the sequencer
//! can later predict a batch's proving cost without any RISC-V execution.
pub mod features;

pub use features::{FeatureId, FeatureVector};
