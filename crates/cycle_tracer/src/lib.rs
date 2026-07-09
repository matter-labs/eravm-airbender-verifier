//! Fast-VM (`zksync_vm2`) tracer + online estimator for the Airbender cycle-cost
//! model.
//!
//! The sequencer attaches a [`CycleFeatureTracer`] while it executes a batch on
//! the fast VM (it is passive — no VM-state mutation, so execution is identical
//! to a proved run). After the batch finishes it calls [`estimate`] with two
//! scalars from the batch output plus a small [`BatchContext`], and gets a
//! predicted guest cycle count to compare against the per-proof limit — with no
//! RISC-V execution.
//!
//! The feature schema, fitted cost model, and result type live in the
//! VM-agnostic [`zksync_era_airbender_cycles_estimator`] crate; this crate is the
//! `zksync_vm2` half that observes a live execution and feeds that model.
//!
//! [`BatchContext`]: zksync_era_airbender_cycles_estimator::BatchContext
pub mod estimator;
pub mod tracer;

pub use estimator::{estimate, estimate_with_model, features_for_estimate};
pub use tracer::CycleFeatureTracer;
