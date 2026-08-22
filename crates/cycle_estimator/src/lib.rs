#![deny(rustdoc::broken_intra_doc_links)]
//! Airbender guest cycle-count model.
//!
//! Predicts how many Airbender RISC-V guest cycles a batch will cost when
//! re-executed by the verifier, from a feature vector — with no RISC-V
//! execution. Intended for the sequencer, to decide whether a batch fits the
//! per-proof cycle limit while it is being built.
//!
//! This crate is VM-agnostic: it defines the [`FeatureVector`] schema and the
//! measured [`CostTable`], and exposes the batch-level inputs
//! and result ([`CycleEstimate`]). It does NOT observe a VM — the vm2 tracer
//! that fills the feature vector lives in the sibling
//! `zksync-era-airbender-cycles-tracer` crate, and zksync-era has its own
//! in-tree legacy-VM tracer. Both feed the SAME calibrated model here.
//!
//! The cost table is calibrated offline (see the `zksync_cycle_model` crate) and
//! committed at `model/cost_table.json`.
//!
//! # Premises of the safety invariant
//!
//! The goal — *no batch is both trusted by the gate and materially under-predicted* —
//! is a property of the model AND the host it models, checked against a finite fixture
//! set. Break one of these and the invariant goes with it.
//!
//! 1. **Each bytecode byte is decoded at most once per batch.** Holds while the program
//!    cache is unbounded. Under a cache cap a cyclic working set larger than the cap
//!    re-decodes per far call, which no feature would see. Re-check before adding a cap.
//! 2. **Frame churn cannot be amplified past the calibrated domain.** Reaching the ceiling
//!    needs ~1.68M near-call iterations; the domain check declines above ~314k. Previously
//!    this rested on an arithmetic-share heuristic, now removed.
//! 3. **A repeat `DECOMMIT` is priced.** It re-resolves bytes O(len) while vm2 refunds the
//!    burn and emits no `CycleStats::Decommit`. Counted via that absence and bounded at the
//!    largest deployable bytecode. vm2 PR #130 removes the dead work.
//! 4. **Every precompile rate bounds its true cost over reachable inputs.** Verified by
//!    input sweeps: `mod_exp` linear in exponent bits and `ec_mul` saturating in scalar
//!    bits, both invisible to the tracer and so bounded at the maximum; `ec_pairing`
//!    carries its pair count and is measured per pair. **The open case is `arith_div_op`**
//!    — the family designed to find the worst divisor path is dead in the corpus, so its
//!    bound is the worst *measured* regime, on the one axis that alone approaches the
//!    ceiling.
//!
//! # Cycles only — not a memory control
//!
//! [`CycleEstimate`] has no memory field, and on every measured decommit-flood
//! shape the heap arena is exhausted *before* the cycle budget (memory binds at
//! roughly a third of the cycle-binding gas level, where the prediction sits at
//! ~26–37% of the limit and `fits()` is true). Peak memory needs its own
//! criterion.
pub mod estimator;
pub mod features;
pub mod model;

pub use estimator::{estimate_from_features, CycleEstimate};
pub use features::{FeatureId, FeatureVector, VM_TRACE_FEATURES};
pub use model::{
    Base, CostEntry, CostTable, Provenance, TableProvenance, EMBEDDED_COST_TABLE,
    PROVING_CYCLE_CEILING,
};
