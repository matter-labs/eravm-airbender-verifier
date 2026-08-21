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
//!
//! # Premises of the safety invariant
//!
//! The goal — *no batch is both trusted by [`CycleEstimate::fits`] and
//! materially under-predicted* — is a property of the model AND the host it
//! models, checked against a finite fixture set. Break one of these and the
//! invariant goes with it:
//!
//! 1. **Each bytecode byte is decoded at most once per batch.** Holds while the
//!    program cache is unbounded. Under a cache cap, a cyclic working set larger
//!    than the cap re-decodes per far call: 46.25M guest cycles per 2 MiB, up to
//!    1,006× the prediction, reported as a fit. Fenced today only because such a
//!    set also blows through the `decommit_cycles` envelope.
//! 2. **Per-frame stack clearing is not attacker-amplifiable.** A frame-churn
//!    loop dirtying the pooled stack costs ~730k host cycles/iteration vs ~20k
//!    predicted (36.5×; 46.1× with an in-place-clear variant). Rejected only
//!    *incidentally*, by [`model::Calibration::rich_addressing_share_max`].
//! 3. **`World::decommit_code` is not repeat-hammered.** A repeat query
//!    re-resolves the bytes O(len) while vm2 refunds the burn and emits no
//!    `CycleStats::Decommit` — the work moves no feature and no fence sees it.
//!    Magnitude **unmeasured**: estimates on record disagree (~4× re-resolve,
//!    ~70× cache-hit rebuild), so the direction is established and any single
//!    multiplier is not. Pricing it needs a hook vm2 does not expose.
//! 4. **Precompile coefficients bound their true cost.** Enforced for *unseen*
//!    precompiles by [`CostModel::unpriced_used`]; a present-but-underdetermined
//!    coefficient is not (`ec_recover_cycles` barely varies organically, so its
//!    fitted value is an artifact in whichever direction the fit landed).
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

pub use estimator::{assemble_feature_vector, estimate_from_features, BatchContext, CycleEstimate};
pub use features::{
    FeatureId, FeatureVector, OFFLINE_ONLY_FEATURES, SAFETY_CRITICAL_FEATURES, VM_TRACE_FEATURES,
};
pub use model::{
    Calibration, CostModel, LinearModel, Provenance, EMBEDDED_COST_TABLE,
    SHARE_EXTRAPOLATION_FACTOR, VOLUME_EXTRAPOLATION_FACTOR,
};
