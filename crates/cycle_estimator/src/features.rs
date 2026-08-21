use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Stable, ordered identifier for one calibration feature (a model INPUT —
/// something the sequencer can compute natively from a vm2 trace).
///
/// Opcode-family variants mirror the buckets in
/// `crates/multivm/src/versions/vm_fast/tracers/circuits.rs`; crypto/size
/// variants add Airbender-relevant dimensions that tracer omits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum FeatureId {
    // vm2 opcode-family counts (from `after_instruction`)
    /// LEGACY AGGREGATE — the whole arithmetic bucket as one count. The tracer no
    /// longer emits it and `total` must not price it; the variant survives so
    /// tables and datasets predating the 2026-08-21 split still parse. Superseded
    /// by [`ARITHMETIC_FEATURES`], because one coefficient cannot serve a bucket
    /// whose members were measured 67x apart (`add` 137 vs `div` 9,188 cyc/op).
    RichAddressingOp,
    // Arithmetic bucket, split by MEASURED cost class (2026-08-21). Grouping is by
    // isolated per-op cost, not by opcode taxonomy: two opcodes share a feature
    // only if they cost about the same. See ARITHMETIC_FEATURES.
    /// Single-word ALU and control flow: `Nop`/`Add`/`Sub`/`Jump`/`Xor`/`And`/`Or`.
    ArithCheapOp,
    /// `ShiftLeft`/`ShiftRight`/`RotateLeft`/`RotateRight`.
    ArithShiftOp,
    /// `Mul` — 256x256 -> 512, materially dearer than the cheap class.
    ArithMulOp,
    /// `Div` — 512/256 long division, the most expensive opcode in the VM per erg
    /// and the reason this split exists.
    ArithDivOp,
    /// Fat-pointer arithmetic: `PointerAdd`/`PointerSub`/`PointerPack`/`PointerShrink`.
    ArithPtrOp,
    AverageOp,
    StorageRead,
    StorageWrite,
    TransientStorageRead,
    TransientStorageWrite,
    Event,
    PrecompileCall,
    Decommit,
    FarCall,
    UmaWrite,
    UmaRead,
    // crypto complexity (from `on_extra_prover_cycles`, value = cycles/rounds)
    Keccak256Cycles,
    Sha256Cycles,
    EcRecoverCycles,
    Secp256r1VerifyCycles,
    ModExpCycles,
    EcAddCycles,
    EcMulCycles,
    EcPairingCycles,
    DecommitCycles,
    StorageApplication,
    // batch-level features
    TransactionCount,
    NearCallCount,
    PubdataBytes,
    MerkleLeafCount,
    // setup-phase drivers (batch-level, from input.vm_run_data) — the verifier
    // hashes every used bytecode and materializes the storage view + initial
    // heap before the VM runs; the vm2 tracer never observes this work.
    UsedBytecodeBytes,
    UsedBytecodeCount,
    StorageKeyCount,
    InitialHeapWords,
    // commitment-phase drivers (from the finished batch) — keccak over the
    // serialized state diffs and system logs.
    StateDiffCount,
    SystemLogCount,
}

/// Precompile / crypto complexity features that are expensive per unit and whose
/// cost the model MUST price for an estimate to be trustworthy. If a batch uses
/// one of these but the model prices it at ~0 (no coefficient — e.g. the corpus
/// never exercised that precompile), the prediction silently omits that work and
/// is an under-estimate. The estimator flags this via
/// [`crate::model::CostModel::unpriced_used`] so callers can fail safe.
///
/// These are the values of [`CycleStats`](zksync_vm2::interface::CycleStats):
/// each is measured as operation complexity (hashing rounds / circuit cycles),
/// so it already scales with input size — a bigger keccak yields a bigger count.
pub const SAFETY_CRITICAL_FEATURES: &[FeatureId] = &[
    FeatureId::Keccak256Cycles,
    FeatureId::Sha256Cycles,
    FeatureId::EcRecoverCycles,
    FeatureId::Secp256r1VerifyCycles,
    FeatureId::ModExpCycles,
    FeatureId::EcAddCycles,
    FeatureId::EcMulCycles,
    FeatureId::EcPairingCycles,
];

/// Features any real VM execution produces, emitted by a tracer from
/// `after_instruction` / `on_extra_prover_cycles` (the vm2 tracer in
/// `zksync-era-airbender-cycles-tracer`, or era's in-tree legacy-VM one).
///
/// One transaction retires thousands of these — bootloader far-calls, heap (UMA)
/// traffic, arithmetic. All-zero across the whole set therefore does not mean "a
/// tiny batch", it means **no tracer ran**, and must read as UNRELIABLE — see
/// [`crate::model::CostModel::trace_missing`].
/// The arithmetic cost classes that replaced [`FeatureId::RichAddressingOp`].
///
/// The bucket was split because isolated measurement found a **55x spread inside
/// it** — `add` 137, `mul` 871, `div` 9,188 effective cycles per op — so any single
/// coefficient is either unsafe on `div` or ruinous on `add`: one safe against
/// the dear end costs 14.73% organic MAPE against 5.97%, and no share- or
/// volume-based guard can separate
/// them (organic traffic already runs within 1.23x of the arithmetic COUNT that
/// reaches the 2^36 ceiling with `div`, and `add`/`div` differ 67x at identical
/// count and share — the information simply is not in an aggregate count).
///
/// This list is also what the arithmetic half of the extrapolation envelope sums
/// over, so a new arithmetic feature must be added here or it is silently
/// unguarded.
pub const ARITHMETIC_FEATURES: &[FeatureId] = &[
    FeatureId::ArithCheapOp,
    FeatureId::ArithShiftOp,
    FeatureId::ArithMulOp,
    FeatureId::ArithDivOp,
    FeatureId::ArithPtrOp,
];

pub const VM_TRACE_FEATURES: &[FeatureId] = &[
    FeatureId::ArithCheapOp,
    FeatureId::ArithShiftOp,
    FeatureId::ArithMulOp,
    FeatureId::ArithDivOp,
    FeatureId::ArithPtrOp,
    FeatureId::AverageOp,
    FeatureId::StorageRead,
    FeatureId::StorageWrite,
    FeatureId::Event,
    FeatureId::PrecompileCall,
    FeatureId::Decommit,
    FeatureId::FarCall,
    FeatureId::UmaWrite,
    FeatureId::UmaRead,
];

/// Features NO online producer supplies: not VM observables, and
/// [`crate::BatchContext`] deliberately omits them. They exist only in the
/// offline dataset, where `cycle_bench` derives them from the verifier input.
///
/// A non-zero coefficient on one of these in `total` is **train/serve skew** —
/// the fit prices work the deployed estimator feeds as 0, so it under-estimates.
/// Enforced twice: `TOTAL_EXCLUDE` in `fit_cost_model.py` keeps them out of the
/// fit, and `model::tests::total_prices_no_offline_only_feature` fails the build
/// if a committed table prices one anyway. A refit that needs one must extend
/// `BatchContext` **and** an online producer first.
pub const OFFLINE_ONLY_FEATURES: &[FeatureId] = &[
    FeatureId::UsedBytecodeBytes,
    FeatureId::UsedBytecodeCount,
    FeatureId::StorageKeyCount,
    FeatureId::InitialHeapWords,
    FeatureId::SystemLogCount,
];

/// A calibration feature vector: model INPUTS only (no measured cycles).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureVector {
    pub counts: BTreeMap<FeatureId, u64>,
}

impl FeatureVector {
    /// Accumulate `n` occurrences of `id`.
    pub fn add(&mut self, id: FeatureId, n: u64) {
        *self.counts.entry(id).or_insert(0) += n;
    }

    /// Current count for `id` (0 if never added).
    pub fn get(&self, id: FeatureId) -> u64 {
        self.counts.get(&id).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_accumulates_and_get_defaults_zero() {
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::StorageRead, 3);
        fv.add(FeatureId::StorageRead, 4);
        assert_eq!(fv.get(FeatureId::StorageRead), 7);
        assert_eq!(fv.get(FeatureId::FarCall), 0);
    }

    #[test]
    fn json_roundtrip_is_stable() {
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::Keccak256Cycles, 42);
        let json = serde_json::to_string(&fv).unwrap();
        let back: FeatureVector = serde_json::from_str(&json).unwrap();
        assert_eq!(fv, back);
        assert!(json.contains("keccak256_cycles"));
    }
}
