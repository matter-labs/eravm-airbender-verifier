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
    RichAddressingOp,
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
    // Airbender size features
    HeapGrowthBytes,
    CopyBytes,
    DecommitBytes,
    // batch-level features
    TransactionCount,
    NearCallCount,
    PubdataBytes,
    MerkleLeafCount,
}

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
