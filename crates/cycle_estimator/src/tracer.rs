use std::sync::{Arc, Mutex};

use zksync_vm2::interface::{
    CycleStats, GlobalStateInterface, Opcode, OpcodeType, ShouldStop, Tracer,
};

use crate::features::{FeatureId, FeatureVector};

/// Passive vm2 tracer that counts calibration features into a shared recorder.
///
/// Modeled on `crates/multivm/src/versions/vm_fast/tracers/circuits.rs`, but
/// emits RAW counts (the per-feature cycle weights are learned by the offline
/// fit, never baked in here). Every hook only observes — it returns
/// [`ShouldStop::Continue`] and mutates no VM state — so a batch executed with
/// this tracer runs identically to the proved guest.
///
/// Cloning shares one recorder: clone the tracer per transaction (matching how
/// the fast VM's tuple `TracerDispatcher` is fed) and all counts accumulate into
/// the same [`FeatureVector`].
#[derive(Debug, Clone, Default)]
pub struct CycleFeatureTracer {
    recorder: Arc<Mutex<FeatureVector>>,
}

impl CycleFeatureTracer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle to the shared recorder, for callers that want to read counts
    /// after driving the VM through a clone of this tracer.
    pub fn recorder(&self) -> Arc<Mutex<FeatureVector>> {
        Arc::clone(&self.recorder)
    }

    /// Snapshot the accumulated feature counts.
    pub fn snapshot(&self) -> FeatureVector {
        self.recorder.lock().unwrap().clone()
    }

    fn bump(&self, id: FeatureId, n: u64) {
        self.recorder.lock().unwrap().add(id, n);
    }
}

impl Tracer for CycleFeatureTracer {
    fn after_instruction<OP: OpcodeType, S: GlobalStateInterface>(
        &mut self,
        _state: &mut S,
    ) -> ShouldStop {
        // Opcode → feature-family mapping mirrors `circuits.rs`'s bucketing so
        // the offline categories line up with the sequencer's existing model.
        let id = match OP::VALUE {
            Opcode::Nop
            | Opcode::Add
            | Opcode::Sub
            | Opcode::Mul
            | Opcode::Div
            | Opcode::Jump
            | Opcode::Xor
            | Opcode::And
            | Opcode::Or
            | Opcode::ShiftLeft
            | Opcode::ShiftRight
            | Opcode::RotateLeft
            | Opcode::RotateRight
            | Opcode::PointerAdd
            | Opcode::PointerSub
            | Opcode::PointerPack
            | Opcode::PointerShrink => FeatureId::RichAddressingOp,
            Opcode::This
            | Opcode::Caller
            | Opcode::CodeAddress
            | Opcode::ContextMeta
            | Opcode::ErgsLeft
            | Opcode::SP
            | Opcode::ContextU128
            | Opcode::SetContextU128
            | Opcode::AuxMutating0
            | Opcode::IncrementTxNumber
            | Opcode::Ret(_) => FeatureId::AverageOp,
            Opcode::NearCall => {
                self.bump(FeatureId::NearCallCount, 1);
                FeatureId::AverageOp
            }
            Opcode::StorageRead => FeatureId::StorageRead,
            Opcode::StorageWrite => FeatureId::StorageWrite,
            Opcode::TransientStorageRead => FeatureId::TransientStorageRead,
            Opcode::TransientStorageWrite => FeatureId::TransientStorageWrite,
            Opcode::L2ToL1Message | Opcode::Event => FeatureId::Event,
            Opcode::PrecompileCall => FeatureId::PrecompileCall,
            Opcode::Decommit => FeatureId::Decommit,
            Opcode::FarCall(_) => FeatureId::FarCall,
            Opcode::AuxHeapWrite | Opcode::HeapWrite | Opcode::StaticMemoryWrite => {
                FeatureId::UmaWrite
            }
            Opcode::AuxHeapRead
            | Opcode::HeapRead
            | Opcode::PointerRead
            | Opcode::StaticMemoryRead => FeatureId::UmaRead,
        };
        self.bump(id, 1);
        ShouldStop::Continue
    }

    fn on_extra_prover_cycles(&mut self, stats: CycleStats) {
        // Same categories as `circuits.rs::on_extra_prover_cycles`; the payload
        // is the operation's complexity (hashing rounds / circuit cycles), which
        // we keep as the crypto size feature rather than a plain call count.
        match stats {
            CycleStats::Keccak256(c) => self.bump(FeatureId::Keccak256Cycles, c as u64),
            CycleStats::Sha256(c) => self.bump(FeatureId::Sha256Cycles, c as u64),
            CycleStats::EcRecover(c) => self.bump(FeatureId::EcRecoverCycles, c as u64),
            CycleStats::Secp256r1Verify(c) => self.bump(FeatureId::Secp256r1VerifyCycles, c as u64),
            CycleStats::Decommit(c) => self.bump(FeatureId::DecommitCycles, c as u64),
            CycleStats::StorageRead => self.bump(FeatureId::StorageApplication, 1),
            CycleStats::StorageWrite => self.bump(FeatureId::StorageApplication, 2),
            CycleStats::EcAdd(c) => self.bump(FeatureId::EcAddCycles, c as u64),
            CycleStats::ModExp(c) => self.bump(FeatureId::ModExpCycles, c as u64),
            CycleStats::EcMul(c) => self.bump(FeatureId::EcMulCycles, c as u64),
            CycleStats::EcPairing(c) => self.bump(FeatureId::EcPairingCycles, c as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_one_recorder() {
        let t1 = CycleFeatureTracer::new();
        let t2 = t1.clone();
        t1.bump(FeatureId::FarCall, 2);
        t2.bump(FeatureId::FarCall, 3);
        assert_eq!(t1.snapshot().get(FeatureId::FarCall), 5);
    }
}
