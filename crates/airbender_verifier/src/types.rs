use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zksync_types::{
    block::L2BlockExecutionData,
    commitment::{BlobHash, PubdataParams},
    witness_block_state::WitnessStorageState,
    L1BatchNumber, ProtocolVersionId, H256, U256,
};
use zksync_vm_interface::{L1BatchEnv, SystemEnv};

pub use zksync_merkle_tree::{StorageLogMetadata, WitnessInputMerklePaths};

const HASH_LEN: usize = 32;

/// Number of blob hash/commitment pairs in the auxiliary output.
///
/// Must stay in sync with the L1 source of truth: `IExecutor.sol`'s
/// `TOTAL_BLOBS_IN_COMMITMENT`. `test_total_blobs_in_commitment_matches_l1`
/// pins the value.
pub const TOTAL_BLOBS_IN_COMMITMENT: usize = 16;

#[cfg(test)]
mod blob_constant_tests {
    /// Change detector: if L1's `TOTAL_BLOBS_IN_COMMITMENT` ever changes, this constant
    /// must be updated in lockstep with the contract and the sequencer.
    #[test]
    fn test_total_blobs_in_commitment_matches_l1() {
        assert_eq!(super::TOTAL_BLOBS_IN_COMMITMENT, 16);
    }
}

/// VM execution witness used by verifier input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VMRunWitnessInputData {
    pub l1_batch_number: L1BatchNumber,
    pub used_bytecodes: HashMap<U256, Vec<[u8; HASH_LEN]>>,
    pub initial_heap_content: Vec<(usize, U256)>,
    pub protocol_version: ProtocolVersionId,
    pub bootloader_code: Vec<[u8; HASH_LEN]>,
    pub default_account_code_hash: U256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm_emulator_code_hash: Option<U256>,
    pub storage_refunds: Vec<u32>,
    pub pubdata_costs: Vec<i32>,
    pub witness_block_state: WitnessStorageState,
}

/// Data required for L1 batch commitment computation that is not produced by
/// VM execution and must be provided externally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitmentInput {
    /// The `storedBatchInfo.commitment` of the previous batch (stored on L1).
    /// Used to construct the proof public input: `keccak256(prev || curr) >> 32`.
    /// If the operator provides the wrong value, the proof will not match L1's
    /// reconstruction and will be rejected.
    pub prev_batch_commitment: H256,
    /// The metadata hash of the previous batch. Together with `prev_aux_hash`,
    /// used to verify that `prev_batch_commitment` is consistent with the
    /// previous state root (old_root_hash).
    pub prev_meta_hash: H256,
    /// The auxiliary output hash of the previous batch.
    pub prev_aux_hash: H256,
    /// `(linear_hash, opening_commitment)` pairs that go into the auxiliary
    /// output. Length must equal `TOTAL_BLOBS_IN_COMMITMENT`; unused slots are
    /// `BlobHash::default()`.
    pub blob_hashes: Vec<BlobHash>,
    /// EIP-4844 versioned hashes for each blob (from the L1 blob transaction).
    /// Length must equal `TOTAL_BLOBS_IN_COMMITMENT`. Used to derive opening
    /// points; not part of the auxiliary-output bytes.
    pub blob_versioned_hashes: Vec<H256>,
}

impl Default for CommitmentInput {
    fn default() -> Self {
        Self {
            prev_batch_commitment: H256::zero(),
            prev_meta_hash: H256::zero(),
            prev_aux_hash: H256::zero(),
            blob_hashes: vec![BlobHash::default(); TOTAL_BLOBS_IN_COMMITMENT],
            blob_versioned_hashes: vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT],
        }
    }
}

/// Versioned wire format for verifier input.
///
/// The bincode payload begins with a variant tag so the on-disk corpus and
/// the host↔guest channel can evolve without rewriting the format each time
/// the payload changes.
///
/// `V0` is a placeholder with no payload. It pins later discriminants so
/// removing or shuffling variants does not silently change the encoding of
/// every existing dump.
///
/// - `V1` matches the pre-v31 bincode shape and exists solely for backward
///   compatibility with the on-disk corpus in
///   `testdata/era_mainnet_batches/`. Decoded V1 inputs are upgraded to V2
///   via `V1AirbenderVerifierInput::into_v2` before verification.
/// - `V2` carries the post-v31 wire format used by the prover server and
///   by all newly produced inputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum AirbenderVerifierInput {
    V0,
    V1(V1AirbenderVerifierInput),
    V2(V2AirbenderVerifierInput),
}

impl AirbenderVerifierInput {
    /// Extract a V2 payload, upgrading V1 in place. Errors on the reserved
    /// `V0` marker.
    pub fn into_v2(self) -> anyhow::Result<V2AirbenderVerifierInput> {
        match self {
            AirbenderVerifierInput::V0 => {
                anyhow::bail!("AirbenderVerifierInput::V0 has no payload — expected V1 or V2")
            }
            AirbenderVerifierInput::V1(v1) => Ok(v1.into_v2()),
            AirbenderVerifierInput::V2(v2) => Ok(v2),
        }
    }
}

/// Pre-v31 verifier input payload, kept for backward compatibility with the
/// on-disk corpus. Field types snapshot the wire shape that existed before
/// the v31 refactor of `L1BatchEnv` and `PubdataParams` — see
/// [`crate::v1_compat`]. New inputs should be encoded as `V2`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V1AirbenderVerifierInput {
    pub vm_run_data: VMRunWitnessInputData,
    pub merkle_paths: WitnessInputMerklePaths,
    pub l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    pub l1_batch_env: crate::v1_compat::L1BatchEnvV1,
    pub system_env: SystemEnv,
    pub pubdata_params: crate::v1_compat::PubdataParamsV1,
    pub commitment_input: Option<CommitmentInput>,
}

impl V1AirbenderVerifierInput {
    /// Upgrade to the post-v31 payload shape, filling the new `interop_fee` and
    /// `settlement_layer` fields with the implicit values a pre-v31 chain
    /// would have carried (see [`crate::v1_compat`]).
    pub fn into_v2(self) -> V2AirbenderVerifierInput {
        V2AirbenderVerifierInput {
            vm_run_data: self.vm_run_data,
            merkle_paths: self.merkle_paths,
            l2_blocks_execution_data: self.l2_blocks_execution_data,
            l1_batch_env: self.l1_batch_env.upgrade(),
            system_env: self.system_env,
            pubdata_params: self.pubdata_params.upgrade(),
            commitment_input: self.commitment_input,
        }
    }
}

/// Post-v31 verifier input payload.
///
/// `commitment_input` carries the L1 chain context the verifier needs to
/// produce a `proof_public_input` bound to L1 settlement; `Verify::verify`
/// requires it to be `Some`. The field is `Option<...>` so VM-only flows
/// (e.g., the serialization roundtrip test) can construct an input without
/// fabricating commitment data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2AirbenderVerifierInput {
    pub vm_run_data: VMRunWitnessInputData,
    pub merkle_paths: WitnessInputMerklePaths,
    pub l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    pub l1_batch_env: L1BatchEnv,
    pub system_env: SystemEnv,
    pub pubdata_params: PubdataParams,
    pub commitment_input: Option<CommitmentInput>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_merkle_paths_roundtrip() {
        let zero_hash = [0_u8; HASH_LEN];
        let logs = (0_u64..10).map(|i| {
            let mut merkle_paths = vec![zero_hash; 255];
            merkle_paths.push([i as u8; HASH_LEN]);
            StorageLogMetadata {
                root_hash: zero_hash,
                is_write: i.is_multiple_of(2),
                first_write: i.is_multiple_of(3),
                merkle_paths,
                leaf_hashed_key: U256::from(i),
                leaf_enumeration_index: i + 1,
                value_written: [i as u8; HASH_LEN],
                value_read: [0; HASH_LEN],
            }
        });
        let logs: Vec<_> = logs.collect();

        let mut witness = WitnessInputMerklePaths::new(4);
        witness.reserve(logs.len());
        for log in &logs {
            witness.push_merkle_path(log.clone());
        }

        for (i, log) in witness.merkle_paths.iter().enumerate() {
            let expected_merkle_path_len = if i == 0 { 256 } else { 1 };
            assert_eq!(log.merkle_paths.len(), expected_merkle_path_len);
        }

        let logs_from_witness: Vec<_> = witness.into_merkle_paths().collect();
        assert_eq!(logs_from_witness, logs);
    }
}
