use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zksync_types::{
    block::L2BlockExecutionData, commitment::PubdataParams,
    witness_block_state::WitnessStorageState, L1BatchNumber, ProtocolVersionId, H256, U256,
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
    /// EIP-4844 blob linear hashes for the auxiliary output.
    /// Length must equal `TOTAL_BLOBS_IN_COMMITMENT`; unused slots are `H256::zero()`.
    pub blob_linear_hashes: Vec<H256>,
    /// EIP-4844 versioned hashes for each blob (from the L1 blob transaction).
    /// Used to verify blob opening commitments.
    pub blob_versioned_hashes: Vec<H256>,
    /// Blob opening commitment hashes: `keccak256(versioned_hash || opening_point || opening_value)`.
    /// Verified by evaluating the blob polynomial at the opening point.
    pub blob_opening_commitments: Vec<H256>,
}

impl Default for CommitmentInput {
    fn default() -> Self {
        Self {
            prev_batch_commitment: H256::zero(),
            prev_meta_hash: H256::zero(),
            prev_aux_hash: H256::zero(),
            blob_linear_hashes: vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT],
            blob_versioned_hashes: vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT],
            blob_opening_commitments: vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT],
        }
    }
}

/// Version 1 of the data used as input for the TEE verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V1TeeVerifierInput {
    pub vm_run_data: VMRunWitnessInputData,
    pub merkle_paths: WitnessInputMerklePaths,
    pub l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    pub l1_batch_env: L1BatchEnv,
    pub system_env: SystemEnv,
    pub pubdata_params: PubdataParams,
}

impl V1TeeVerifierInput {
    pub fn new(
        vm_run_data: VMRunWitnessInputData,
        merkle_paths: WitnessInputMerklePaths,
        l2_blocks_execution_data: Vec<L2BlockExecutionData>,
        l1_batch_env: L1BatchEnv,
        system_env: SystemEnv,
        pubdata_params: PubdataParams,
    ) -> Self {
        Self {
            vm_run_data,
            merkle_paths,
            l2_blocks_execution_data,
            l1_batch_env,
            system_env,
            pubdata_params,
        }
    }
}

/// Version 2: V1 + CommitmentInput for Airbender settlement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2TeeVerifierInput {
    pub v1: V1TeeVerifierInput,
    pub commitment_input: CommitmentInput,
}

/// Data used as input for the TEE verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum TeeVerifierInput {
    /// `V0` suppresses warning about irrefutable `let...else` pattern.
    V0,
    V1(V1TeeVerifierInput),
    V2(V2TeeVerifierInput),
}

impl TeeVerifierInput {
    pub fn new(input: V1TeeVerifierInput) -> Self {
        Self::V1(input)
    }
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
