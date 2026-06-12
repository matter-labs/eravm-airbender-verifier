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
/// - `V0`: reserved with no payload; pins later discriminants.
/// - `V1`: pre-v31 bincode layout, decoded via [`crate::v1_compat`].
/// - `V2`: canonical post-v31 layout.
///
/// Both `V1` and `V2` carry the same Rust payload; only the on-wire shape
/// differs. [`AirbenderVerifierInput::into_v2`] strips the tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum AirbenderVerifierInput {
    V0,
    V1(#[serde(with = "crate::v1_compat")] V2AirbenderVerifierInput),
    V2(V2AirbenderVerifierInput),
}

impl AirbenderVerifierInput {
    /// Strip the wire-version tag. Errors on the reserved `V0` marker.
    pub fn into_v2(self) -> anyhow::Result<V2AirbenderVerifierInput> {
        match self {
            Self::V0 => anyhow::bail!("AirbenderVerifierInput::V0 has no payload"),
            Self::V1(payload) | Self::V2(payload) => Ok(payload),
        }
    }
}

/// Untagged decoder for the flat JSON payload zksync-era puts on the wire
/// (no version envelope — see `server`'s `fetch_fri_job`).
///
/// Variant order is load-bearing: the strict post-v31 shape is tried first;
/// a payload without `settlement_layer` fails it and falls through to the
/// legacy pre-v31 shape, which [`crate::v1_compat`] upgrades with the
/// implicit pre-v31 defaults. [`FlatAirbenderVerifierInput::into_v2`] then
/// rejects the legacy shape when the payload claims a post-v31 protocol
/// version, so a corrupt v31 payload cannot smuggle in defaulted fields.
///
/// JSON-only: `#[serde(untagged)]` needs a self-describing format and must
/// never sit on the bincode path (the corpus and host↔guest channel keep
/// using the tagged [`AirbenderVerifierInput`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum FlatAirbenderVerifierInput {
    /// Post-v31 flat payload: all v31 fields present (`settlement_layer`
    /// required, `interop_fee` may default).
    V2(V2AirbenderVerifierInput),
    /// Pre-v31 flat payload from a node that does not know the v31 fields.
    Legacy(#[serde(with = "crate::v1_compat")] V2AirbenderVerifierInput),
}

impl FlatAirbenderVerifierInput {
    /// Unwrap to the canonical payload, rejecting a legacy-shaped payload
    /// that carries a post-v31 protocol version: such a sender must provide
    /// `settlement_layer` explicitly instead of inheriting the upgrade
    /// defaults.
    pub fn into_v2(self) -> anyhow::Result<V2AirbenderVerifierInput> {
        match self {
            Self::V2(payload) => Ok(payload),
            Self::Legacy(payload) => {
                let version = payload.system_env.version;
                anyhow::ensure!(
                    version.is_pre_medium_interop(),
                    "flat payload has the pre-v31 wire shape (no `settlement_layer`) \
                     but claims post-v31 protocol version {version:?}"
                );
                Ok(payload)
            }
        }
    }
}

/// Canonical verifier input payload.
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
