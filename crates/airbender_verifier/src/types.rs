use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zksync_contracts::BaseSystemContracts;
use zksync_types::{
    block::L2BlockExecutionData,
    commitment::{BlobHash, PubdataParams},
    witness_block_state::WitnessStorageState,
    L1BatchNumber, L2ChainId, ProtocolVersionId, H256, U256,
};
use zksync_vm_interface::{L1BatchEnv, SystemEnv, TxExecutionMode};

pub use zksync_merkle_tree::{StorageLogMetadata, WitnessInputMerklePaths};

pub(crate) const HASH_LEN: usize = 32;

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

/// The operator-facing shape of the execution environment: [`SystemEnv`] minus
/// the protocol version, which is not an input — `execute` injects
/// `PINNED_PROTOCOL_VERSION` at [`SystemEnvInput::into_system_env`].
///
/// Field order is the bincode wire order. Under `cycle-markers` `version` sits
/// at position 2 as it does in [`SystemEnv`]; the calibration channel still
/// moved overall, since [`VMRunWitnessInputData`]'s mirror is gone in every
/// flavour, so a calibration guest must be rebuilt alongside its host.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemEnvInput {
    pub zk_porter_available: bool,
    /// Calibration-only: each corpus batch replays under its own semantics.
    /// Structurally absent from the production build — not just skipped.
    #[cfg(feature = "cycle-markers")]
    pub version: ProtocolVersionId,
    pub base_system_smart_contracts: BaseSystemContracts,
    pub bootloader_gas_limit: u32,
    pub execution_mode: TxExecutionMode,
    pub default_validation_computational_gas_limit: u32,
    pub chain_id: L2ChainId,
}

impl SystemEnvInput {
    /// The single place a version enters the STF. `execute` passes
    /// `PINNED_PROTOCOL_VERSION`; the calibration flavour passes the batch's
    /// own.
    pub fn into_system_env(self, version: ProtocolVersionId) -> SystemEnv {
        SystemEnv {
            zk_porter_available: self.zk_porter_available,
            version,
            base_system_smart_contracts: self.base_system_smart_contracts,
            bootloader_gas_limit: self.bootloader_gas_limit,
            execution_mode: self.execution_mode,
            default_validation_computational_gas_limit: self
                .default_validation_computational_gas_limit,
            chain_id: self.chain_id,
        }
    }
}

// Mirrors `SystemEnv`'s manual impl: print contract hashes, not the bytecodes.
impl std::fmt::Debug for SystemEnvInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SystemEnvInput");
        s.field("zk_porter_available", &self.zk_porter_available);
        #[cfg(feature = "cycle-markers")]
        s.field("version", &self.version);
        s.field(
            "base_system_smart_contracts",
            &self.base_system_smart_contracts.hashes(),
        )
        .field("gas_limit", &self.bootloader_gas_limit)
        .field(
            "default_validation_computational_gas_limit",
            &self.default_validation_computational_gas_limit,
        )
        .field("execution_mode", &self.execution_mode)
        .field("chain_id", &self.chain_id)
        .finish()
    }
}

/// VM execution witness used by verifier input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VMRunWitnessInputData {
    pub l1_batch_number: L1BatchNumber,
    pub used_bytecodes: HashMap<U256, Vec<[u8; HASH_LEN]>>,
    pub initial_heap_content: Vec<(usize, U256)>,
    pub bootloader_code: Vec<[u8; HASH_LEN]>,
    pub default_account_code_hash: U256,
    /// `None` on an EVM-emulator-disabled chain, which `verify_commitment`
    /// supports.
    ///
    /// NOT `skip_serializing_if`: bincode reads a fixed field count, so
    /// `default` never fires and an omitted field left the `None` payload
    /// undecodable. `default` stays for the JSON path; `Some` encodes
    /// identically either way, so the corpus is unaffected.
    #[serde(default)]
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

/// Verifier input payload — the guest-facing shape, bincode-encoded on the
/// host↔guest channel.
///
/// The wire cannot express a protocol version: [`SystemEnvInput`] has no
/// version field and [`VMRunWitnessInputData`]'s mirror is deleted. `execute`
/// injects `PINNED_PROTOCOL_VERSION` — the STF chooses, not the operator. The
/// era export and on-disk corpus keep the historical labels host-side
/// (`zksync_cli_utils::labeled`); the only minor on the wire is an upgrade tx's
/// `upgrade_id` (batch content). Under `cycle-markers` the wire also carries
/// `system_env.version`, so the calibration guest replays each batch under its
/// own semantics.
///
/// `commitment_input` carries the L1 chain context the verifier needs to
/// produce a `proof_public_input` bound to L1 settlement; `Verify::verify`
/// requires it to be `Some`. The field is `Option<...>` so VM-only flows
/// (e.g., the serialization roundtrip test) can construct an input without
/// fabricating commitment data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AirbenderVerifierInput {
    pub vm_run_data: VMRunWitnessInputData,
    pub merkle_paths: WitnessInputMerklePaths,
    pub l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    pub l1_batch_env: L1BatchEnv,
    pub system_env: SystemEnvInput,
    pub pubdata_params: PubdataParams,
    pub commitment_input: Option<CommitmentInput>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vm_run_data(evm_emulator_code_hash: Option<U256>) -> VMRunWitnessInputData {
        VMRunWitnessInputData {
            l1_batch_number: Default::default(),
            used_bytecodes: Default::default(),
            initial_heap_content: vec![],
            bootloader_code: vec![],
            default_account_code_hash: Default::default(),
            evm_emulator_code_hash,
            storage_refunds: vec![],
            pubdata_costs: vec![],
            witness_block_state: Default::default(),
        }
    }

    /// Regression: `skip_serializing_if` left the `None` payload one field
    /// short and undecodable. The `Some` arm pins that dropping it kept the
    /// corpus wire byte-identical.
    #[test]
    fn evm_emulator_none_round_trips() {
        let cfg = bincode::config::standard();
        for value in [Some(U256::zero()), None] {
            let input = sample_vm_run_data(value);
            let bytes = bincode::serde::encode_to_vec(&input, cfg).expect("encode");
            let (decoded, read) =
                bincode::serde::decode_from_slice::<VMRunWitnessInputData, _>(&bytes, cfg)
                    .unwrap_or_else(|e| panic!("{value:?} must decode: {e}"));
            assert_eq!(read, bytes.len(), "trailing bytes for {value:?}");
            assert_eq!(decoded, input, "round trip differs for {value:?}");
        }
    }

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

        // These siblings are not empty-subtree constants, so nothing is stripped:
        // each path is stored exactly as pushed, independently of the others. (The
        // old delta form stored `[256, 1, 1, …]` here — every later entry's size
        // was a function of entry 0.)
        for log in &witness.merkle_paths {
            assert_eq!(log.merkle_paths.len(), 256);
        }

        let logs_from_witness: Vec<_> = witness.into_merkle_paths().collect();
        assert_eq!(logs_from_witness, logs);
    }
}
