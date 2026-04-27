//! Tee verifier
//!
//! Verifies that a L1Batch has the expected root hash after executing the VM
//! and verifying all the accessed memory slots by their merkle path, and
//! computes the Era VM batch commitment together with the proof public input
//! hash that the Airbender → FFLONK wrapper feeds to L1 settlement.

pub mod commitment;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod types;

use anyhow::{bail, Context, Result};
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_merkle_tree::{
    BlockOutputWithProofs, TreeInstruction, TreeLogEntry, TreeLogEntryWithProof, ValueHash,
};
use zksync_multivm::{
    interface::{
        storage::{StorageSnapshot, StorageView},
        FinishedL1Batch, L2BlockEnv, VmInterfaceExt, VmInterfaceHistoryEnabled,
    },
    is_supported_by_fast_vm,
    pubdata_builders::pubdata_params_to_builder,
    utils::get_used_bootloader_memory_bytes,
    FastVmInstance,
};
use zksync_types::{
    block::L2BlockExecutionData,
    bytecode::BytecodeHash,
    commitment::{serialize_commitments, PubdataParams},
    u256_to_h256,
    web3::keccak256,
    writes::StateDiffRecord,
    L1BatchNumber, ProtocolVersionId, StorageLog, StorageValue, Transaction, H256, U256,
};

use crate::commitment::{expand_bootloader_heap, CommitmentData, ZK_SYNC_BYTES_PER_BLOB};
use crate::types::{
    CommitmentInput, StorageLogMetadata, V1TeeVerifierInput, V2TeeVerifierInput,
    WitnessInputMerklePaths,
};

/// A structure to hold the result of verification.
pub struct VerificationResult {
    /// The root hash of the batch that was verified.
    pub value_hash: ValueHash,
    /// The batch number that was verified.
    pub batch_number: L1BatchNumber,
    /// The proof public input preimage `keccak256(prev || curr)`, packed as 8 big-endian
    /// u32 words. See [`commitment::BatchCommitmentOutput::proof_public_input`] for the
    /// L1 `PUBLIC_INPUT_SHIFT` contract and the wrapper's responsibility.
    pub proof_public_input: [u32; 8],
    /// The computed batch commitment.
    pub commitment: H256,
    /// The new Merkle tree enumeration index after all insertions.
    pub new_enumeration_index: u64,
    /// Sub-hashes for debugging / cross-checking against the sequencer.
    pub pass_through_data_hash: H256,
    pub metadata_hash: H256,
    pub auxiliary_output_hash: H256,
    /// Intermediate hashes for cross-checking.
    pub system_logs_hash: H256,
    pub state_diff_hash: H256,
    pub bootloader_heap_hash: H256,
    /// Raw data for independent cross-checking by tests.
    pub system_logs: Vec<zksync_types::l2_to_l1_log::SystemL2ToL1Log>,
    pub state_diffs: Vec<zksync_types::writes::StateDiffRecord>,
    /// Pubdata produced by VM execution, for blob hash computation.
    pub pubdata_input: Option<Vec<u8>>,
}

/// A trait for the computations that can be verified in TEE.
pub trait Verify {
    fn verify(self) -> anyhow::Result<VerificationResult>;
}

impl Verify for V2TeeVerifierInput {
    /// Run the VM, verify the new state root, and compute the batch commitment.
    fn verify(self) -> anyhow::Result<VerificationResult> {
        let state = execute(self.v1)?;
        verify_commitment(state, self.commitment_input)
    }
}

/// Run the VM, verify the new state root via merkle proofs, and return the
/// intermediate state needed to compute the batch commitment.
///
/// This does not run any commitment-input-dependent checks (prev binding,
/// blob verification). Test code can call this to obtain pubdata, then build
/// a `CommitmentInput` and pass the state to [`verify_commitment`].
pub fn execute(input: V1TeeVerifierInput) -> anyhow::Result<VmExecutionState> {
    anyhow::ensure!(
        is_supported_by_fast_vm(input.system_env.version),
        "Protocol version {:?} is not supported by FastVM tee verifier",
        input.system_env.version
    );

    execute_inner(input, |l1_batch_env, system_env, storage_view| {
        FastVerifierVm::fast(l1_batch_env, system_env, storage_view)
    })
}

type VerifierStorage = StorageSnapshot;
type VerifierStorageView = StorageView<VerifierStorage>;
type FastVerifierVm = FastVmInstance<VerifierStorage>;

/// Intermediate state after VM execution and merkle proof verification,
/// before any commitment-input-dependent checks.
pub struct VmExecutionState {
    batch_number: zksync_types::L1BatchNumber,
    old_root_hash: H256,
    prev_enumeration_index: u64,
    new_root_hash: H256,
    new_enumeration_index: u64,
    system_logs: Vec<zksync_types::l2_to_l1_log::SystemL2ToL1Log>,
    state_diffs: Vec<StateDiffRecord>,
    pubdata_input: Option<Vec<u8>>,
    expanded_heap: Vec<u8>,
    zk_porter_available: bool,
    bootloader_code_hash: H256,
    default_aa_code_hash: H256,
    evm_emulator_code_hash: H256,
}

impl VmExecutionState {
    /// Pubdata produced by the VM. Empty when the VM did not emit a pubdata
    /// input (e.g. pre-gateway protocols).
    pub fn pubdata(&self) -> &[u8] {
        self.pubdata_input.as_deref().unwrap_or(&[])
    }
}

fn execute_inner<VM, F>(input: V1TeeVerifierInput, make_vm: F) -> anyhow::Result<VmExecutionState>
where
    VM: VmInterfaceHistoryEnabled + VmInterfaceExt,
    F: FnOnce(
        zksync_vm_interface::L1BatchEnv,
        zksync_vm_interface::SystemEnv,
        zksync_vm_interface::storage::StoragePtr<VerifierStorageView>,
    ) -> VM,
{
    let old_root_hash = input
        .l1_batch_env
        .previous_batch_hash
        .context("previous_batch_hash is missing — genesis batches are not supported")?;
    let enumeration_index = input.merkle_paths.next_enumeration_index();
    let batch_number = input.l1_batch_env.number;
    let protocol_version = input.system_env.version;
    let zk_porter_available = input.system_env.zk_porter_available;
    let bootloader_code_hash = input.system_env.base_system_smart_contracts.bootloader.hash;
    let default_aa_code_hash = u256_to_h256(input.vm_run_data.default_account_code_hash);
    let evm_emulator_code_hash = input
        .vm_run_data
        .evm_emulator_code_hash
        .map(u256_to_h256)
        .unwrap_or_default();

    // Map hashed storage key → enumeration index, sourced from the Merkle witness.
    // Needed so `FinishedL1Batch.state_diffs` carries correct enum indices for the
    // state-diff hash. A key that appears in multiple merkle-path entries (read+write
    // in the same batch) must agree on its enum index — disagreement means a malformed
    // witness.
    let mut enum_index_map: std::collections::HashMap<H256, u64> = std::collections::HashMap::new();
    for log in input
        .merkle_paths
        .merkle_paths
        .iter()
        .filter(|log| log.leaf_enumeration_index > 0)
    {
        let mut key_bytes = [0u8; 32];
        log.leaf_hashed_key.to_little_endian(&mut key_bytes);
        let hashed = H256(key_bytes);
        if let Some(&existing) = enum_index_map.get(&hashed) {
            anyhow::ensure!(
                existing == log.leaf_enumeration_index,
                "merkle_paths witness has inconsistent enumeration indices for \
                 leaf_hashed_key {hashed:?}: {existing} vs {}",
                log.leaf_enumeration_index,
            );
        } else {
            enum_index_map.insert(hashed, log.leaf_enumeration_index);
        }
    }

    let read_storage_ops = input
        .vm_run_data
        .witness_block_state
        .read_storage_key
        .into_iter();

    let initial_writes_ops = input
        .vm_run_data
        .witness_block_state
        .is_write_initial
        .into_iter();

    // Reads of never-written zero slots must be encoded as `None`, not `Some((0, 0))`,
    // or `StorageSnapshot::new` will violate its own invariants and bloat with phantoms.
    let storage =
        read_storage_ops
            .map(|(key, value)| {
                let hashed = key.hashed_key();
                let enum_idx = enum_index_map.get(&hashed).copied().unwrap_or(0);
                let entry = if enum_idx == 0 && value == H256::zero() {
                    None
                } else {
                    Some((value, enum_idx))
                };
                (hashed, entry)
            })
            .chain(initial_writes_ops.filter_map(|(key, initial_write)| {
                initial_write.then_some((key.hashed_key(), None))
            }))
            .collect();

    // Verify the bootloader bytecode matches its claimed hash.
    // The bootloader is loaded separately from used_bytecodes and orchestrates
    // all transaction execution — a tampered bootloader would compromise everything.
    {
        let bootloader_flat: Vec<u8> = input
            .vm_run_data
            .bootloader_code
            .iter()
            .flat_map(|word| word.as_slice())
            .copied()
            .collect();
        let computed = BytecodeHash::for_bytecode(&bootloader_flat);
        anyhow::ensure!(
            u256_to_h256(computed.value_u256()) == bootloader_code_hash,
            "bootloader bytecode hash mismatch: claimed {bootloader_code_hash:?}, computed {:?}",
            u256_to_h256(computed.value_u256()),
        );
    }

    // Verify all other bytecode hashes and build factory deps in a single pass.
    let factory_deps = input
        .vm_run_data
        .used_bytecodes
        .into_iter()
        .map(|(claimed_hash, words)| {
            let flat_bytes = words.into_flattened();
            verify_bytecode_hash(claimed_hash, &flat_bytes)?;
            Ok((u256_to_h256(claimed_hash), flat_bytes))
        })
        .collect::<anyhow::Result<std::collections::HashMap<H256, Vec<u8>>>>()?;

    // Verify that default_aa and evm_emulator code hashes correspond to verified
    // bytecodes. These hashes go into metadataHash (and thus the batch commitment).
    // In Boojum, the code decommitter circuit verifies them when decommitted.
    // Here, we check they exist in the already-verified factory_deps map.
    anyhow::ensure!(
        factory_deps.contains_key(&default_aa_code_hash),
        "default_aa_code_hash {default_aa_code_hash:?} not found in verified factory deps — \
         the bytecode must be included in used_bytecodes to verify its hash"
    );
    if evm_emulator_code_hash != H256::zero() {
        anyhow::ensure!(
            factory_deps.contains_key(&evm_emulator_code_hash),
            "evm_emulator_code_hash {evm_emulator_code_hash:?} not found in verified factory deps — \
             the bytecode must be included in used_bytecodes to verify its hash"
        );
    }

    let storage_snapshot = StorageSnapshot::new(storage, factory_deps);
    let storage_view = StorageView::new(storage_snapshot).to_rc_ptr();
    let vm = make_vm(input.l1_batch_env, input.system_env, storage_view);

    let mut vm_out = execute_vm(
        input.l2_blocks_execution_data,
        vm,
        input.pubdata_params,
        protocol_version,
    )?;

    // Take fields out of vm_out before generate_tree_instructions consumes it.
    // The tree-instructions path only reads final_execution_state.deduplicated_storage_logs.
    let system_logs = std::mem::take(&mut vm_out.final_execution_state.system_logs);
    let pubdata_input = vm_out.pubdata_input.take();
    let state_diffs = vm_out
        .state_diffs
        .take()
        .context("state_diffs missing from VM output — required for commitment")?;

    let block_output_with_proofs = get_bowp(input.merkle_paths)?;

    let instructions: Vec<TreeInstruction> =
        generate_tree_instructions(enumeration_index, &block_output_with_proofs, vm_out)?;

    block_output_with_proofs
        .verify_proofs(&Blake2Hasher, old_root_hash, &instructions)
        .context("Failed to verify_proofs {l1_batch_number} correctly!")?;

    let new_root_hash = block_output_with_proofs.root_hash().unwrap();
    // The new enumeration index is the old index + number of newly inserted leaves.
    // Only TreeLogEntry::Inserted entries increment the index — Updated entries reuse
    // their existing leaf_index and don't allocate a new slot.
    let num_insertions = block_output_with_proofs
        .logs
        .iter()
        .filter(|log| matches!(log.base, TreeLogEntry::Inserted))
        .count() as u64;
    let new_enumeration_index = enumeration_index + num_insertions;

    // Expand bootloader heap; needed by commitment computation downstream.
    let bootloader_memory_size = get_used_bootloader_memory_bytes(protocol_version.into());
    let expanded_heap = expand_bootloader_heap(
        &input.vm_run_data.initial_heap_content,
        bootloader_memory_size,
    );

    Ok(VmExecutionState {
        batch_number,
        old_root_hash,
        prev_enumeration_index: enumeration_index,
        new_root_hash,
        new_enumeration_index,
        system_logs,
        state_diffs,
        pubdata_input,
        expanded_heap,
        zk_porter_available,
        bootloader_code_hash,
        default_aa_code_hash,
        evm_emulator_code_hash,
    })
}

/// Run commitment-input-dependent checks (zk_porter sanity, prev-batch binding,
/// blob verification) against the post-execution state, then compute the batch
/// commitment and the proof public input.
pub fn verify_commitment(
    state: VmExecutionState,
    commitment_input: CommitmentInput,
) -> anyhow::Result<VerificationResult> {
    anyhow::ensure!(
        state.zk_porter_available == zksync_system_constants::ZKPORTER_IS_AVAILABLE,
        "zk_porter_available from witness ({}) does not match the L1 chain constant ({}) — \
         the resulting commitment would never match L1 settlement",
        state.zk_porter_available,
        zksync_system_constants::ZKPORTER_IS_AVAILABLE,
    );

    // Verify that prev_batch_commitment is consistent with old_root_hash.
    // This binds the previous state root to the previous commitment inside the proof,
    // preventing a malicious operator from supplying a correct prev_batch_commitment
    // with a fake old_root_hash. Matches Boojum's scheduler circuit behavior.
    let prev_passthrough = commitment::compute_pass_through_data_hash(
        state.prev_enumeration_index,
        state.old_root_hash,
    );
    let expected_prev_commitment = commitment::compute_commitment(
        prev_passthrough,
        commitment_input.prev_meta_hash,
        commitment_input.prev_aux_hash,
    );
    anyhow::ensure!(
        expected_prev_commitment == commitment_input.prev_batch_commitment,
        "prev_batch_commitment binding failed: recomputed {expected_prev_commitment:?} \
         != claimed {:?}. old_root_hash={:?}, enumeration_index={}",
        commitment_input.prev_batch_commitment,
        state.old_root_hash,
        state.prev_enumeration_index,
    );

    // Verify blob hashes against pubdata produced by execution.
    // In Boojum, both linear hashes and opening commitments were verified by a
    // dedicated EIP4844Repack sub-circuit inside the scheduler. Post-gateway VMs
    // always populate `pubdata_input`; if it is missing here, treat it as a
    // malformed input.
    let pubdata = state
        .pubdata_input
        .as_deref()
        .context("VM output is missing pubdata_input — required for blob verification")?;
    verify_blob_linear_hashes(pubdata, &commitment_input.blob_linear_hashes)?;
    commitment::verify_blob_opening_commitments(
        pubdata,
        &commitment_input.blob_versioned_hashes,
        &commitment_input.blob_linear_hashes,
        &commitment_input.blob_opening_commitments,
    )?;

    let system_logs_hash = commitment::compute_system_logs_hash(&state.system_logs);
    let state_diff_hash = compute_state_diff_hash(&state.state_diffs);

    let commitment_data = CommitmentData {
        new_state_root: state.new_root_hash,
        new_enumeration_index: state.new_enumeration_index,
        zk_porter_available: state.zk_porter_available,
        bootloader_code_hash: state.bootloader_code_hash,
        default_aa_code_hash: state.default_aa_code_hash,
        evm_emulator_code_hash: state.evm_emulator_code_hash,
        system_logs_hash,
        state_diff_hash,
        bootloader_initial_heap: state.expanded_heap,
        commitment_input,
    };

    let commitment_output = commitment_data.compute()?;

    Ok(VerificationResult {
        value_hash: state.new_root_hash,
        batch_number: state.batch_number,
        proof_public_input: commitment_output.proof_public_input,
        commitment: commitment_output.commitment,
        new_enumeration_index: state.new_enumeration_index,
        pass_through_data_hash: commitment_output.pass_through_data_hash,
        metadata_hash: commitment_output.metadata_hash,
        auxiliary_output_hash: commitment_output.auxiliary_output_hash,
        system_logs_hash: commitment_output.system_logs_hash,
        state_diff_hash: commitment_output.state_diff_hash,
        bootloader_heap_hash: commitment_output.bootloader_heap_hash,
        system_logs: state.system_logs,
        state_diffs: state.state_diffs,
        pubdata_input: state.pubdata_input,
    })
}

/// Compute the state diff hash: `keccak256` of padded-encoded state diff records.
///
/// Each `StateDiffRecord` is serialized to 272 bytes (156 bytes of data, zero-padded
/// to `PADDED_ENCODED_STORAGE_DIFF_LEN_BYTES` for keccak round alignment).
/// All records are concatenated and hashed.
///
/// The storage snapshot must be set up with real enumeration indices (from the Merkle
/// witness) so that `FinishedL1Batch.state_diffs` contains correct values.
///
/// Matches the sequencer's `L1BatchAuxiliaryOutput::state_diff_hash` derivation.
fn compute_state_diff_hash(state_diffs: &[StateDiffRecord]) -> H256 {
    H256(keccak256(&serialize_commitments(state_diffs)))
}

/// Verify that blob linear hashes match the pubdata produced by VM execution.
///
/// Each blob linear hash is `keccak256` of a `ZK_SYNC_BYTES_PER_BLOB`-sized chunk
/// of pubdata (zero-padded if the last chunk is shorter). Unused blob slots must
/// have a zero hash.
///
/// In Boojum, this was verified by a dedicated `EIP4844Repack` sub-circuit inside
/// the scheduler. In Airbender, we verify it directly from the VM's pubdata output.
fn verify_blob_linear_hashes(pubdata: &[u8], claimed_hashes: &[H256]) -> anyhow::Result<()> {
    let num_blobs_from_pubdata = pubdata.len().div_ceil(ZK_SYNC_BYTES_PER_BLOB);

    for (i, claimed) in claimed_hashes.iter().enumerate() {
        if i < num_blobs_from_pubdata {
            let start = i * ZK_SYNC_BYTES_PER_BLOB;
            let end = ((i + 1) * ZK_SYNC_BYTES_PER_BLOB).min(pubdata.len());
            let chunk = &pubdata[start..end];

            let hash = if chunk.len() == ZK_SYNC_BYTES_PER_BLOB {
                H256(keccak256(chunk))
            } else {
                let mut padded = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
                padded[..chunk.len()].copy_from_slice(chunk);
                H256(keccak256(&padded))
            };

            anyhow::ensure!(
                hash == *claimed,
                "blob {i} linear hash mismatch: computed {hash:?}, claimed {claimed:?}"
            );
        } else {
            anyhow::ensure!(
                *claimed == H256::zero(),
                "blob {i} has no pubdata but claimed hash is non-zero: {claimed:?}"
            );
        }
    }
    Ok(())
}

/// Verify that a bytecode's content matches its claimed hash.
///
/// EraVM bytecode hashes are SHA256 with the first 4 bytes overwritten:
/// `[marker, 0, len_hi, len_lo, sha256[4..]]`.
/// We use `BytecodeHash::for_bytecode` for EraVM bytecodes and
/// `BytecodeHash::for_evm_bytecode` for EVM bytecodes (marker-based dispatch).
fn verify_bytecode_hash(claimed_hash: U256, flat_bytecode: &[u8]) -> anyhow::Result<()> {
    let claimed_h256 = u256_to_h256(claimed_hash);
    let marker = claimed_h256.as_bytes()[0];

    let computed = match marker {
        1 => BytecodeHash::for_bytecode(flat_bytecode),
        2 => {
            // EVM bytecode: the length field encodes the raw (unpadded) length.
            let raw_len =
                u16::from_be_bytes([claimed_h256.as_bytes()[2], claimed_h256.as_bytes()[3]])
                    as usize;
            BytecodeHash::for_evm_bytecode(raw_len, flat_bytecode)
        }
        _ => anyhow::bail!("unknown bytecode marker {marker} in hash {claimed_h256:?}"),
    };

    anyhow::ensure!(
        computed.value_u256() == claimed_hash,
        "bytecode hash mismatch: claimed {claimed_h256:?}, computed {:?}",
        u256_to_h256(computed.value_u256()),
    );
    Ok(())
}

/// Sets the initial storage values and returns `BlockOutputWithProofs`
fn get_bowp(witness_input_merkle_paths: WitnessInputMerklePaths) -> Result<BlockOutputWithProofs> {
    let logs_result: Result<_, _> = witness_input_merkle_paths
        .into_merkle_paths()
        .map(
            |StorageLogMetadata {
                 root_hash,
                 merkle_paths,
                 is_write,
                 first_write,
                 leaf_enumeration_index,
                 value_read,
                 leaf_hashed_key: leaf_storage_key,
                 ..
             }| {
                let root_hash = root_hash.into();
                let merkle_path = merkle_paths.into_iter().map(|x| x.into()).collect();
                let base: TreeLogEntry = match (is_write, first_write, leaf_enumeration_index) {
                    (false, _, 0) => TreeLogEntry::ReadMissingKey,
                    (false, false, _) => {
                        // This is a special U256 here, which needs `to_little_endian`
                        let mut hashed_key = [0_u8; 32];
                        leaf_storage_key.to_little_endian(&mut hashed_key);
                        tracing::trace!(
                            "TreeLogEntry::Read {leaf_storage_key:x} = {:x}",
                            StorageValue::from(value_read)
                        );
                        TreeLogEntry::Read {
                            leaf_index: leaf_enumeration_index,
                            value: value_read.into(),
                        }
                    }
                    (false, true, _) => {
                        tracing::error!("get_bowp is_write = false, first_write = true");
                        bail!("get_bowp is_write = false, first_write = true");
                    }
                    (true, true, _) => TreeLogEntry::Inserted,
                    (true, false, _) => {
                        // This is a special U256 here, which needs `to_little_endian`
                        let mut hashed_key = [0_u8; 32];
                        leaf_storage_key.to_little_endian(&mut hashed_key);
                        tracing::trace!(
                            "TreeLogEntry::Updated {leaf_storage_key:x} = {:x}",
                            StorageValue::from(value_read)
                        );
                        TreeLogEntry::Updated {
                            leaf_index: leaf_enumeration_index,
                            previous_value: value_read.into(),
                        }
                    }
                };
                Ok(TreeLogEntryWithProof {
                    base,
                    merkle_path,
                    root_hash,
                })
            },
        )
        .collect();

    let logs: Vec<TreeLogEntryWithProof> = logs_result?;

    Ok(BlockOutputWithProofs {
        logs,
        leaf_count: 0,
    })
}

/// Executes the VM and returns `FinishedL1Batch` on success.
fn execute_vm<VM>(
    l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    mut vm: VM,
    pubdata_params: PubdataParams,
    protocol_version: ProtocolVersionId,
) -> anyhow::Result<FinishedL1Batch>
where
    VM: VmInterfaceHistoryEnabled + VmInterfaceExt,
{
    let next_l2_blocks_data = l2_blocks_execution_data.iter().skip(1);

    let l2_blocks_data = l2_blocks_execution_data.iter().zip(next_l2_blocks_data);

    for (l2_block_data, next_l2_block_data) in l2_blocks_data {
        tracing::trace!(
            "Started execution of l2_block: {:?}, executing {:?} transactions",
            l2_block_data.number,
            l2_block_data.txs.len(),
        );
        for tx in &l2_block_data.txs {
            tracing::trace!("Started execution of tx: {tx:?}");
            execute_tx(tx, &mut vm)
                .context("failed to execute transaction in TeeVerifierInputProducer")?;
            tracing::trace!("Finished execution of tx: {tx:?}");
        }

        tracing::trace!("finished l2_block {l2_block_data:?}");
        tracing::trace!("about to vm.start_new_l2_block {next_l2_block_data:?}");

        vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(next_l2_block_data));

        tracing::trace!("Finished execution of l2_block: {:?}", l2_block_data.number);
    }

    tracing::trace!("about to vm.finish_batch()");

    Ok(vm.finish_batch(pubdata_params_to_builder(pubdata_params, protocol_version)))
}

/// Map `LogQuery` and `TreeLogEntry` to a `TreeInstruction`
fn map_log_tree(
    storage_log: &StorageLog,
    tree_log_entry: &TreeLogEntry,
    idx: &mut u64,
) -> anyhow::Result<TreeInstruction> {
    let key = storage_log.key.hashed_key_u256();
    let tree_instruction = match (storage_log.is_write(), *tree_log_entry) {
        (true, TreeLogEntry::Updated { leaf_index, .. }) => {
            TreeInstruction::write(key, leaf_index, H256(storage_log.value.into()))
        }
        (true, TreeLogEntry::Inserted) => {
            let leaf_index = *idx;
            *idx += 1;
            TreeInstruction::write(key, leaf_index, H256(storage_log.value.into()))
        }
        (false, TreeLogEntry::Read { value, .. }) => {
            if storage_log.value != value {
                tracing::error!(
                    ?storage_log,
                    ?tree_log_entry,
                    "Failed to map LogQuery to TreeInstruction: read value {:#?} != {:#?}",
                    storage_log.value,
                    value
                );
                anyhow::bail!("Failed to map LogQuery to TreeInstruction");
            }
            TreeInstruction::Read(key)
        }
        (false, TreeLogEntry::ReadMissingKey) => TreeInstruction::Read(key),
        (true, TreeLogEntry::Read { .. })
        | (true, TreeLogEntry::ReadMissingKey)
        | (false, TreeLogEntry::Inserted)
        | (false, TreeLogEntry::Updated { .. }) => {
            tracing::error!(
                ?storage_log,
                ?tree_log_entry,
                "Failed to map LogQuery to TreeInstruction"
            );
            anyhow::bail!("Failed to map LogQuery to TreeInstruction");
        }
    };

    Ok(tree_instruction)
}

/// Generates the `TreeInstruction`s from the VM executions.
fn generate_tree_instructions(
    mut idx: u64,
    bowp: &BlockOutputWithProofs,
    vm_out: FinishedL1Batch,
) -> anyhow::Result<Vec<TreeInstruction>> {
    let vm_logs = vm_out.final_execution_state.deduplicated_storage_logs;
    assert_eq!(
        vm_logs.len(),
        bowp.logs.len(),
        "VM deduplicated storage logs count mismatch with merkle proofs: vm_logs={}, merkle_logs={}",
        vm_logs.len(),
        bowp.logs.len()
    );

    vm_logs
        .into_iter()
        .zip(bowp.logs.iter())
        .map(|(log_query, tree_log_entry)| map_log_tree(&log_query, &tree_log_entry.base, &mut idx))
        .collect::<Result<Vec<_>, _>>()
}

fn execute_tx<VM>(tx: &Transaction, vm: &mut VM) -> anyhow::Result<()>
where
    VM: VmInterfaceHistoryEnabled + VmInterfaceExt,
{
    // Attempt to run VM with bytecode compression on.
    vm.make_snapshot();
    if vm
        .execute_transaction_with_bytecode_compression(tx.clone(), true)
        .0
        .is_ok()
    {
        vm.pop_snapshot_no_rollback();
        return Ok(());
    }

    // If failed with bytecode compression, attempt to run without bytecode compression.
    vm.rollback_to_the_latest_snapshot();
    if vm
        .execute_transaction_with_bytecode_compression(tx.clone(), false)
        .0
        .is_err()
    {
        anyhow::bail!("compression can't fail if we don't apply it");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zksync_contracts::{BaseSystemContracts, SystemContractCode};
    use zksync_multivm::interface::{L1BatchEnv, SystemEnv, TxExecutionMode};

    use super::*;
    use crate::types::{TeeVerifierInput, VMRunWitnessInputData};

    #[test]
    fn test_verify_bytecode_hash_valid() {
        let bytecode = vec![0u8; 32];
        let hash = BytecodeHash::for_bytecode(&bytecode);
        verify_bytecode_hash(hash.value_u256(), &bytecode).unwrap();
    }

    #[test]
    fn test_verify_bytecode_hash_tampered() {
        let bytecode = vec![0u8; 32];
        let hash = BytecodeHash::for_bytecode(&bytecode);
        let mut tampered = bytecode.clone();
        tampered[0] = 0xFF;
        let err = verify_bytecode_hash(hash.value_u256(), &tampered).unwrap_err();
        assert!(
            err.to_string().contains("bytecode hash mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_bytecode_hash_unknown_marker() {
        let bytecode = vec![0u8; 32];
        // Construct a hash with marker = 0xFF (unknown).
        let mut fake_hash = [0u8; 32];
        fake_hash[0] = 0xFF;
        let err = verify_bytecode_hash(U256::from_big_endian(&fake_hash), &bytecode).unwrap_err();
        assert!(
            err.to_string().contains("unknown bytecode marker"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_blob_hashes_valid() {
        // One blob worth of pubdata.
        let pubdata = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let expected_hash = H256(keccak256(&pubdata));
        let mut claimed = vec![H256::zero(); 16];
        claimed[0] = expected_hash;
        verify_blob_linear_hashes(&pubdata, &claimed).unwrap();
    }

    #[test]
    fn test_verify_blob_hashes_partial_blob() {
        // Less than one blob — gets zero-padded.
        let pubdata = vec![0xCD_u8; 1000];
        let mut padded = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
        padded[..1000].copy_from_slice(&pubdata);
        let expected_hash = H256(keccak256(&padded));
        let mut claimed = vec![H256::zero(); 16];
        claimed[0] = expected_hash;
        verify_blob_linear_hashes(&pubdata, &claimed).unwrap();
    }

    #[test]
    fn test_verify_blob_hashes_tampered() {
        let pubdata = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let mut claimed = vec![H256::zero(); 16];
        claimed[0] = H256([0xFF; 32]);
        let err = verify_blob_linear_hashes(&pubdata, &claimed).unwrap_err();
        assert!(
            err.to_string().contains("linear hash mismatch"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_verify_blob_hashes_extra_blob() {
        let pubdata = vec![];
        let mut claimed = vec![H256::zero(); 16];
        claimed[0] = H256([0xFF; 32]);
        let err = verify_blob_linear_hashes(&pubdata, &claimed).unwrap_err();
        assert!(err.to_string().contains("no pubdata"), "unexpected: {err}");
    }

    #[test]
    fn test_verify_blob_opening_commitment() {
        use crate::commitment::{verify_blob_opening_commitments, ZK_SYNC_BYTES_PER_BLOB};
        use ark_bls12_381::Fr as Bls12_381Fr;
        use ark_ff::{BigInteger, PrimeField, Zero};

        // Create deterministic blob data.
        let mut blob_data = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
        for (i, b) in blob_data.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        // Compute linear_hash = keccak256(blob_data).
        let linear_hash = H256(keccak256(&blob_data));

        // Create a fake versioned_hash (would normally come from KZG commitment).
        let mut versioned_hash = H256(keccak256(b"test_versioned_hash"));
        versioned_hash.0[0] = 0x01; // EIP-4844 version byte

        // Step 1: Parse polynomial (same logic as verify_blob_opening_commitments).
        let poly: Vec<Bls12_381Fr> = blob_data
            .chunks(31)
            .rev()
            .map(|chunk| {
                let mut buf = [0u8; 32];
                buf[..chunk.len()].copy_from_slice(chunk);
                Bls12_381Fr::from_le_bytes_mod_order(&buf)
            })
            .collect();

        // Step 2: Compute evaluation_point.
        let eval_point_hash = {
            let mut preimage = Vec::new();
            preimage.extend_from_slice(linear_hash.as_bytes());
            preimage.extend_from_slice(versioned_hash.as_bytes());
            keccak256(&preimage)
        };
        let mut eval_point_bytes = [0u8; 32];
        eval_point_bytes[16..32].copy_from_slice(&eval_point_hash[16..32]);
        let evaluation_point = Bls12_381Fr::from_be_bytes_mod_order(&eval_point_bytes);

        // Step 3: Evaluate polynomial (Horner's rule).
        let mut opening_value = Bls12_381Fr::zero();
        for coeff in poly.iter().rev() {
            opening_value *= evaluation_point;
            opening_value += coeff;
        }

        // Step 4: Serialize opening value.
        let opening_value_bytes = {
            let repr = opening_value.into_bigint();
            let be = repr.to_bytes_be();
            let mut buf = [0u8; 32];
            for (j, b) in be.iter().enumerate() {
                if j < 32 {
                    buf[j] = *b;
                }
            }
            buf
        };

        // Step 5: Compute output_hash.
        let output_hash = {
            let mut preimage = Vec::new();
            preimage.extend_from_slice(versioned_hash.as_bytes());
            preimage.extend_from_slice(&eval_point_hash[16..32]);
            preimage.extend_from_slice(&opening_value_bytes);
            H256(keccak256(&preimage))
        };

        // Now verify — should pass.
        let mut linear_hashes = vec![H256::zero(); 16];
        linear_hashes[0] = linear_hash;
        let mut versioned_hashes = vec![H256::zero(); 16];
        versioned_hashes[0] = versioned_hash;
        let mut output_hashes = vec![H256::zero(); 16];
        output_hashes[0] = output_hash;

        verify_blob_opening_commitments(
            &blob_data,
            &versioned_hashes,
            &linear_hashes,
            &output_hashes,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_blob_opening_commitment_tampered() {
        use crate::commitment::{verify_blob_opening_commitments, ZK_SYNC_BYTES_PER_BLOB};

        let blob_data = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let linear_hash = H256(keccak256(&blob_data));
        let versioned_hash = H256([0x01; 32]);

        let mut linear_hashes = vec![H256::zero(); 16];
        linear_hashes[0] = linear_hash;
        let mut versioned_hashes = vec![H256::zero(); 16];
        versioned_hashes[0] = versioned_hash;
        let mut output_hashes = vec![H256::zero(); 16];
        output_hashes[0] = H256([0xFF; 32]); // wrong hash

        let err = verify_blob_opening_commitments(
            &blob_data,
            &versioned_hashes,
            &linear_hashes,
            &output_hashes,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("opening commitment mismatch"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_v1_serialization() {
        let tvi = V1TeeVerifierInput::new(
            VMRunWitnessInputData {
                l1_batch_number: Default::default(),
                used_bytecodes: Default::default(),
                initial_heap_content: vec![],
                protocol_version: Default::default(),
                bootloader_code: vec![],
                default_account_code_hash: Default::default(),
                evm_emulator_code_hash: Some(Default::default()),
                storage_refunds: vec![],
                pubdata_costs: vec![],
                witness_block_state: Default::default(),
            },
            WitnessInputMerklePaths::new(0),
            vec![],
            L1BatchEnv {
                previous_batch_hash: Some(H256([1; 32])),
                number: Default::default(),
                timestamp: 0,
                fee_input: Default::default(),
                fee_account: Default::default(),
                enforced_base_fee: None,
                first_l2_block: L2BlockEnv {
                    number: 0,
                    timestamp: 0,
                    prev_block_hash: H256([1; 32]),
                    max_virtual_blocks_to_create: 0,
                    interop_roots: vec![],
                },
            },
            SystemEnv {
                zk_porter_available: false,
                version: Default::default(),
                base_system_smart_contracts: BaseSystemContracts {
                    bootloader: SystemContractCode {
                        code: vec![1; 32],
                        hash: H256([1; 32]),
                    },
                    default_aa: SystemContractCode {
                        code: vec![1; 32],
                        hash: H256([1; 32]),
                    },
                    evm_emulator: None,
                },
                bootloader_gas_limit: 0,
                execution_mode: TxExecutionMode::VerifyExecute,
                default_validation_computational_gas_limit: 0,
                chain_id: Default::default(),
            },
            Default::default(),
        );
        let tvi = TeeVerifierInput::new(tvi);
        let serialized =
            bincode_v1::serialize(&tvi).expect("Failed to serialize TeeVerifierInput.");
        let deserialized: TeeVerifierInput =
            bincode_v1::deserialize(&serialized).expect("Failed to deserialize TeeVerifierInput.");

        assert_eq!(tvi, deserialized);
    }

    #[test]
    fn test_prev_commitment_binding_recomputation() {
        use crate::commitment::{
            compute_commitment, compute_pass_through_data_hash, CommitmentData,
        };
        use crate::types::CommitmentInput;

        // Simulate a "previous batch" by computing its commitment.
        let prev_state_root = H256([0xAA; 32]);
        let prev_enum_index: u64 = 42;
        let prev_meta_hash = H256([0xBB; 32]);
        let prev_aux_hash = H256([0xCC; 32]);

        // Compute prev_passthrough and commitment using the shared functions
        // (the same ones used by the binding check in verify_with_vm).
        let prev_passthrough = compute_pass_through_data_hash(prev_enum_index, prev_state_root);
        let prev_commitment = compute_commitment(prev_passthrough, prev_meta_hash, prev_aux_hash);

        // Verify CommitmentData::compute() produces the same passthrough hash.
        let commitment_data = CommitmentData {
            new_state_root: prev_state_root,
            new_enumeration_index: prev_enum_index,
            zk_porter_available: false,
            bootloader_code_hash: H256::zero(),
            default_aa_code_hash: H256::zero(),
            evm_emulator_code_hash: H256::zero(),
            system_logs_hash: commitment::compute_system_logs_hash(&[]),
            state_diff_hash: H256::zero(),
            bootloader_initial_heap: vec![],
            commitment_input: CommitmentInput {
                prev_batch_commitment: H256::zero(),
                prev_meta_hash: H256::zero(),
                prev_aux_hash: H256::zero(),
                blob_linear_hashes: vec![H256::zero(); 16],
                blob_versioned_hashes: vec![H256::zero(); 16],
                blob_opening_commitments: vec![H256::zero(); 16],
            },
        };
        let output = commitment_data.compute().unwrap();

        // The passthrough hash must match — both paths use the same shared function.
        assert_eq!(
            output.pass_through_data_hash, prev_passthrough,
            "passthrough hash mismatch between CommitmentData and shared function"
        );

        // The full commitment must match when using the same meta + aux hashes.
        let reconstructed =
            compute_commitment(output.pass_through_data_hash, prev_meta_hash, prev_aux_hash);
        assert_eq!(
            reconstructed, prev_commitment,
            "reconstructed commitment doesn't match — encoding mismatch"
        );
    }

    /// Exercises the binding logic with non-zero `prev_meta_hash` / `prev_aux_hash`:
    /// a claimed `prev_batch_commitment` recomputed from consistent inputs must
    /// match, and tampering with any input must cause a mismatch (which
    /// `verify_with_vm` turns into an error via `anyhow::ensure!`).
    #[test]
    fn test_prev_commitment_binding_rejects_mismatch() {
        use crate::commitment::{compute_commitment, compute_pass_through_data_hash};

        let old_root_hash = H256([0xAA; 32]);
        let enumeration_index: u64 = 4242;
        let prev_meta_hash = H256([0xBB; 32]);
        let prev_aux_hash = H256([0xCC; 32]);

        let prev_passthrough = compute_pass_through_data_hash(enumeration_index, old_root_hash);
        let valid_prev = compute_commitment(prev_passthrough, prev_meta_hash, prev_aux_hash);

        // Sanity: passing the matching triple reconstructs the same commitment.
        let recomputed_match = compute_commitment(prev_passthrough, prev_meta_hash, prev_aux_hash);
        assert_eq!(recomputed_match, valid_prev);

        // Tampering the meta hash must produce a different commitment.
        let recomputed_bad_meta =
            compute_commitment(prev_passthrough, H256([0xDE; 32]), prev_aux_hash);
        assert_ne!(recomputed_bad_meta, valid_prev);

        // Tampering the aux hash must produce a different commitment.
        let recomputed_bad_aux =
            compute_commitment(prev_passthrough, prev_meta_hash, H256([0xAD; 32]));
        assert_ne!(recomputed_bad_aux, valid_prev);

        // Tampering the enumeration index must produce a different passthrough,
        // which yields a different commitment.
        let bad_passthrough = compute_pass_through_data_hash(enumeration_index + 1, old_root_hash);
        let recomputed_bad_enum =
            compute_commitment(bad_passthrough, prev_meta_hash, prev_aux_hash);
        assert_ne!(recomputed_bad_enum, valid_prev);

        // Tampering the old root hash likewise.
        let bad_passthrough = compute_pass_through_data_hash(enumeration_index, H256([0xEE; 32]));
        let recomputed_bad_root =
            compute_commitment(bad_passthrough, prev_meta_hash, prev_aux_hash);
        assert_ne!(recomputed_bad_root, valid_prev);
    }
}
