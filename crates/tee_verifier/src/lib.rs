//! Tee verifier
//!
//! Verifies that a L1Batch has the expected root hash after
//! executing the VM and verifying all the accessed memory slots by their
//! merkle path.
//!
//! When used with Airbender, the verifier also computes the Era VM batch
//! commitment and returns a proof public input hash for L1 settlement.

pub mod commitment;
pub mod types;

use anyhow::{bail, Context, Result};
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_merkle_tree::{
    BlockOutputWithProofs, TreeInstruction, TreeLogEntry, TreeLogEntryWithProof, ValueHash,
};
use zksync_multivm::{
    interface::{
        storage::{StorageSnapshot, StorageView},
        FinishedL1Batch, L2BlockEnv, VmFactory, VmInterfaceExt, VmInterfaceHistoryEnabled,
    },
    is_supported_by_fast_vm,
    pubdata_builders::pubdata_params_to_builder,
    utils::get_used_bootloader_memory_bytes,
    FastVmInstance, LegacyVmInstance,
};
use zksync_types::{
    block::L2BlockExecutionData, bytecode::BytecodeHash, commitment::PubdataParams, u256_to_h256,
    web3::keccak256, writes::StateDiffRecord, L1BatchNumber, ProtocolVersionId, StorageLog,
    StorageValue, Transaction, H256, U256,
};

use crate::commitment::{expand_bootloader_heap, CommitmentData, ZK_SYNC_BYTES_PER_BLOB};
use crate::types::{StorageLogMetadata, V1TeeVerifierInput, WitnessInputMerklePaths};

/// A structure to hold the result of verification.
pub struct VerificationResult {
    /// The root hash of the batch that was verified.
    pub value_hash: ValueHash,
    /// The batch number that was verified.
    pub batch_number: L1BatchNumber,
    /// The proof public input hash for L1 settlement: `keccak256(prev || curr)`.
    /// L1 applies `>> 32` before verifying against the proof.
    pub proof_public_input: [u32; 8],
    /// The computed batch commitment.
    pub commitment: H256,
}

/// A trait for the computations that can be verified in TEE.
pub trait Verify {
    fn verify(self) -> anyhow::Result<VerificationResult>;

    fn verify_legacy(self) -> anyhow::Result<VerificationResult>;
}

use crate::types::CommitmentInput;

/// Verify execution and compute the batch commitment.
/// `commitment_input` is provided separately from `V1TeeVerifierInput` because the
/// latter's bincode layout is frozen (old test batches must still deserialize).
pub fn verify_and_commit(
    input: V1TeeVerifierInput,
    commitment_input: CommitmentInput,
) -> anyhow::Result<VerificationResult> {
    assert!(
        is_supported_by_fast_vm(input.system_env.version),
        "Protocol version {:?} is not supported by FastVM tee verifier",
        input.system_env.version
    );

    verify_with_vm(input, commitment_input, |l1_batch_env, system_env, storage_view| {
        FastVerifierVm::fast(l1_batch_env, system_env, storage_view)
    })
}

type VerifierStorage = StorageSnapshot;
type VerifierStorageView = StorageView<VerifierStorage>;
type FastVerifierVm = FastVmInstance<VerifierStorage>;
type LegacyVerifierVm =
    LegacyVmInstance<VerifierStorage, zksync_multivm::vm_latest::HistoryEnabled>;

fn verify_with_vm<VM, F>(
    input: V1TeeVerifierInput,
    commitment_input: CommitmentInput,
    make_vm: F,
) -> anyhow::Result<VerificationResult>
where
    VM: VmInterfaceHistoryEnabled + VmInterfaceExt,
    F: FnOnce(
        zksync_vm_interface::L1BatchEnv,
        zksync_vm_interface::SystemEnv,
        zksync_vm_interface::storage::StoragePtr<VerifierStorageView>,
    ) -> VM,
{
    let old_root_hash = input.l1_batch_env.previous_batch_hash.unwrap();
    let enumeration_index = input.merkle_paths.next_enumeration_index();
    let batch_number = input.l1_batch_env.number;
    let initial_heap_content = input.vm_run_data.initial_heap_content.clone();
    let protocol_version = input.system_env.version;
    let zk_porter_available = input.system_env.zk_porter_available;
    let bootloader_code_hash = input.system_env.base_system_smart_contracts.bootloader.hash;
    let default_aa_code_hash = u256_to_h256(input.vm_run_data.default_account_code_hash);
    let evm_emulator_code_hash = input
        .vm_run_data
        .evm_emulator_code_hash
        .map(u256_to_h256)
        .unwrap_or_default();

    // Build a mapping from hashed storage key → real enumeration index from the
    // Merkle proof witness. This is needed so that FinishedL1Batch.state_diffs
    // contains correct enumeration indices for state diff hash computation.
    // The leaf_hashed_key in StorageLogMetadata is a U256 (little-endian convention),
    // which we convert to H256 to match the StorageSnapshot key format.
    let enum_index_map: std::collections::HashMap<H256, u64> = input
        .merkle_paths
        .merkle_paths
        .iter()
        .filter(|log| log.leaf_enumeration_index > 0)
        .map(|log| {
            let mut key_bytes = [0u8; 32];
            log.leaf_hashed_key.to_little_endian(&mut key_bytes);
            (H256(key_bytes), log.leaf_enumeration_index)
        })
        .collect();

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

    // Build the storage snapshot with real enumeration indices from the Merkle witness.
    // Slots with a known enumeration index get Some((value, index)); slots that are
    // initial writes (no prior index) get None.
    let storage = read_storage_ops
        .map(|(key, value)| {
            let hashed = key.hashed_key();
            let enum_idx = enum_index_map.get(&hashed).copied().unwrap_or(0);
            if enum_idx > 0 {
                (hashed, Some((value, enum_idx)))
            } else {
                // Key exists in reads but has no enumeration index — treat as
                // a slot without a prior write (value is the default or was
                // never indexed).
                (hashed, Some((value, 0)))
            }
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
        .collect::<anyhow::Result<_>>()?;

    let storage_snapshot = StorageSnapshot::new(storage, factory_deps);
    let storage_view = StorageView::new(storage_snapshot).to_rc_ptr();
    let vm = make_vm(input.l1_batch_env, input.system_env.clone(), storage_view);

    let vm_out = execute_vm(
        input.l2_blocks_execution_data,
        vm,
        input.pubdata_params,
        input.system_env.version,
    )?;

    // Extract system logs and state diffs before consuming vm_out for tree instructions.
    let system_logs = vm_out.final_execution_state.system_logs.clone();
    let state_diffs = vm_out
        .state_diffs
        .clone()
        .context("state_diffs missing from VM output — required for commitment")?;
    let state_diff_hash = compute_state_diff_hash(&state_diffs);

    // Verify blob hashes against pubdata produced by execution.
    // In Boojum, both linear hashes and opening commitments were verified by a
    // dedicated EIP4844Repack sub-circuit inside the scheduler.
    // Skip if no blob hashes were provided (CommitmentInput::default() has all zeros).
    let has_blob_hashes = commitment_input
        .blob_linear_hashes
        .iter()
        .any(|h| *h != H256::zero());
    if has_blob_hashes {
        if let Some(pubdata) = &vm_out.pubdata_input {
            verify_blob_linear_hashes(pubdata, &commitment_input.blob_linear_hashes);
            commitment::verify_blob_opening_commitments(
                pubdata,
                &commitment_input.blob_versioned_hashes,
                &commitment_input.blob_linear_hashes,
                &commitment_input.blob_opening_commitments,
            );
        }
    }

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

    // Expand bootloader heap and compute the batch commitment.
    let bootloader_memory_size =
        get_used_bootloader_memory_bytes(protocol_version.into());
    let expanded_heap = expand_bootloader_heap(&initial_heap_content, bootloader_memory_size);

    let commitment_data = CommitmentData {
        new_state_root: new_root_hash,
        new_enumeration_index,
        zk_porter_available,
        bootloader_code_hash,
        default_aa_code_hash,
        evm_emulator_code_hash,
        system_logs,
        state_diff_hash,
        bootloader_initial_heap: expanded_heap,
        commitment_input,
    };

    let commitment_output = commitment_data.compute()?;

    Ok(VerificationResult {
        value_hash: new_root_hash,
        batch_number,
        proof_public_input: commitment_output.proof_public_input,
        commitment: commitment_output.commitment,
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
/// Matches `zksync-era/core/lib/types/src/commitment/mod.rs:424-425`.
fn compute_state_diff_hash(state_diffs: &[StateDiffRecord]) -> H256 {
    use zksync_types::{commitment::serialize_commitments, web3::keccak256};
    let packed = serialize_commitments(state_diffs);
    H256(keccak256(&packed))
}

/// Verify that blob linear hashes match the pubdata produced by VM execution.
///
/// Each blob linear hash is `keccak256` of a `ZK_SYNC_BYTES_PER_BLOB`-sized chunk
/// of pubdata (zero-padded if the last chunk is shorter). Unused blob slots must
/// have a zero hash.
///
/// In Boojum, this was verified by a dedicated `EIP4844Repack` sub-circuit inside
/// the scheduler. In Airbender, we verify it directly from the VM's pubdata output.
fn verify_blob_linear_hashes(pubdata: &[u8], claimed_hashes: &[H256]) {
    // Compute expected hashes from pubdata chunks.
    let num_blobs_from_pubdata = pubdata.len().div_ceil(ZK_SYNC_BYTES_PER_BLOB);

    for (i, claimed) in claimed_hashes.iter().enumerate() {
        if i < num_blobs_from_pubdata {
            // This blob has data — compute keccak256 of the (possibly padded) chunk.
            let start = i * ZK_SYNC_BYTES_PER_BLOB;
            let end = ((i + 1) * ZK_SYNC_BYTES_PER_BLOB).min(pubdata.len());
            let chunk = &pubdata[start..end];

            let hash = if chunk.len() == ZK_SYNC_BYTES_PER_BLOB {
                H256(keccak256(chunk))
            } else {
                // Last chunk: zero-pad to full blob size.
                let mut padded = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
                padded[..chunk.len()].copy_from_slice(chunk);
                H256(keccak256(&padded))
            };

            assert_eq!(
                hash, *claimed,
                "blob linear hash mismatch for blob {i}: computed {hash:?}, claimed {claimed:?}"
            );
        } else {
            // No data for this blob slot — hash must be zero.
            assert_eq!(
                *claimed,
                H256::zero(),
                "blob {i} has no pubdata but claimed hash is non-zero: {claimed:?}"
            );
        }
    }
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
            let raw_len = u16::from_be_bytes([
                claimed_h256.as_bytes()[2],
                claimed_h256.as_bytes()[3],
            ]) as usize;
            BytecodeHash::for_evm_bytecode(raw_len, flat_bytecode)
        }
        _ => anyhow::bail!(
            "unknown bytecode marker {marker} in hash {claimed_h256:?}"
        ),
    };

    anyhow::ensure!(
        computed.value_u256() == claimed_hash,
        "bytecode hash mismatch: claimed {claimed_h256:?}, computed {:?}",
        u256_to_h256(computed.value_u256()),
    );
    Ok(())
}

impl Verify for V1TeeVerifierInput {
    /// Verify that the L1Batch produces the expected root hash
    /// by executing the VM and verifying the merkle paths of all
    /// touch storage slots.
    ///
    /// # Errors
    ///
    /// Returns a verbose error of the failure, because any error is
    /// not actionable.
    fn verify(self) -> anyhow::Result<VerificationResult> {
        assert!(
            is_supported_by_fast_vm(self.system_env.version),
            "Protocol version {:?} is not supported by FastVM tee verifier",
            self.system_env.version
        );

        verify_with_vm(self, CommitmentInput::default(), |l1_batch_env, system_env, storage_view| {
            FastVerifierVm::fast(l1_batch_env, system_env, storage_view)
        })
    }

    fn verify_legacy(self) -> anyhow::Result<VerificationResult> {
        verify_with_vm(self, CommitmentInput::default(), |l1_batch_env, system_env, storage_view| {
            <LegacyVerifierVm as VmFactory<VerifierStorageView>>::new(
                l1_batch_env,
                system_env,
                storage_view,
            )
        })
    }
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
    fn test_verify_blob_hashes_valid() {
        // One blob worth of pubdata.
        let pubdata = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let expected_hash = H256(keccak256(&pubdata));
        let mut claimed = vec![H256::zero(); 16];
        claimed[0] = expected_hash;
        verify_blob_linear_hashes(&pubdata, &claimed);
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
        verify_blob_linear_hashes(&pubdata, &claimed);
    }

    #[test]
    #[should_panic(expected = "blob linear hash mismatch")]
    fn test_verify_blob_hashes_tampered() {
        let pubdata = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let mut claimed = vec![H256::zero(); 16];
        claimed[0] = H256([0xFF; 32]); // wrong hash
        verify_blob_linear_hashes(&pubdata, &claimed);
    }

    #[test]
    #[should_panic(expected = "no pubdata but claimed hash is non-zero")]
    fn test_verify_blob_hashes_extra_blob() {
        let pubdata = vec![]; // no data
        let mut claimed = vec![H256::zero(); 16];
        claimed[0] = H256([0xFF; 32]); // but claims a blob exists
        verify_blob_linear_hashes(&pubdata, &claimed);
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
                if j < 32 { buf[j] = *b; }
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
        );
    }

    #[test]
    #[should_panic(expected = "blob 0 opening commitment mismatch")]
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

        verify_blob_opening_commitments(
            &blob_data,
            &versioned_hashes,
            &linear_hashes,
            &output_hashes,
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
}
