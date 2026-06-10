//! Tee verifier
//!
//! Verifies that a L1Batch has the expected root hash after executing the VM
//! and verifying all the accessed memory slots by their merkle path, and
//! computes the Era VM batch commitment together with the proof public input
//! hash that the Airbender → PLONK SNARK wrapper feeds to L1 settlement.

pub mod commitment;
#[doc(hidden)]
pub mod test_utils;
pub mod types;

use anyhow::{bail, Context, Result};
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_crypto_primitives::hasher::Hasher;
use zksync_merkle_tree::{
    BlockOutputWithProofs, TreeInstruction, TreeLogEntry, TreeLogEntryWithProof, ValueHash,
};
use zksync_multivm::{
    interface::{
        storage::{StorageSnapshot, StorageView},
        utils::compress_value_and_index,
        FinishedL1Batch, L2BlockEnv, VmInterfaceExt, VmInterfaceHistoryEnabled,
    },
    is_supported_by_fast_vm,
    pubdata_builders::pubdata_params_to_builder,
    utils::get_used_bootloader_memory_bytes,
    FastVmInstance,
};
use zksync_types::{
    block::L2BlockExecutionData,
    bytecode::{BytecodeHash, BytecodeMarker},
    commitment::{
        serialize_commitments, AuxCommitments, L1BatchAuxiliaryCommonOutput,
        L1BatchAuxiliaryOutput, L1BatchCommitment, L1BatchMetaParameters, L1BatchPassThroughData,
        PubdataParams, RootState,
    },
    u256_to_h256,
    web3::keccak256,
    writes::StateDiffRecord,
    L1BatchNumber, ProtocolVersionId, StorageLog, StorageValue, Transaction, H256, U256,
};

use crate::commitment::expand_bootloader_heap;
use crate::types::{
    AirbenderVerifierInput, CommitmentInput, StorageLogMetadata, V1AirbenderVerifierInput,
    WitnessInputMerklePaths, TOTAL_BLOBS_IN_COMMITMENT,
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

impl Verify for AirbenderVerifierInput {
    /// Unwrap the V1 payload and verify it. The reserved `V0` marker has no
    /// payload, so it produces an error.
    fn verify(self) -> anyhow::Result<VerificationResult> {
        self.into_v1()?.verify()
    }
}

impl Verify for V1AirbenderVerifierInput {
    /// Run the VM, verify the new state root, and compute the batch commitment.
    /// Requires `commitment_input` to be `Some`.
    fn verify(mut self) -> anyhow::Result<VerificationResult> {
        // `execute` ignores `commitment_input`, so move it out first to avoid
        // cloning the blob hash vectors.
        let commitment_input = self.commitment_input.take().context(
            "V1AirbenderVerifierInput::verify requires `commitment_input`; \
             use `execute(...)` directly for VM-only flows",
        )?;
        let state = execute(self)?;
        verify_commitment(state, commitment_input)
    }
}

type VerifierStorage = StorageSnapshot;
type FastVerifierVm = FastVmInstance<VerifierStorage>;

/// Intermediate state after VM execution and merkle proof verification,
/// before any commitment-input-dependent checks.
pub struct VmExecutionState {
    batch_number: zksync_types::L1BatchNumber,
    protocol_version: ProtocolVersionId,
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
    evm_emulator_code_hash: Option<H256>,
}

impl VmExecutionState {
    /// Pubdata produced by the VM. Empty when the VM did not emit a pubdata
    /// input (e.g. pre-gateway protocols).
    pub fn pubdata(&self) -> &[u8] {
        self.pubdata_input.as_deref().unwrap_or(&[])
    }
}

/// Run the VM, verify the new state root via merkle proofs, and return the
/// intermediate state needed to compute the batch commitment.
///
/// Commitment-input-dependent checks (prev binding, blob verification) are
/// not performed here — `input.commitment_input` is ignored. `Verify::verify`
/// runs this and then `verify_commitment` to complete the pipeline.
pub fn execute(input: V1AirbenderVerifierInput) -> anyhow::Result<VmExecutionState> {
    anyhow::ensure!(
        is_supported_by_fast_vm(input.system_env.version),
        "Protocol version {:?} is not supported by FastVM tee verifier",
        input.system_env.version
    );

    let old_root_hash = input
        .l1_batch_env
        .previous_batch_hash
        .context("previous_batch_hash is missing — genesis batches are not supported")?;
    let enumeration_index = input.merkle_paths.next_enumeration_index();
    let batch_number = input.l1_batch_env.number;
    let protocol_version = input.system_env.version;
    let zk_porter_available = input.system_env.zk_porter_available;

    // `vm_run_data` carries operator-supplied copies of values the verifier also
    // derives from the canonical batch/system env. Bind the redundant copies that
    // have an authoritative counterpart so a malicious witness cannot disagree with
    // the environment the VM actually executes against.
    anyhow::ensure!(
        input.vm_run_data.l1_batch_number == batch_number,
        "vm_run_data.l1_batch_number {:?} does not match l1_batch_env.number {batch_number:?}",
        input.vm_run_data.l1_batch_number,
    );
    anyhow::ensure!(
        input.vm_run_data.protocol_version == protocol_version,
        "vm_run_data.protocol_version {:?} does not match system_env.version {protocol_version:?}",
        input.vm_run_data.protocol_version,
    );
    // `vm_run_data.{initial_heap_content, storage_refunds, pubdata_costs}` are
    // populated by the witness generator for the legacy proving path and are not
    // consumed here: the verifier recomputes the bootloader heap it commits to from
    // VM execution and derives refunds/pubdata itself. They are intentionally left
    // unconstrained — real witnesses carry non-empty values for these fields.

    if let Some(first) = input.l2_blocks_execution_data.first() {
        let canonical = &input.l1_batch_env.first_l2_block;
        anyhow::ensure!(
            first.number.0 == canonical.number
                && first.timestamp == canonical.timestamp
                && first.prev_block_hash == canonical.prev_block_hash
                && first.virtual_blocks == canonical.max_virtual_blocks_to_create
                && first.interop_roots == canonical.interop_roots,
            "l2_blocks_execution_data[0] metadata must equal l1_batch_env.first_l2_block",
        );
    }

    // Source all metadata-bound code hashes from system_env.base_system_smart_contracts.
    // That's what the VM actually loads — verifying any other copy (vm_run_data's
    // bootloader_code, default_account_code_hash, evm_emulator_code_hash) leaves a
    // window for a malicious witness to lie: ship a legitimate bytecode in
    // vm_run_data while the VM runs a different one from system_env.
    let base = &input.system_env.base_system_smart_contracts;
    let bootloader_code_hash = base.bootloader.hash;
    let default_aa_code_hash = base.default_aa.hash;
    let evm_emulator_code_hash = base.evm_emulator.as_ref().map(|e| e.hash);

    // Verify the bytecodes the VM consumes match the hashes that flow into
    // metadata_hash (and thus the batch commitment). System contracts are
    // EraVM bytecodes in practice; `verify_bytecode_hash` dispatches on the
    // marker byte so it works uniformly with user contracts in factory_deps.
    let h256_to_u256 = |h: H256| U256::from_big_endian(h.as_bytes());
    verify_bytecode_hash(h256_to_u256(bootloader_code_hash), &base.bootloader.code)
        .context("verifying bootloader bytecode")?;
    verify_bytecode_hash(h256_to_u256(default_aa_code_hash), &base.default_aa.code)
        .context("verifying default_aa bytecode")?;
    if let Some(emu) = &base.evm_emulator {
        verify_bytecode_hash(h256_to_u256(emu.hash), &emu.code)
            .context("verifying evm_emulator bytecode")?;
    }

    // Enforce that vm_run_data's redundant copies match system_env. The
    // verifier doesn't *use* these (system_env is the source of truth) but a
    // mismatch is a malformed witness and we'd rather catch it here than
    // have it propagate silently.
    {
        let vm_run_default_aa = u256_to_h256(input.vm_run_data.default_account_code_hash);
        anyhow::ensure!(
            vm_run_default_aa == default_aa_code_hash,
            "vm_run_data.default_account_code_hash {vm_run_default_aa:?} does not match \
             system_env.base_system_smart_contracts.default_aa.hash {default_aa_code_hash:?}",
        );

        let vm_run_evm_emulator = input.vm_run_data.evm_emulator_code_hash.map(u256_to_h256);
        anyhow::ensure!(
            vm_run_evm_emulator == evm_emulator_code_hash,
            "vm_run_data.evm_emulator_code_hash {vm_run_evm_emulator:?} does not match \
             system_env.base_system_smart_contracts.evm_emulator hash {evm_emulator_code_hash:?}",
        );

        let vm_run_bootloader_bytes: Vec<u8> = input
            .vm_run_data
            .bootloader_code
            .iter()
            .flat_map(|word| word.as_slice())
            .copied()
            .collect();
        anyhow::ensure!(
            vm_run_bootloader_bytes == base.bootloader.code,
            "vm_run_data.bootloader_code does not match system_env.base_system_smart_contracts.bootloader.code \
             (lengths: {} vs {})",
            vm_run_bootloader_bytes.len(),
            base.bootloader.code.len(),
        );
    }

    // Build the VM's storage view directly from the Merkle witness — the only
    // pre-state data bound to `old_root_hash` by `verify_proofs`. The operator's
    // `vm_run_data.witness_block_state` (`read_storage_key` / `is_write_initial`)
    // is intentionally NOT consulted: it has no anchor to the trusted root, so
    // trusting it would let a malicious operator feed the VM a forged value or
    // initialness for any slot.
    let storage = build_storage_view_from_witness(&input.merkle_paths.merkle_paths)?;

    // Verify user-contract bytecodes (factory_deps) match their claimed hashes.
    // VM-internal contracts (bootloader/default_aa/evm_emulator) are loaded from
    // system_env, not from factory_deps, so they're verified separately above.
    let factory_deps = input
        .vm_run_data
        .used_bytecodes
        .into_iter()
        .map(|(claimed_hash, words)| {
            let flat_bytes = words.into_flattened();
            verify_bytecode_hash(claimed_hash, &flat_bytes)?;
            Ok((u256_to_h256(claimed_hash), flat_bytes))
        })
        .collect::<anyhow::Result<std::collections::BTreeMap<H256, Vec<u8>>>>()?;

    let storage_snapshot = StorageSnapshot::new(storage, factory_deps);
    let storage_view = StorageView::new(storage_snapshot).to_rc_ptr();
    let vm = FastVerifierVm::fast(input.l1_batch_env, input.system_env, storage_view);

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
    // The final bootloader memory is what the VM actually executed (initial layout
    // built from `l1_batch_env` + transactions, plus pubdata appended in-flight).
    // Hashing the witness's `vm_run_data.initial_heap_content` would let a malicious
    // proof commit a heap that was never executed; this comes from the VM itself.
    let final_bootloader_memory = vm_out.final_bootloader_memory.take().context(
        "VM output is missing final_bootloader_memory — required for the bootloader heap commitment",
    )?;

    let block_output_with_proofs = get_bowp(input.merkle_paths)?;

    let instructions: Vec<TreeInstruction> =
        generate_tree_instructions(enumeration_index, &block_output_with_proofs, vm_out)?;

    block_output_with_proofs
        .verify_proofs(&Blake2Hasher, old_root_hash, &instructions)
        .with_context(|| format!("Failed to verify_proofs {batch_number} correctly!"))?;

    let new_root_hash = block_output_with_proofs
        .root_hash()
        .context("root_hash unavailable after verify_proofs")?;
    // The new enumeration index is the old index + number of newly inserted leaves.
    // Only TreeLogEntry::Inserted entries increment the index — Updated entries reuse
    // their existing leaf_index and don't allocate a new slot.
    let num_insertions = block_output_with_proofs
        .logs
        .iter()
        .filter(|log| matches!(log.base, TreeLogEntry::Inserted))
        .count() as u64;
    let new_enumeration_index = enumeration_index + num_insertions;

    let bootloader_memory_size = get_used_bootloader_memory_bytes(protocol_version.into());
    let expanded_heap = expand_bootloader_heap(&final_bootloader_memory, bootloader_memory_size);

    Ok(VmExecutionState {
        batch_number,
        protocol_version,
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
    //
    // Slots self-degenerate for non-Rollup DA modes the same way Boojum's
    // `EIP4844Repack` does: when a chain uses Validium / NoDA / external DA,
    // the L2 DA validator emits zero `linear_hash` for every slot.
    // `verify_blob_hashes` skips those slots — both checks trivially pass
    // while the auxiliary-output hash still includes the (zero) blob slots,
    // matching what L1 expects.
    //
    // Post-gateway VMs always populate `pubdata_input`; if it is missing
    // here, treat it as a malformed input.
    let pubdata = state
        .pubdata_input
        .as_deref()
        .context("VM output is missing pubdata_input — required for blob verification")?;
    commitment::verify_blob_hashes(
        pubdata,
        &commitment_input.blob_versioned_hashes,
        &commitment_input.blob_hashes,
    )?;

    let system_logs_hash = H256(keccak256(&serialize_commitments(&state.system_logs)));
    let state_diff_hash = H256(keccak256(&serialize_commitments(&state.state_diffs)));
    let bootloader_heap_hash = Blake2Hasher.hash_bytes(&state.expanded_heap);

    anyhow::ensure!(
        commitment_input.blob_hashes.len() == TOTAL_BLOBS_IN_COMMITMENT,
        "blob_hashes length mismatch: got {}, expected {TOTAL_BLOBS_IN_COMMITMENT}",
        commitment_input.blob_hashes.len()
    );

    // `to_bytes()` for `PostBoojum` ignores `common`, `state_diffs_compressed`,
    // `aggregation_root`, and `local_root`, so we fill them with zeros.
    let commitment = L1BatchCommitment {
        pass_through_data: L1BatchPassThroughData {
            shared_states: vec![
                RootState {
                    last_leaf_index: state.new_enumeration_index,
                    root_hash: state.new_root_hash,
                },
                // zkPorter shared state — reserved, always zero.
                RootState {
                    last_leaf_index: 0,
                    root_hash: H256::zero(),
                },
            ],
        },
        meta_parameters: L1BatchMetaParameters {
            zkporter_is_available: state.zk_porter_available,
            bootloader_code_hash: state.bootloader_code_hash,
            default_aa_code_hash: state.default_aa_code_hash,
            evm_emulator_code_hash: state.evm_emulator_code_hash,
            protocol_version: Some(state.protocol_version),
        },
        auxiliary_output: L1BatchAuxiliaryOutput::PostBoojum {
            common: L1BatchAuxiliaryCommonOutput {
                l2_l1_logs_merkle_root: H256::zero(),
                protocol_version: state.protocol_version,
            },
            system_logs_linear_hash: system_logs_hash,
            state_diffs_compressed: vec![],
            state_diffs_hash: state_diff_hash,
            aux_commitments: AuxCommitments {
                // Post-Boojum commitments do not compute an events queue hash: the slot
                // is still serialized into the auxiliary output hash, but this pipeline
                // pins it to zero. Events are recoverable from the bound transaction
                // heap, system logs, state diffs, and blob hashes, so the legacy
                // commitment is left unused.
                events_queue_commitment: H256::zero(),
                bootloader_initial_content_commitment: bootloader_heap_hash,
            },
            blob_hashes: commitment_input.blob_hashes,
            aggregation_root: H256::zero(),
            local_root: H256::zero(),
        },
    };
    let hashes = commitment
        .hash()
        .expect("L1BatchCommitment with two RootStates always succeeds");
    let proof_public_input = commitment::compute_proof_public_input(
        commitment_input.prev_batch_commitment,
        hashes.commitment,
    );

    Ok(VerificationResult {
        value_hash: state.new_root_hash,
        batch_number: state.batch_number,
        proof_public_input,
        commitment: hashes.commitment,
        new_enumeration_index: state.new_enumeration_index,
        pass_through_data_hash: hashes.pass_through_data,
        metadata_hash: hashes.meta_parameters,
        auxiliary_output_hash: hashes.aux_output,
        system_logs_hash,
        state_diff_hash,
        bootloader_heap_hash,
        system_logs: state.system_logs,
        state_diffs: state.state_diffs,
        pubdata_input: state.pubdata_input,
    })
}

/// Verify that a bytecode's content matches its claimed hash.
///
/// Dispatches on the marker byte via upstream `BytecodeHash::try_from`,
/// which validates the marker and exposes the encoded length so we don't
/// re-parse the hash by hand.
fn verify_bytecode_hash(claimed_hash: U256, flat_bytecode: &[u8]) -> anyhow::Result<()> {
    let claimed_h256 = u256_to_h256(claimed_hash);
    let claimed = BytecodeHash::try_from(claimed_h256)?;

    let computed = match claimed.marker() {
        BytecodeMarker::EraVm => BytecodeHash::for_bytecode(flat_bytecode),
        BytecodeMarker::Evm => {
            BytecodeHash::for_evm_bytecode(claimed.len_in_bytes(), flat_bytecode)
        }
    };

    anyhow::ensure!(
        computed == claimed,
        "bytecode hash mismatch: claimed {claimed_h256:?}, computed {:?}",
        computed.value(),
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
                 // `value_written` is consumed only by the Merkle tree's build path
                 // (`zksync_merkle_tree::domain`), never by the verifier, which derives
                 // the written value from VM execution. Bind it explicitly (instead of
                 // `..`) so this match stays exhaustive: a future field added to
                 // `StorageLogMetadata` won't compile until someone decides whether the
                 // verifier should consume it, rather than being silently ignored.
                 value_written: _,
             }| {
                let root_hash = root_hash.into();
                let merkle_path = merkle_paths.into_iter().map(|x| x.into()).collect();
                let base: TreeLogEntry = match (is_write, first_write, leaf_enumeration_index) {
                    (false, _, 0) => TreeLogEntry::ReadMissingKey,
                    (false, false, _) => {
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
                    (true, false, 0) => {
                        // A repeated write must reference an existing leaf. Index 0
                        // produces an `Updated{leaf_index:0}` that folds identically to
                        // an empty leaf, committing a ghost leaf at index 0.
                        bail!(
                            "get_bowp repeated write to leaf {leaf_storage_key:x} has \
                             enumeration index 0"
                        );
                    }
                    (true, false, _) => {
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
    anyhow::ensure!(
        l2_blocks_execution_data
            .last()
            .is_none_or(|block| block.txs.is_empty()),
        "Last L2 block's txs are never executed; populating them is a malformed witness",
    );

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
                .context("failed to execute transaction in AirbenderVerifierInputProducer")?;
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

/// Build the VM's storage view (hashed key → `Some((value, enum_index))` /
/// `None`) entirely from the Merkle witness, which `verify_proofs` binds to
/// `old_root_hash`. This is the single source of truth for every slot's
/// pre-state: value, enumeration index, and initialness all follow from the
/// witness, so a malicious operator cannot disagree with the proven root.
///
/// Per entry, the proven pre-state is:
/// - empty slot (`ReadMissingKey`: read with index 0; `Inserted`: first write)
///   → zero value, no enumeration index (`None`);
/// - existing slot (`Read` / `Updated`) → `value_read` at `leaf_enumeration_index`.
///
/// A key may appear in several entries (e.g. read + write in one batch); they
/// must agree on the pre-state, otherwise the witness is malformed.
fn build_storage_view_from_witness(
    merkle_paths: &[StorageLogMetadata],
) -> anyhow::Result<std::collections::BTreeMap<H256, Option<(H256, u64)>>> {
    use std::collections::btree_map::Entry;

    let mut storage = std::collections::BTreeMap::new();
    for log in merkle_paths {
        let hashed = H256(log.leaf_hashed_key_array());
        let proves_empty = if log.is_write {
            log.first_write
        } else {
            log.leaf_enumeration_index == 0
        };
        let slot = if proves_empty {
            compress_value_and_index(H256::zero(), None)
        } else {
            compress_value_and_index(H256(log.value_read), Some(log.leaf_enumeration_index))
        };
        match storage.entry(hashed) {
            Entry::Vacant(v) => {
                v.insert(slot);
            }
            Entry::Occupied(existing) => anyhow::ensure!(
                *existing.get() == slot,
                "merkle_paths witness proves inconsistent pre-state for leaf {hashed:?}",
            ),
        }
    }
    Ok(storage)
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
    use airbender_codec::{AirbenderCodec, AirbenderCodecV0};
    use zksync_contracts::{BaseSystemContracts, SystemContractCode};
    use zksync_multivm::interface::{L1BatchEnv, SystemEnv, TxExecutionMode};
    use zksync_types::commitment::BlobHash;

    use super::*;
    use crate::commitment::ZK_SYNC_BYTES_PER_BLOB;
    use crate::types::{AirbenderVerifierInput, V1AirbenderVerifierInput, VMRunWitnessInputData};
    use zksync_types::{AccountTreeId, Address, StorageKey};

    /// A storage key in a distinct contract address, so tests pick unique
    /// hashed keys without collisions.
    fn key(n: u64) -> StorageKey {
        StorageKey::new(
            AccountTreeId::new(Address::from_low_u64_be(n)),
            H256::zero(),
        )
    }

    /// Build a `StorageLogMetadata` witness entry for `key`. `merkle_paths` is
    /// left empty — the derivation under test reads only the flags, enumeration
    /// index, and `value_read`.
    fn meta(
        key: StorageKey,
        is_write: bool,
        first_write: bool,
        leaf_enumeration_index: u64,
        value_read: H256,
    ) -> StorageLogMetadata {
        StorageLogMetadata {
            root_hash: [0u8; 32],
            is_write,
            first_write,
            merkle_paths: vec![],
            leaf_hashed_key: key.hashed_key_u256(),
            leaf_enumeration_index,
            value_written: [0u8; 32],
            value_read: value_read.0,
        }
    }

    #[test]
    fn derives_empty_slot_for_read_missing_key() {
        // ReadMissingKey (read, index 0) ⇒ empty slot, value 0, no enum index —
        // regardless of anything the operator might have claimed. This is what
        // makes a forged `read_storage_key[K]` impossible to honor.
        let k = key(0x1001);
        let storage =
            build_storage_view_from_witness(&[meta(k, false, false, 0, H256::zero())]).unwrap();
        assert_eq!(storage.get(&k.hashed_key()), Some(&None));
    }

    #[test]
    fn derives_existing_slot_for_read() {
        let k = key(0x1002);
        let v = H256::from_low_u64_be(0x11);
        let storage = build_storage_view_from_witness(&[meta(k, false, false, 7, v)]).unwrap();
        assert_eq!(storage.get(&k.hashed_key()), Some(&Some((v, 7))));
    }

    #[test]
    fn derives_empty_slot_for_inserted_write() {
        // Inserted (first write): empty in the old tree, so value 0 / no index —
        // the new enumeration index is *not* exposed as a pre-existing one.
        let k = key(0x1003);
        let storage =
            build_storage_view_from_witness(&[meta(k, true, true, 5, H256::zero())]).unwrap();
        assert_eq!(storage.get(&k.hashed_key()), Some(&None));
    }

    #[test]
    fn derives_existing_slot_for_updated_write() {
        let k = key(0x1004);
        let v_real = H256::from_low_u64_be(0x22);
        let storage = build_storage_view_from_witness(&[meta(k, true, false, 9, v_real)]).unwrap();
        assert_eq!(storage.get(&k.hashed_key()), Some(&Some((v_real, 9))));
    }

    #[test]
    fn rejects_inconsistent_witness_for_same_key() {
        let k = key(0x1005);
        let paths = vec![
            meta(k, false, false, 7, H256::from_low_u64_be(0x1)),
            meta(k, false, false, 7, H256::from_low_u64_be(0x2)),
        ];
        assert!(build_storage_view_from_witness(&paths).is_err());
    }

    #[test]
    fn get_bowp_rejects_repeated_write_with_zero_index() {
        // Ghost leaf: a repeated write (first_write=false) must reference an
        // existing leaf (index > 0). Not subsumed by the storage-view derivation
        // because it corrupts the proof fold, not the VM's view.
        let mut paths = WitnessInputMerklePaths::new(1);
        paths.push_merkle_path(meta(key(0x3001), true, false, 0, H256::zero()));
        assert!(get_bowp(paths).is_err());
    }

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
            err.to_string().contains("unknown bytecode hash marker"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_blob_hashes_linear_tampered() {
        // Wrong linear hash → fails on linear check before commitment check.
        let pubdata = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let mut blob_hashes = vec![BlobHash::default(); 16];
        blob_hashes[0] = BlobHash {
            linear_hash: H256([0xFF; 32]),
            commitment: H256::zero(),
        };
        let versioned_hashes = vec![H256::zero(); 16];
        let err =
            commitment::verify_blob_hashes(&pubdata, &versioned_hashes, &blob_hashes).unwrap_err();
        assert!(
            err.to_string().contains("linear hash mismatch"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_verify_blob_hashes_no_pubdata() {
        // Non-zero claim but no pubdata → fails before hash checks.
        let pubdata = vec![];
        let mut blob_hashes = vec![BlobHash::default(); 16];
        blob_hashes[0] = BlobHash {
            linear_hash: H256([0xFF; 32]),
            commitment: H256::zero(),
        };
        let versioned_hashes = vec![H256::zero(); 16];
        let err =
            commitment::verify_blob_hashes(&pubdata, &versioned_hashes, &blob_hashes).unwrap_err();
        assert!(err.to_string().contains("no pubdata"), "unexpected: {err}");
    }

    #[test]
    fn test_verify_blob_hashes_valid() {
        use crate::commitment::{verify_blob_hashes, ZK_SYNC_BYTES_PER_BLOB};
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

        // Step 1: Parse polynomial (same logic as verify_blob_hashes).
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
        let mut blob_hashes = vec![BlobHash::default(); 16];
        blob_hashes[0] = BlobHash {
            linear_hash,
            commitment: output_hash,
        };
        let mut versioned_hashes = vec![H256::zero(); 16];
        versioned_hashes[0] = versioned_hash;

        verify_blob_hashes(&blob_data, &versioned_hashes, &blob_hashes).unwrap();
    }

    #[test]
    fn test_verify_blob_hashes_commitment_tampered() {
        use crate::commitment::{verify_blob_hashes, ZK_SYNC_BYTES_PER_BLOB};

        let blob_data = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let linear_hash = H256(keccak256(&blob_data));
        let versioned_hash = H256([0x01; 32]);

        let mut blob_hashes = vec![BlobHash::default(); 16];
        blob_hashes[0] = BlobHash {
            linear_hash,
            commitment: H256([0xFF; 32]), // wrong commitment
        };
        let mut versioned_hashes = vec![H256::zero(); 16];
        versioned_hashes[0] = versioned_hash;

        let err = verify_blob_hashes(&blob_data, &versioned_hashes, &blob_hashes).unwrap_err();
        assert!(
            err.to_string().contains("opening commitment mismatch"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let v1 = V1AirbenderVerifierInput {
            vm_run_data: VMRunWitnessInputData {
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
            merkle_paths: WitnessInputMerklePaths::new(0),
            l2_blocks_execution_data: vec![],
            l1_batch_env: L1BatchEnv {
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
            system_env: SystemEnv {
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
            pubdata_params: Default::default(),
            commitment_input: None,
        };
        let avi = AirbenderVerifierInput::V1(v1);
        let serialized =
            AirbenderCodecV0::encode(&avi).expect("Failed to serialize AirbenderVerifierInput.");
        let deserialized: AirbenderVerifierInput = AirbenderCodecV0::decode(&serialized)
            .expect("Failed to deserialize AirbenderVerifierInput.");

        assert_eq!(avi, deserialized);
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
