//! Batch commitment computation for EraVM-on-Airbender.
//!
//! Computes the 3-layer Era VM commitment hash tree that matches
//! `Committer.sol::_createBatchCommitment()` on L1:
//!
//! ```text
//! commitment = keccak256(abi.encode(passThroughDataHash, metadataHash, auxiliaryOutputHash))
//! ```
//!
//! ## Relationship to `zksync_types::commitment::L1BatchCommitment`
//!
//! The vendored `zksync_types::commitment::L1BatchCommitment` from zksync-era
//! computes the same 3-layer hash for Boojum. We don't reuse it directly
//! because Airbender deviates inside `auxiliaryOutputHash`:
//! - `bootloaderHeapInitialContentsHash` uses Blake2s instead of Poseidon2-Goldilocks.
//! - `eventsQueueStateHash` is set to `bytes32(0)` (events are deterministic outputs
//!   of proven-correct execution and don't need separate commitment).
//!
//! `pass_through_data_hash` and `metadata_hash` are otherwise identical to
//! upstream and are cross-checked against `L1BatchCommitment::hash()` in
//! `host::fri::crosscheck_commitment` for every CI batch.

use anyhow::Context;
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_crypto_primitives::hasher::Hasher;
use zksync_types::{
    commitment::{
        serialize_commitments, AuxCommitments, BlobHash, L1BatchAuxiliaryCommonOutput,
        L1BatchAuxiliaryOutput, L1BatchMetaParameters, L1BatchPassThroughData, RootState,
    },
    l2_to_l1_log::SystemL2ToL1Log,
    web3::keccak256,
    ProtocolVersionId, H256, U256,
};

use crate::types::{CommitmentInput, TOTAL_BLOBS_IN_COMMITMENT};

/// `keccak256` of serialized system logs, matching L1's `keccak256(_batch.systemLogs)`.
pub fn compute_system_logs_hash(system_logs: &[SystemL2ToL1Log]) -> H256 {
    H256(keccak256(&serialize_commitments(system_logs)))
}

/// Compute the passthrough data hash for a batch.
///
/// This is used both for the current batch's commitment and for verifying
/// the previous batch's commitment binding. Delegates to upstream
/// `L1BatchPassThroughData::hash` so the encoding stays in lockstep with
/// `Committer.sol::_batchPassThroughData()`.
pub fn compute_pass_through_data_hash(enumeration_index: u64, state_root: H256) -> H256 {
    L1BatchPassThroughData {
        shared_states: vec![
            RootState {
                last_leaf_index: enumeration_index,
                root_hash: state_root,
            },
            // zkPorter shared state — `last_leaf_index` and `root_hash` are reserved
            // and always zero.
            RootState {
                last_leaf_index: 0,
                root_hash: H256::zero(),
            },
        ],
    }
    .hash()
    .expect("two RootStates must serialize to 80 bytes")
}

/// Compute the full batch commitment from its three sub-hashes.
///
/// Used for both current batch commitment and previous batch commitment
/// reconstruction. Matches `Committer.sol::_createBatchCommitment()`.
pub fn compute_commitment(
    pass_through_data_hash: H256,
    metadata_hash: H256,
    auxiliary_output_hash: H256,
) -> H256 {
    // abi.encode(bytes32, bytes32, bytes32) — 96 bytes, stack-allocated.
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(pass_through_data_hash.as_bytes());
    data[32..64].copy_from_slice(metadata_hash.as_bytes());
    data[64..96].copy_from_slice(auxiliary_output_hash.as_bytes());
    H256(keccak256(&data))
}

/// Result of the batch commitment computation.
pub struct BatchCommitmentOutput {
    /// The batch commitment: `keccak256(abi.encode(passThrough, metadata, auxiliary))`.
    pub commitment: H256,
    /// The proof public input preimage: `keccak256(prev_batch_commitment || current_commitment)`,
    /// packed as 8 big-endian u32 words (`u32[0]` = bytes 0..4 of the hash, `u32[7]` = bytes 28..32).
    ///
    /// # Why the full 256 bits, and why the wrapper drops 32 of them
    ///
    /// The on-chain SNARK verifier takes a single BN254 scalar as public input, but
    /// BN254's scalar field is ~254 bits — the full 256-bit `keccak(prev || curr)`
    /// doesn't fit. L1 passes `uint256(keccak(prev || curr)) >> PUBLIC_INPUT_SHIFT`
    /// with `PUBLIC_INPUT_SHIFT = 32` (see `Executor.sol::_getBatchProofPublicInput`
    /// and `Config.sol`), i.e. the high 224 bits.
    ///
    /// We expose all 256 bits here for two reasons: (a) the STARK public output is
    /// byte-shaped, so the natural emission is the full hash; (b) keeping the unshifted
    /// hash decouples the guest from the wrapper circuit's field-size constraint — if
    /// the wrapper later switches curve or proving system, only the wrapper changes.
    ///
    /// The Airbender → PLONK SNARK wrapper drops the low 32 bits when forming the BN254
    /// public input: treat `u32[0..7]` as a big-endian 224-bit integer and ignore
    /// `u32[7]`. This mirrors Boojum's scheduler, which emits only the high 28 bytes.
    /// (Airbender currently uses PLONK; an FFLONK wrapper variant may be added later.)
    ///
    /// `test_proof_public_input_matches_l1_shift` pins this relationship — any wrapper
    /// or encoding change must update that test.
    pub proof_public_input: [u32; 8],
    /// Sub-hashes for debugging / cross-checking.
    pub pass_through_data_hash: H256,
    pub metadata_hash: H256,
    pub auxiliary_output_hash: H256,
    pub system_logs_hash: H256,
    pub state_diff_hash: H256,
    pub bootloader_heap_hash: H256,
}

/// All data needed to compute the batch commitment, collected after verification.
pub struct CommitmentData {
    // passThroughData components
    pub new_state_root: H256,
    pub new_enumeration_index: u64,

    // metadataHash components
    pub protocol_version: ProtocolVersionId,
    pub zk_porter_available: bool,
    pub bootloader_code_hash: H256,
    pub default_aa_code_hash: H256,
    pub evm_emulator_code_hash: H256,

    // auxiliaryOutput components
    pub system_logs_hash: H256,
    pub state_diff_hash: H256,
    pub bootloader_initial_heap: Vec<u8>,

    // External inputs (from CommitmentInput)
    pub commitment_input: CommitmentInput,
}

impl CommitmentData {
    pub fn compute(self) -> anyhow::Result<BatchCommitmentOutput> {
        let pass_through_data_hash =
            compute_pass_through_data_hash(self.new_enumeration_index, self.new_state_root);
        let metadata_hash = self.compute_metadata_hash();
        let system_logs_hash = self.system_logs_hash;
        let bootloader_heap_hash = self.compute_bootloader_heap_hash();
        let state_diff_hash = self.state_diff_hash;
        let auxiliary_output_hash = self.compute_auxiliary_output_hash()?;

        let commitment =
            compute_commitment(pass_through_data_hash, metadata_hash, auxiliary_output_hash);

        // Matches `Executor.sol::_getBatchProofPublicInput`:
        //   uint256(keccak256(abi.encodePacked(prev, curr))) >> PUBLIC_INPUT_SHIFT
        // The shift is the wrapper's responsibility — see the doc comment on
        // `BatchCommitmentOutput::proof_public_input`.
        let prev = self.commitment_input.prev_batch_commitment;
        let proof_public_input = {
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(prev.as_bytes());
            data[32..].copy_from_slice(commitment.as_bytes());
            bytes32_to_u32x8(keccak256(&data))
        };

        Ok(BatchCommitmentOutput {
            commitment,
            proof_public_input,
            pass_through_data_hash,
            metadata_hash,
            auxiliary_output_hash,
            system_logs_hash,
            state_diff_hash,
            bootloader_heap_hash,
        })
    }

    /// Delegates to upstream `L1BatchMetaParameters::hash`, which matches
    /// `Executor.sol::_batchMetaParameters()` for protocol versions ≥ 1.5.0
    /// (the only ones supported by this verifier — see
    /// `is_supported_by_fast_vm` in `lib.rs`).
    ///
    /// `zk_porter_available` is sourced from the witness (`SystemEnv`); the
    /// sequencer must set it to match L1's `ZKPORTER_IS_AVAILABLE` constant
    /// or the commitment will mismatch.
    fn compute_metadata_hash(&self) -> H256 {
        L1BatchMetaParameters {
            zkporter_is_available: self.zk_porter_available,
            bootloader_code_hash: self.bootloader_code_hash,
            default_aa_code_hash: self.default_aa_code_hash,
            evm_emulator_code_hash: Some(self.evm_emulator_code_hash),
            protocol_version: Some(self.protocol_version),
        }
        .hash()
    }

    /// Delegates to upstream `L1BatchAuxiliaryOutput::hash` (PostBoojum variant)
    /// so the encoding stays in lockstep with `Committer.sol::_batchAuxiliaryOutput()`.
    ///
    /// Airbender deviations from Boojum (documented in the module preamble) are
    /// encoded as direct field values:
    /// - `bootloader_initial_content_commitment`: Blake2s of the expanded heap
    ///   (vs Boojum's Poseidon2-Goldilocks sponge).
    /// - `events_queue_commitment`: `H256::zero()` (events are deterministic
    ///   outputs of proven-correct execution).
    fn compute_auxiliary_output_hash(&self) -> anyhow::Result<H256> {
        let hashes = &self.commitment_input.blob_linear_hashes;
        let commits = &self.commitment_input.blob_opening_commitments;
        anyhow::ensure!(
            hashes.len() == TOTAL_BLOBS_IN_COMMITMENT,
            "blob_linear_hashes length mismatch: got {}, expected {TOTAL_BLOBS_IN_COMMITMENT}",
            hashes.len()
        );
        anyhow::ensure!(
            commits.len() == TOTAL_BLOBS_IN_COMMITMENT,
            "blob_opening_commitments length mismatch: got {}, expected {TOTAL_BLOBS_IN_COMMITMENT}",
            commits.len()
        );
        let blob_hashes: Vec<BlobHash> = hashes
            .iter()
            .zip(commits.iter())
            .map(|(&linear_hash, &commitment)| BlobHash {
                linear_hash,
                commitment,
            })
            .collect();

        // `to_bytes()` for `PostBoojum` ignores `common`, `state_diffs_compressed`,
        // `aggregation_root`, and `local_root`, so we fill them with zeros.
        Ok(L1BatchAuxiliaryOutput::PostBoojum {
            common: L1BatchAuxiliaryCommonOutput {
                l2_l1_logs_merkle_root: H256::zero(),
                protocol_version: self.protocol_version,
            },
            system_logs_linear_hash: self.system_logs_hash,
            state_diffs_compressed: vec![],
            state_diffs_hash: self.state_diff_hash,
            aux_commitments: AuxCommitments {
                events_queue_commitment: H256::zero(),
                bootloader_initial_content_commitment: self.compute_bootloader_heap_hash(),
            },
            blob_hashes,
            aggregation_root: H256::zero(),
            local_root: H256::zero(),
        }
        .hash())
    }

    /// Blake2s hash of the full expanded bootloader heap.
    /// Replaces Boojum's Poseidon2-Goldilocks sponge over `MemoryQuery` entries.
    fn compute_bootloader_heap_hash(&self) -> H256 {
        Blake2Hasher.hash_bytes(&self.bootloader_initial_heap)
    }
}

/// Size of a single blob chunk in ZKsync's encoding (31 bytes per field element).
const BLOB_CHUNK_SIZE: usize = 31;

/// Number of field elements per EIP-4844 blob.
const ELEMENTS_PER_4844_BLOCK: usize = 4096;

/// Total blob data size: 31 * 4096 = 126976 bytes.
pub const ZK_SYNC_BYTES_PER_BLOB: usize = BLOB_CHUNK_SIZE * ELEMENTS_PER_4844_BLOCK;

/// Return blob `i`'s bytes from `pubdata` as a fully-sized,
/// zero-padded `Vec<u8>` (length `ZK_SYNC_BYTES_PER_BLOB`).
/// Returns `None` when `i` is past pubdata's blob count.
///
/// Owned `Vec` rather than `Cow`/scratch keeps the API simple; the worst
/// case is one full blob copy per slot, which is negligible next to the
/// keccak / BLS12-381 work each caller does on the result.
pub fn padded_blob_for(pubdata: &[u8], i: usize) -> Option<Vec<u8>> {
    let start = i * ZK_SYNC_BYTES_PER_BLOB;
    if start >= pubdata.len() {
        return None;
    }
    let end = ((i + 1) * ZK_SYNC_BYTES_PER_BLOB).min(pubdata.len());
    let mut padded = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
    padded[..end - start].copy_from_slice(&pubdata[start..end]);
    Some(padded)
}

/// Compute blob linear hashes from pubdata: keccak256 of each blob-sized chunk,
/// zero-padded for the last partial chunk. Returns `TOTAL_BLOBS_IN_COMMITMENT`
/// entries; unused slots are `H256::zero()`.
pub fn compute_blob_linear_hashes(pubdata: &[u8]) -> Vec<H256> {
    let mut result = vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT];
    for (i, slot) in result.iter_mut().enumerate() {
        if let Some(blob) = padded_blob_for(pubdata, i) {
            *slot = H256(keccak256(&blob));
        }
    }
    result
}

/// Compute the EIP-4844 opening commitment for a single padded blob.
///
/// Steps (matching Boojum's `EIP4844Repack` and `zksync-protocol`'s `eip_4844`):
/// 1. evaluation_point = `keccak256(linear_hash || versioned_hash)[16..32]`
/// 2. opening_value = `polynomial(evaluation_point)` over the BLS12-381 scalar
///    field, where the polynomial is the blob bytes interpreted as 31-byte
///    little-endian coefficients with the highest-degree coefficient first.
/// 3. opening_commitment = `keccak256(versioned_hash || eval_point[16..32] || opening_value)`
///
/// `blob_bytes` must be exactly `ZK_SYNC_BYTES_PER_BLOB` long; callers are
/// responsible for zero-padding partial blobs.
pub fn compute_blob_opening_commitment(
    blob_bytes: &[u8],
    versioned_hash: H256,
    linear_hash: H256,
) -> H256 {
    use ark_bls12_381::Fr as Bls12_381Fr;
    use ark_ff::{BigInteger, PrimeField, Zero};

    debug_assert_eq!(
        blob_bytes.len(),
        ZK_SYNC_BYTES_PER_BLOB,
        "compute_blob_opening_commitment expects a fully-padded blob"
    );

    // Step 1.
    let eval_hash = {
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(linear_hash.as_bytes());
        preimage[32..].copy_from_slice(versioned_hash.as_bytes());
        keccak256(&preimage)
    };
    let mut evaluation_point_bytes = [0u8; 32];
    evaluation_point_bytes[16..32].copy_from_slice(&eval_hash[16..32]);
    let evaluation_point = Bls12_381Fr::from_be_bytes_mod_order(&evaluation_point_bytes);

    // Step 2: Horner's rule, forward iteration treats first chunk as
    // highest-degree coefficient.
    let mut opening_value = Bls12_381Fr::zero();
    let mut buf = [0u8; 32];
    for chunk in blob_bytes.chunks(BLOB_CHUNK_SIZE) {
        buf[..BLOB_CHUNK_SIZE].copy_from_slice(chunk);
        // 31 bytes LE is always below the BLS12-381 modulus.
        let coeff = Bls12_381Fr::from_le_bytes_mod_order(&buf);
        opening_value *= evaluation_point;
        opening_value += coeff;
    }

    // Step 3.
    let opening_value_bytes: [u8; 32] = opening_value
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("BLS12-381 Fr should be 32 bytes BE");

    let mut preimage = [0u8; 32 + 16 + 32];
    preimage[..32].copy_from_slice(versioned_hash.as_bytes());
    preimage[32..48].copy_from_slice(&eval_hash[16..32]);
    preimage[48..].copy_from_slice(&opening_value_bytes);
    H256(keccak256(&preimage))
}

/// Verify blob opening commitments by recomputing each via
/// [`compute_blob_opening_commitment`] and comparing against the claimed value.
///
/// Matches the `EIP4844Repack` sub-circuit in Boojum
/// (`zkevm_circuits/src/eip_4844/mod.rs`).
pub fn verify_blob_opening_commitments(
    pubdata: &[u8],
    versioned_hashes: &[H256],
    claimed_linear_hashes: &[H256],
    claimed_output_hashes: &[H256],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        versioned_hashes.len() == claimed_linear_hashes.len()
            && claimed_linear_hashes.len() == claimed_output_hashes.len(),
        "blob array length mismatch: versioned={}, linear={}, output={}",
        versioned_hashes.len(),
        claimed_linear_hashes.len(),
        claimed_output_hashes.len()
    );

    for i in 0..claimed_output_hashes.len() {
        if claimed_linear_hashes[i] == H256::zero() {
            anyhow::ensure!(
                claimed_output_hashes[i] == H256::zero(),
                "blob {i}: linear hash is zero but output hash is non-zero"
            );
            continue;
        }

        // A non-zero claimed linear hash outside the pubdata range is caught by
        // `verify_blob_linear_hashes` before we get here; treat it as a bug if reached.
        let blob = padded_blob_for(pubdata, i).with_context(|| {
            format!("blob {i}: claimed linear hash is non-zero but no pubdata for this slot")
        })?;

        let computed =
            compute_blob_opening_commitment(&blob, versioned_hashes[i], claimed_linear_hashes[i]);

        anyhow::ensure!(
            computed == claimed_output_hashes[i],
            "blob {i} opening commitment mismatch: computed {computed:?}, claimed {:?}",
            claimed_output_hashes[i]
        );
    }
    Ok(())
}

/// Expand sparse bootloader heap content to a full byte buffer.
/// Mirrors `expand_memory_contents` in `commitment_generator/utils.rs`.
pub fn expand_bootloader_heap(
    initial_heap_content: &[(usize, U256)],
    memory_size_bytes: usize,
) -> Vec<u8> {
    let mut result = vec![0u8; memory_size_bytes];
    for &(offset, value) in initial_heap_content {
        let start = offset * 32;
        let end = start + 32;
        assert!(
            end <= memory_size_bytes,
            "bootloader heap entry at offset {offset} (byte {start}..{end}) exceeds memory size {memory_size_bytes}"
        );
        value.to_big_endian(&mut result[start..end]);
    }
    result
}

fn bytes32_to_u32x8(hash: [u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for (i, chunk) in hash.chunks_exact(4).enumerate() {
        result[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_bootloader_heap() {
        let content = vec![(0, U256::from(42)), (2, U256::from(100))];
        let expanded = expand_bootloader_heap(&content, 128);
        assert_eq!(expanded.len(), 128);

        // First word (offset 0) should be 42 in big-endian
        let mut expected = [0u8; 32];
        U256::from(42).to_big_endian(&mut expected);
        assert_eq!(&expanded[0..32], &expected);

        // Second word (offset 1) should be all zeros
        assert_eq!(&expanded[32..64], &[0u8; 32]);

        // Third word (offset 2) should be 100
        U256::from(100).to_big_endian(&mut expected);
        assert_eq!(&expanded[64..96], &expected);
    }

    #[test]
    fn test_bytes32_to_u32x8() {
        let hash = [0u8; 32];
        assert_eq!(bytes32_to_u32x8(hash), [0u32; 8]);

        let mut hash = [0u8; 32];
        hash[0] = 0xFF;
        let result = bytes32_to_u32x8(hash);
        assert_eq!(result[0], 0xFF000000);
    }

    /// Any post-1.5.0 protocol version yields the same metadata-hash byte
    /// layout (97 bytes); pick a stable one for tests.
    const TEST_PROTOCOL_VERSION: ProtocolVersionId = ProtocolVersionId::Version28;

    fn make_test_commitment_data() -> CommitmentData {
        CommitmentData {
            new_state_root: H256([0xAB; 32]),
            new_enumeration_index: 42,
            protocol_version: TEST_PROTOCOL_VERSION,
            zk_porter_available: false,
            bootloader_code_hash: H256([0x11; 32]),
            default_aa_code_hash: H256([0x22; 32]),
            evm_emulator_code_hash: H256([0x33; 32]),
            system_logs_hash: compute_system_logs_hash(&[]),
            state_diff_hash: H256([0x44; 32]),
            bootloader_initial_heap: vec![0u8; 64], // 2 words of zeros
            commitment_input: CommitmentInput {
                prev_batch_commitment: H256([0x55; 32]),
                prev_meta_hash: H256::zero(),
                prev_aux_hash: H256::zero(),
                blob_linear_hashes: vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT],
                blob_versioned_hashes: vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT],
                blob_opening_commitments: vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT],
            },
        }
    }

    #[test]
    fn test_pass_through_data_hash_encoding() {
        // Verify the encoding matches abi.encodePacked(uint64, bytes32, uint64, bytes32)
        let data = CommitmentData {
            new_state_root: H256([0xAB; 32]),
            new_enumeration_index: 42,
            protocol_version: TEST_PROTOCOL_VERSION,
            zk_porter_available: false,
            bootloader_code_hash: H256::zero(),
            default_aa_code_hash: H256::zero(),
            evm_emulator_code_hash: H256::zero(),
            system_logs_hash: compute_system_logs_hash(&[]),
            state_diff_hash: H256::zero(),
            bootloader_initial_heap: vec![],
            commitment_input: CommitmentInput::default(),
        };

        let hash = compute_pass_through_data_hash(data.new_enumeration_index, data.new_state_root);
        // Should be keccak256 of: 8 bytes (42 as u64 BE) + 32 bytes (0xAB...) + 8 bytes (0) + 32 bytes (0)
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&42u64.to_be_bytes());
        expected_input.extend_from_slice(&[0xAB; 32]);
        expected_input.extend_from_slice(&0u64.to_be_bytes());
        expected_input.extend_from_slice(&[0u8; 32]);
        assert_eq!(hash, H256(keccak256(&expected_input)));
    }

    #[test]
    fn test_metadata_hash_encoding() {
        let data = make_test_commitment_data();
        let hash = data.compute_metadata_hash();
        // abi.encodePacked(bool, bytes32, bytes32, bytes32)
        let mut expected = Vec::new();
        expected.push(0u8); // zkPorterAvailable = false
        expected.extend_from_slice(&[0x11; 32]); // bootloader
        expected.extend_from_slice(&[0x22; 32]); // default AA
        expected.extend_from_slice(&[0x33; 32]); // EVM emulator
        assert_eq!(hash, H256(keccak256(&expected)));
    }

    #[test]
    fn test_full_commitment_deterministic() {
        // Two identical CommitmentData must produce identical outputs.
        let data1 = make_test_commitment_data();
        let data2 = make_test_commitment_data();
        let out1 = data1.compute().unwrap();
        let out2 = data2.compute().unwrap();
        assert_eq!(out1.commitment, out2.commitment);
        assert_eq!(out1.proof_public_input, out2.proof_public_input);
    }

    #[test]
    fn test_commitment_changes_with_state_root() {
        let data1 = make_test_commitment_data();
        let mut data2 = make_test_commitment_data();
        data2.new_state_root = H256([0xCD; 32]);
        let out1 = data1.compute().unwrap();
        let out2 = data2.compute().unwrap();
        assert_ne!(out1.commitment, out2.commitment);
    }

    #[test]
    fn test_commitment_changes_with_bootloader_heap() {
        let data1 = make_test_commitment_data();
        let mut data2 = make_test_commitment_data();
        data2.bootloader_initial_heap = vec![0xFF; 64];
        let out1 = data1.compute().unwrap();
        let out2 = data2.compute().unwrap();
        assert_ne!(out1.commitment, out2.commitment);
    }

    #[test]
    fn test_proof_public_input_depends_on_prev_commitment() {
        let data1 = make_test_commitment_data();
        let mut data2 = make_test_commitment_data();
        data2.commitment_input.prev_batch_commitment = H256([0xEE; 32]);
        let out1 = data1.compute().unwrap();
        let out2 = data2.compute().unwrap();
        // Same current commitment, different prev → different proof public input.
        assert_eq!(out1.commitment, out2.commitment);
        assert_ne!(out1.proof_public_input, out2.proof_public_input);
    }

    #[test]
    fn test_proof_public_input_encoding() {
        let data = make_test_commitment_data();
        let out = data.compute().unwrap();
        // Manually compute: keccak256(prev || commitment)
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&[0x55; 32]); // prev_batch_commitment
        preimage[32..].copy_from_slice(out.commitment.as_bytes());
        let expected = keccak256(&preimage);
        assert_eq!(out.proof_public_input, bytes32_to_u32x8(expected));
    }

    #[test]
    #[should_panic(expected = "bootloader heap entry at offset")]
    fn test_expand_bootloader_heap_out_of_range() {
        let content = vec![(1000, U256::from(1))]; // offset 1000 * 32 = 32000 > 128
        expand_bootloader_heap(&content, 128);
    }

    /// Pins the wrapper contract described on `BatchCommitmentOutput::proof_public_input`:
    /// the big-endian integer formed by the high 7 u32 words must equal
    /// `uint256(keccak(prev || curr)) >> PUBLIC_INPUT_SHIFT` (PUBLIC_INPUT_SHIFT = 32).
    ///
    /// If this test breaks, either the on-wire `[u32; 8]` encoding changed or the L1
    /// shift contract changed — both require coordinated changes in the SNARK wrapper.
    #[test]
    fn test_proof_public_input_matches_l1_shift() {
        const PUBLIC_INPUT_SHIFT: u32 = 32;
        let out = make_test_commitment_data().compute().unwrap();

        // Reconstruct L1's value: keccak(prev || curr) >> 32, as a U256.
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&[0x55; 32]);
        preimage[32..].copy_from_slice(out.commitment.as_bytes());
        let l1_input = U256::from_big_endian(&keccak256(&preimage)) >> PUBLIC_INPUT_SHIFT;

        // Reconstruct what the wrapper should feed into L1:
        // the high 7 u32 words of `proof_public_input`, big-endian-combined into a u256.
        let mut wrapper_bytes = [0u8; 32];
        for (i, word) in out.proof_public_input[..7].iter().enumerate() {
            wrapper_bytes[4 + i * 4..4 + (i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        let wrapper_input = U256::from_big_endian(&wrapper_bytes);

        assert_eq!(
            wrapper_input, l1_input,
            "proof_public_input high 7 words must equal L1's keccak >> 32"
        );
    }
}
