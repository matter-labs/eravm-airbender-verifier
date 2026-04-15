//! Batch commitment computation for EraVM-on-Airbender.
//!
//! Computes the 3-layer Era VM commitment hash tree that matches
//! `Committer.sol::_createBatchCommitment()` on L1:
//!
//! ```text
//! commitment = keccak256(abi.encode(passThroughDataHash, metadataHash, auxiliaryOutputHash))
//! ```
//!
//! The only deviation from Boojum is inside `auxiliaryOutputHash`:
//! - `bootloaderHeapInitialContentsHash` uses Blake2s instead of Poseidon2-Goldilocks.
//! - `eventsQueueStateHash` is set to `bytes32(0)` (events are deterministic outputs of
//!   proven-correct execution and don't need separate commitment).
//!
//! All other components are identical to the L1 contract's computation.

use anyhow::ensure;
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_crypto_primitives::hasher::Hasher;
use zksync_types::{
    commitment::serialize_commitments, l2_to_l1_log::SystemL2ToL1Log, web3::keccak256, H256, U256,
};

use crate::types::{CommitmentInput, TOTAL_BLOBS_IN_COMMITMENT};

/// Result of the batch commitment computation.
pub struct BatchCommitmentOutput {
    /// The batch commitment: `keccak256(abi.encode(passThrough, metadata, auxiliary))`.
    pub commitment: H256,
    /// The proof public input: `keccak256(prevCommitment || currentCommitment)`.
    /// L1 applies `>> 32` before verifying; the guest returns the full 256-bit hash.
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
    pub zk_porter_available: bool,
    pub bootloader_code_hash: H256,
    pub default_aa_code_hash: H256,
    pub evm_emulator_code_hash: H256,

    // auxiliaryOutput components
    pub system_logs: Vec<SystemL2ToL1Log>,
    pub state_diff_hash: H256,
    pub bootloader_initial_heap: Vec<u8>,

    // External inputs (from CommitmentInput)
    pub commitment_input: CommitmentInput,
}

impl CommitmentData {
    pub fn compute(self) -> anyhow::Result<BatchCommitmentOutput> {
        let pass_through_data_hash = self.compute_pass_through_data_hash();
        let metadata_hash = self.compute_metadata_hash();
        let system_logs_hash = self.compute_system_logs_hash();
        let bootloader_heap_hash = self.compute_bootloader_heap_hash();
        let state_diff_hash = self.state_diff_hash;
        let auxiliary_output_hash = self.compute_auxiliary_output_hash()?;

        // Committer.sol:749 — uses abi.encode (equivalent to abi.encodePacked for bytes32 types)
        let commitment = {
            let mut data = Vec::with_capacity(96);
            data.extend_from_slice(pass_through_data_hash.as_bytes());
            data.extend_from_slice(metadata_hash.as_bytes());
            data.extend_from_slice(auxiliary_output_hash.as_bytes());
            H256(keccak256(&data))
        };

        // Executor.sol:321-322
        let prev = self.commitment_input.prev_batch_commitment;
        let proof_public_input = {
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(prev.as_bytes());
            data[32..].copy_from_slice(commitment.as_bytes());
            let hash = keccak256(&data);
            bytes32_to_u32x8(hash)
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

    /// Matches `Committer.sol::_batchPassThroughData()`.
    ///
    /// ```solidity
    /// abi.encodePacked(
    ///     _batch.indexRepeatedStorageChanges,  // uint64
    ///     _batch.newStateRoot,                 // bytes32
    ///     uint64(0),                           // zkPorter index (reserved)
    ///     bytes32(0)                           // zkPorter batch hash (reserved)
    /// )
    /// ```
    fn compute_pass_through_data_hash(&self) -> H256 {
        let mut data = Vec::with_capacity(8 + 32 + 8 + 32);
        data.extend_from_slice(&self.new_enumeration_index.to_be_bytes());
        data.extend_from_slice(self.new_state_root.as_bytes());
        data.extend_from_slice(&0u64.to_be_bytes()); // zkPorter index
        data.extend_from_slice(&[0u8; 32]); // zkPorter batch hash
        H256(keccak256(&data))
    }

    /// Matches `Committer.sol::_batchMetaParameters()`.
    ///
    /// ```solidity
    /// abi.encodePacked(
    ///     s.zkPorterIsAvailable,
    ///     s.l2BootloaderBytecodeHash,
    ///     s.l2DefaultAccountBytecodeHash,
    ///     s.l2EvmEmulatorBytecodeHash
    /// )
    /// ```
    fn compute_metadata_hash(&self) -> H256 {
        let mut data = Vec::with_capacity(1 + 32 + 32 + 32);
        data.push(self.zk_porter_available as u8);
        data.extend_from_slice(self.bootloader_code_hash.as_bytes());
        data.extend_from_slice(self.default_aa_code_hash.as_bytes());
        data.extend_from_slice(self.evm_emulator_code_hash.as_bytes());
        H256(keccak256(&data))
    }

    /// Matches `Committer.sol::_batchAuxiliaryOutput()`.
    ///
    /// ```solidity
    /// abi.encodePacked(
    ///     keccak256(systemLogs),
    ///     stateDiffHash,
    ///     bootloaderHeapInitialContentsHash,  // Blake2s (was Poseidon2)
    ///     eventsQueueStateHash,               // bytes32(0) (was Poseidon2)
    ///     _encodeBlobAuxiliaryOutput(blobCommitments, blobHashes)
    /// )
    /// ```
    fn compute_auxiliary_output_hash(&self) -> anyhow::Result<H256> {
        let system_logs_hash = self.compute_system_logs_hash();
        let bootloader_heap_hash = self.compute_bootloader_heap_hash();

        let mut data = Vec::new();
        // [1] keccak256(systemLogs)
        data.extend_from_slice(system_logs_hash.as_bytes());
        // [2] stateDiffHash
        data.extend_from_slice(self.state_diff_hash.as_bytes());
        // [3] bootloaderHeapInitialContentsHash — Blake2s of full expanded heap
        data.extend_from_slice(bootloader_heap_hash.as_bytes());
        // [4] eventsQueueStateHash — constant zero
        data.extend_from_slice(&[0u8; 32]);
        // [5] blob auxiliary output — interleaved (hash, commitment) pairs
        data.extend_from_slice(&self.encode_blob_auxiliary_output()?);

        Ok(H256(keccak256(&data)))
    }

    /// `keccak256` of serialized system logs, matching L1's `keccak256(_batch.systemLogs)`.
    fn compute_system_logs_hash(&self) -> H256 {
        let serialized = serialize_commitments(&self.system_logs);
        H256(keccak256(&serialized))
    }

    /// Blake2s hash of the full expanded bootloader heap.
    /// Replaces Boojum's Poseidon2-Goldilocks sponge over `MemoryQuery` entries.
    fn compute_bootloader_heap_hash(&self) -> H256 {
        Blake2Hasher.hash_bytes(&self.bootloader_initial_heap)
    }

    /// Matches `Committer.sol::_encodeBlobAuxiliaryOutput()`.
    /// Produces `TOTAL_BLOBS_IN_COMMITMENT` pairs of `(blobHash, blobCommitment)`,
    /// each 32 bytes, for a total of `TOTAL_BLOBS_IN_COMMITMENT * 64` bytes.
    fn encode_blob_auxiliary_output(&self) -> anyhow::Result<Vec<u8>> {
        let hashes = &self.commitment_input.blob_linear_hashes;
        let commits = &self.commitment_input.blob_opening_commitments;

        ensure!(
            hashes.len() == TOTAL_BLOBS_IN_COMMITMENT,
            "blob_linear_hashes length mismatch: got {}, expected {TOTAL_BLOBS_IN_COMMITMENT}",
            hashes.len()
        );
        ensure!(
            commits.len() == TOTAL_BLOBS_IN_COMMITMENT,
            "blob_opening_commitments length mismatch: got {}, expected {TOTAL_BLOBS_IN_COMMITMENT}",
            commits.len()
        );

        let mut output = Vec::with_capacity(TOTAL_BLOBS_IN_COMMITMENT * 64);
        for i in 0..TOTAL_BLOBS_IN_COMMITMENT {
            output.extend_from_slice(hashes[i].as_bytes());
            output.extend_from_slice(commits[i].as_bytes());
        }
        Ok(output)
    }
}

/// Size of a single blob chunk in ZKsync's encoding (31 bytes per field element).
const BLOB_CHUNK_SIZE: usize = 31;

/// Number of field elements per EIP-4844 blob.
const ELEMENTS_PER_4844_BLOCK: usize = 4096;

/// Total blob data size: 31 * 4096 = 126976 bytes.
pub const ZK_SYNC_BYTES_PER_BLOB: usize = BLOB_CHUNK_SIZE * ELEMENTS_PER_4844_BLOCK;

/// Verify blob opening commitments by evaluating the blob polynomial.
///
/// For each blob with non-zero `linear_hash`:
/// 1. Parse the blob chunk into BLS12-381 scalar field elements (polynomial in monomial form)
/// 2. Compute `evaluation_point = keccak256(linear_hash || versioned_hash)[16..]`
/// 3. Evaluate the polynomial at `evaluation_point` using Horner's rule
/// 4. Verify `output_hash == keccak256(versioned_hash || evaluation_point || opening_value)`
///
/// This matches the `EIP4844Repack` sub-circuit in Boojum
/// (`zkevm_circuits/src/eip_4844/mod.rs`).
pub fn verify_blob_opening_commitments(
    pubdata: &[u8],
    versioned_hashes: &[H256],
    claimed_linear_hashes: &[H256],
    claimed_output_hashes: &[H256],
) -> anyhow::Result<()> {
    use ark_bls12_381::Fr as Bls12_381Fr;
    use ark_ff::{BigInteger, PrimeField, Zero};

    ensure!(
        versioned_hashes.len() == claimed_linear_hashes.len()
            && claimed_linear_hashes.len() == claimed_output_hashes.len(),
        "blob array length mismatch: versioned={}, linear={}, output={}",
        versioned_hashes.len(),
        claimed_linear_hashes.len(),
        claimed_output_hashes.len()
    );

    let num_blobs = pubdata.len().div_ceil(ZK_SYNC_BYTES_PER_BLOB);

    for i in 0..claimed_output_hashes.len() {
        if claimed_linear_hashes[i] == H256::zero() {
            ensure!(
                claimed_output_hashes[i] == H256::zero(),
                "blob {i}: linear hash is zero but output hash is non-zero"
            );
            continue;
        }

        // Get the blob data (pad to full blob size if last chunk is short).
        let blob_data = if i < num_blobs {
            let start = i * ZK_SYNC_BYTES_PER_BLOB;
            let end = ((i + 1) * ZK_SYNC_BYTES_PER_BLOB).min(pubdata.len());
            let chunk = &pubdata[start..end];
            if chunk.len() == ZK_SYNC_BYTES_PER_BLOB {
                chunk.to_vec()
            } else {
                let mut padded = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
                padded[..chunk.len()].copy_from_slice(chunk);
                padded
            }
        } else {
            vec![0u8; ZK_SYNC_BYTES_PER_BLOB]
        };

        // Step 1: Parse blob data into polynomial coefficients (monomial form).
        // Chunks are read in reverse order (highest-degree coefficient first).
        // Each 31-byte chunk is interpreted as a little-endian BLS12-381 scalar.
        let poly: Vec<Bls12_381Fr> = blob_data
            .chunks(BLOB_CHUNK_SIZE)
            .rev()
            .map(|chunk| {
                let mut buf = [0u8; 32];
                buf[..BLOB_CHUNK_SIZE].copy_from_slice(chunk);
                // 31 bytes LE is always below the BLS12-381 modulus.
                Bls12_381Fr::from_le_bytes_mod_order(&buf)
            })
            .collect();

        // Step 2: Compute evaluation point = keccak256(linear_hash || versioned_hash)[16..32]
        let evaluation_point_bytes = {
            let mut preimage = Vec::with_capacity(64);
            preimage.extend_from_slice(claimed_linear_hashes[i].as_bytes());
            preimage.extend_from_slice(versioned_hashes[i].as_bytes());
            let hash = keccak256(&preimage);
            let mut buf = [0u8; 32];
            buf[16..32].copy_from_slice(&hash[16..32]);
            buf
        };
        let evaluation_point = Bls12_381Fr::from_be_bytes_mod_order(&evaluation_point_bytes);

        // Step 3: Evaluate polynomial using Horner's rule.
        // poly[0] is the lowest-degree coefficient (built from the last blob chunk).
        // Horner: result = p[n-1] + x*(p[n-2] + x*(p[n-3] + ... + x*p[0]))
        // But our poly is already in order [a_0, a_1, ..., a_{n-1}],
        // so we iterate in reverse: start from a_{n-1} and work down.
        let mut opening_value = Bls12_381Fr::zero();
        for coeff in poly.iter().rev() {
            opening_value *= evaluation_point;
            opening_value += coeff;
        }

        // Step 4: Serialize opening value as 32-byte big-endian.
        let opening_value_bytes: [u8; 32] = {
            let be_vec = opening_value.into_bigint().to_bytes_be();
            // BLS12-381 Fr uses BigInteger256 → exactly 32 bytes.
            be_vec
                .try_into()
                .expect("BLS12-381 Fr should be 32 bytes BE")
        };

        // Step 5: Compute expected output_hash = keccak256(versioned_hash || evaluation_point || opening_value)
        let expected_output_hash = {
            let mut preimage = Vec::with_capacity(32 + 16 + 32);
            preimage.extend_from_slice(versioned_hashes[i].as_bytes());
            preimage.extend_from_slice(&evaluation_point_bytes[16..32]); // only the 16-byte truncated point
            preimage.extend_from_slice(&opening_value_bytes);
            H256(keccak256(&preimage))
        };

        ensure!(
            expected_output_hash == claimed_output_hashes[i],
            "blob {i} opening commitment mismatch: computed {expected_output_hash:?}, claimed {:?}",
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

    fn make_test_commitment_data() -> CommitmentData {
        CommitmentData {
            new_state_root: H256([0xAB; 32]),
            new_enumeration_index: 42,
            zk_porter_available: false,
            bootloader_code_hash: H256([0x11; 32]),
            default_aa_code_hash: H256([0x22; 32]),
            evm_emulator_code_hash: H256([0x33; 32]),
            system_logs: vec![],
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
            zk_porter_available: false,
            bootloader_code_hash: H256::zero(),
            default_aa_code_hash: H256::zero(),
            evm_emulator_code_hash: H256::zero(),
            system_logs: vec![],
            state_diff_hash: H256::zero(),
            bootloader_initial_heap: vec![],
            commitment_input: CommitmentInput::default(),
        };

        let hash = data.compute_pass_through_data_hash();
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
}
