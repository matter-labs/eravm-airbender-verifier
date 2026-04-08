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
    commitment::serialize_commitments,
    l2_to_l1_log::SystemL2ToL1Log,
    web3::keccak256,
    H256, U256,
};

use crate::types::{CommitmentInput, TOTAL_BLOBS_IN_COMMITMENT};

/// Result of the batch commitment computation.
pub struct BatchCommitmentOutput {
    /// The batch commitment: `keccak256(abi.encode(passThrough, metadata, auxiliary))`.
    pub commitment: H256,
    /// The proof public input: `keccak256(prevCommitment || currentCommitment)`.
    /// L1 applies `>> 32` before verifying; the guest returns the full 256-bit hash.
    pub proof_public_input: [u32; 8],
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
        if end <= memory_size_bytes {
            value.to_big_endian(&mut result[start..end]);
        }
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
}
