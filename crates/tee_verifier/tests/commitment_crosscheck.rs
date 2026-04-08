//! Cross-check: verify that the Airbender guest's full commitment matches
//! an independent computation via the sequencer's L1BatchCommitment code,
//! when using Airbender-style aux commitments (Blake2s bootloader, zero events).
//!
//! Requires: ./scripts/fetch_lfs_batches.sh 506093.bin.gz

use std::path::Path;

use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_crypto_primitives::hasher::Hasher;
use zksync_multivm::utils::get_used_bootloader_memory_bytes;
use zksync_tee_verifier::commitment::{expand_bootloader_heap, ZK_SYNC_BYTES_PER_BLOB};
use zksync_tee_verifier::types::{
    CommitmentInput as AirbenderCommitmentInput, TeeVerifierInput, TOTAL_BLOBS_IN_COMMITMENT,
};
use zksync_tee_verifier::verify_and_commit;
use zksync_types::{
    commitment::{
        AuxCommitments, BlobHash, CommitmentCommonInput,
        CommitmentInput as SequencerCommitmentInput, L1BatchCommitment,
    },
    u256_to_h256,
    H256,
};

fn load_batch(path: &Path) -> TeeVerifierInput {
    let raw_text = if path.extension().is_some_and(|e| e == "gz") {
        let compressed = std::fs::read(path).expect("failed to read");
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut text = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut text).expect("decompress failed");
        text
    } else {
        std::fs::read_to_string(path).expect("failed to read")
    };

    let compact: String = raw_text.chars().filter(|ch| !ch.is_whitespace()).collect();
    let compact = compact.strip_prefix("0x").unwrap_or(&compact);
    let words: Vec<u32> = compact
        .as_bytes()
        .chunks(8)
        .map(|chunk| {
            let s = std::str::from_utf8(chunk).unwrap();
            u32::from_str_radix(s, 16).unwrap()
        })
        .collect();

    let payload_byte_len = words[0] as usize;
    let payload_bytes: Vec<u8> = words[1..].iter().flat_map(|w| w.to_be_bytes()).collect();
    let payload = &payload_bytes[..payload_byte_len];

    let (input, _): (TeeVerifierInput, usize) =
        bincode_v2::serde::decode_from_slice(payload, bincode_v2::config::standard())
            .expect("failed to deserialize");
    input
}

#[test]
fn test_full_commitment_matches_sequencer() {
    let batch_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/era_mainnet_batches/binary/506093.bin.gz");
    if !batch_path.exists() || std::fs::metadata(&batch_path).unwrap().len() < 1000 {
        eprintln!("Skipping: batch file not available");
        return;
    }

    let input = load_batch(&batch_path);
    let TeeVerifierInput::V1(input) = input else {
        panic!("expected V1");
    };

    // Save data needed for sequencer-side commitment computation.
    let protocol_version = input.system_env.version;
    let bootloader_code_hash = input.system_env.base_system_smart_contracts.bootloader.hash;
    let default_aa_code_hash = u256_to_h256(input.vm_run_data.default_account_code_hash);
    let evm_emulator_code_hash = input
        .vm_run_data
        .evm_emulator_code_hash
        .map(u256_to_h256);
    let initial_heap_content = input.vm_run_data.initial_heap_content.clone();

    // Run the Airbender guest's verify_and_commit.
    let airbender_input = AirbenderCommitmentInput::default();
    let result = verify_and_commit(input, airbender_input).expect("verify_and_commit failed");

    println!("Batch: {}", result.batch_number);
    println!("State root: {:?}", result.value_hash);
    println!("Enumeration index: {}", result.new_enumeration_index);
    println!("Guest commitment: {:?}", result.commitment);
    println!("  pass_through_data_hash: {:?}", result.pass_through_data_hash);
    println!("  metadata_hash:          {:?}", result.metadata_hash);
    println!("  auxiliary_output_hash:   {:?}", result.auxiliary_output_hash);

    // Compute Airbender-style AuxCommitments.
    let memory_size = get_used_bootloader_memory_bytes(protocol_version.into());
    let expanded_heap = expand_bootloader_heap(&initial_heap_content, memory_size);
    let bootloader_heap_blake2s = Blake2Hasher.hash_bytes(&expanded_heap);

    let aux_commitments = AuxCommitments {
        events_queue_commitment: H256::zero(),
        bootloader_initial_content_commitment: bootloader_heap_blake2s,
    };

    // Build the sequencer's CommitmentInput with our Airbender aux commitments.
    // We use empty user logs (the sequencer needs them for the Merkle tree,
    // but l2_l1_logs_merkle_root will be computed internally).
    // For state_diffs we use empty (they affect state_diffs_hash in aux output).
    // These will produce DIFFERENT aux hashes since we don't have the real values,
    // BUT we can verify pass_through_data_hash and metadata_hash match exactly.
    let sequencer_input = SequencerCommitmentInput::PostBoojum {
        common: CommitmentCommonInput {
            l2_to_l1_logs: vec![], // empty — will affect l2_l1_logs_merkle_root
            rollup_last_leaf_index: result.new_enumeration_index,
            rollup_root_hash: result.value_hash,
            bootloader_code_hash,
            default_aa_code_hash,
            evm_emulator_code_hash,
            protocol_version,
        },
        system_logs: vec![],  // empty — will affect system_logs_linear_hash
        state_diffs: vec![],  // empty — will affect state_diffs_hash
        aux_commitments,
        blob_hashes: (0..TOTAL_BLOBS_IN_COMMITMENT)
            .map(|_| BlobHash {
                linear_hash: H256::zero(),
                commitment: H256::zero(),
            })
            .collect(),
        aggregation_root: H256::zero(),
    };

    let sequencer_commitment = L1BatchCommitment::new(sequencer_input, true)
        .expect("sequencer commitment construction failed");
    let sequencer_hashes = sequencer_commitment
        .hash()
        .expect("sequencer commitment hash failed");

    println!("\nSequencer sub-hashes:");
    println!("  pass_through_data_hash: {:?}", sequencer_hashes.pass_through_data);
    println!("  metadata_hash:          {:?}", sequencer_hashes.meta_parameters);

    // VERIFY: passThroughDataHash must match exactly.
    // Both encode: keccak256(u64_be(enumeration_index) || state_root || u64_be(0) || bytes32(0))
    assert_eq!(
        result.pass_through_data_hash, sequencer_hashes.pass_through_data,
        "passThroughDataHash mismatch between guest and sequencer"
    );

    // VERIFY: metadataHash must match exactly.
    assert_eq!(
        result.metadata_hash, sequencer_hashes.meta_parameters,
        "metadataHash mismatch between guest and sequencer"
    );

    // VERIFY: system_logs_hash — independently computed from raw system logs
    // using the same serialize_commitments + keccak256 that the sequencer uses.
    use zksync_types::{commitment::serialize_commitments, web3::keccak256};
    let independent_system_logs_hash = {
        let packed = serialize_commitments(&result.system_logs);
        H256(keccak256(&packed))
    };
    assert_eq!(
        result.system_logs_hash, independent_system_logs_hash,
        "system_logs_hash: guest's hash doesn't match independent computation"
    );
    println!("  system_logs_hash:     independent == guest ✓ ({} logs)", result.system_logs.len());

    // VERIFY: state_diff_hash — independently computed from raw state diffs.
    let independent_state_diff_hash = {
        let packed = serialize_commitments(&result.state_diffs);
        H256(keccak256(&packed))
    };
    assert_eq!(
        result.state_diff_hash, independent_state_diff_hash,
        "state_diff_hash: guest's hash doesn't match independent computation"
    );
    println!("  state_diff_hash:      independent == guest ✓ ({} diffs)", result.state_diffs.len());

    // VERIFY: bootloader_heap_hash — independently computed via Blake2s.
    let independent_heap_hash = {
        let expanded = expand_bootloader_heap(&initial_heap_content, memory_size);
        Blake2Hasher.hash_bytes(&expanded)
    };
    assert_eq!(
        result.bootloader_heap_hash, independent_heap_hash,
        "bootloader_heap_hash: guest's hash doesn't match independent computation"
    );
    println!("  bootloader_heap_hash: independent == guest ✓");

    // VERIFY: auxiliaryOutputHash — reconstruct from independently verified sub-hashes.
    let reconstructed_aux_hash = {
        let mut data = Vec::new();
        data.extend_from_slice(independent_system_logs_hash.as_bytes());
        data.extend_from_slice(independent_state_diff_hash.as_bytes());
        data.extend_from_slice(independent_heap_hash.as_bytes());
        data.extend_from_slice(&[0u8; 32]); // events_queue = 0
        for _ in 0..TOTAL_BLOBS_IN_COMMITMENT {
            data.extend_from_slice(&[0u8; 32]); // blob hash
            data.extend_from_slice(&[0u8; 32]); // blob commitment
        }
        H256(keccak256(&data))
    };
    assert_eq!(
        result.auxiliary_output_hash, reconstructed_aux_hash,
        "auxiliaryOutputHash doesn't match reconstruction from independent sub-hashes"
    );
    println!("  auxiliaryOutputHash:  independent == guest ✓");

    // VERIFY: full commitment = keccak256(passThrough || metadata || auxiliary)
    let reconstructed_commitment = {
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(sequencer_hashes.pass_through_data.as_bytes());
        data.extend_from_slice(sequencer_hashes.meta_parameters.as_bytes());
        data.extend_from_slice(reconstructed_aux_hash.as_bytes());
        H256(keccak256(&data))
    };
    assert_eq!(
        result.commitment, reconstructed_commitment,
        "commitment doesn't match reconstruction from sequencer + independent sub-hashes"
    );

    println!("  commitment:           sequencer+independent == guest ✓");
    println!("\nFull cross-check PASSED — every sub-hash verified independently.");
}
