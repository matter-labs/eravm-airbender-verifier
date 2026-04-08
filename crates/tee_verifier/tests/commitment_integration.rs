//! Integration test: load a real batch, run verification, check commitment output.
//!
//! Requires the test batch to be fetched via Git LFS:
//!   ./scripts/fetch_lfs_batches.sh 506093.bin.gz

use std::path::Path;

use zksync_tee_verifier::types::TeeVerifierInput;
use zksync_tee_verifier::Verify;

/// Load a batch from the framed-hex-words format used by the test corpus.
/// Uses bincode v2 (matching the host and vm_compare tooling).
fn load_batch(path: &Path) -> TeeVerifierInput {
    // Decompress if .gz
    let raw_text = if path.extension().is_some_and(|e| e == "gz") {
        let compressed = std::fs::read(path).expect("failed to read batch file");
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut text = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut text).expect("failed to decompress");
        text
    } else {
        std::fs::read_to_string(path).expect("failed to read batch file")
    };

    // Parse hex words
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

    // Extract framed payload (first word = byte length)
    let payload_byte_len = words[0] as usize;
    let payload_bytes: Vec<u8> = words[1..].iter().flat_map(|w| w.to_be_bytes()).collect();
    let payload = &payload_bytes[..payload_byte_len];

    // Deserialize with bincode v2 (matching host/vm_compare tooling)
    let (input, _): (TeeVerifierInput, usize) =
        bincode_v2::serde::decode_from_slice(payload, bincode_v2::config::standard())
            .expect("failed to deserialize TeeVerifierInput");
    input
}

#[test]
fn test_batch_506093_commitment() {
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

    let input = load_batch(&batch_path);
    let TeeVerifierInput::V1(input) = input else {
        panic!("expected TeeVerifierInput::V1");
    };

    println!(
        "Running verification for batch {}...",
        input.l1_batch_env.number
    );
    let result = input.verify().expect("verification failed");

    assert_ne!(
        result.commitment,
        zksync_types::H256::zero(),
        "commitment should be non-zero"
    );
    assert_ne!(
        result.proof_public_input, [0u32; 8],
        "proof public input should be non-zero"
    );

    println!("Batch: {}", result.batch_number);
    println!("State root: {:?}", result.value_hash);
    println!("Commitment: {:?}", result.commitment);
    println!("Proof public input: {:?}", result.proof_public_input);
}
