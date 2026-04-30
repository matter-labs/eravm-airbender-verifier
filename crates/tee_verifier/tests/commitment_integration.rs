//! Integration test: load a real batch, run verification, check commitment output.
//!
//! Requires the test batch to be fetched via Git LFS:
//!   ./scripts/fetch_lfs_batches.sh 506093.bin.gz

use std::path::Path;

use zksync_cli_utils::{load_batch, BatchInputFile};
use zksync_tee_verifier::test_utils::{augment_with_synthetic_commitment, crosscheck_commitment};
use zksync_tee_verifier::types::TeeVerifierInput;
use zksync_tee_verifier::Verify;

#[test]
fn test_batch_506093_commitment() {
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

    let input = load_batch(&BatchInputFile {
        number: BATCH_NUMBER,
        path: batch_path.clone(),
    })
    .expect("failed to load batch");
    let TeeVerifierInput::V1(input) = input else {
        panic!("expected TeeVerifierInput::V1");
    };

    println!(
        "Running verification for batch {}...",
        input.l1_batch_env.number
    );
    // Synthesize a self-consistent V2 input (fake blob/prev-batch data — see
    // `test_utils` module docs) and run the production entry point.
    let v2 = augment_with_synthetic_commitment(input).expect("failed to build V2 input");
    let result = v2.clone().verify().expect("verification failed");
    crosscheck_commitment(&result, &v2).expect("crosscheck failed");

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
