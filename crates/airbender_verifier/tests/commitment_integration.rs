//! Integration test: load a real batch, run verification, check commitment output.
//!
//! Requires the test batch to be fetched via Git LFS:
//!   ./scripts/fetch_lfs_batches.sh <BATCH_NUMBER>.bin.gz

use std::path::Path;

use zksync_airbender_verifier::test_utils::crosscheck_commitment;
use zksync_airbender_verifier::Verify;
use zksync_cli_utils::{load_batch, BatchInputFile};

fn run_commitment_test(batch_number: u64) {
    let batch_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../testdata/era_mainnet_batches/binary/{batch_number}.bin.gz"
    ));

    if !batch_path.exists() {
        eprintln!(
            "Skipping test for batch {batch_number}: batch file not found at {}. Run: ./scripts/fetch_lfs_batches.sh {batch_number}.bin.gz",
            batch_path.display()
        );
        return;
    }

    let file_size = std::fs::metadata(&batch_path).unwrap().len();
    if file_size < 1000 {
        eprintln!(
            "Skipping test for batch {batch_number}: batch file appears to be a Git LFS pointer ({file_size} bytes)"
        );
        return;
    }

    // The corpus ships with a baked-in synthetic `commitment_input` (fake
    // blob/prev-batch data — see `test_utils` module docs), so we can verify
    // directly. Not L1-settlement-equivalent.
    let v1 = load_batch(&BatchInputFile {
        number: batch_number,
        path: batch_path.clone(),
    })
    .expect("failed to load batch")
    .into_v1()
    .expect("expected V1 payload");

    println!(
        "Running verification for batch {}...",
        v1.l1_batch_env.number
    );
    let result = v1.clone().verify().expect("verification failed");
    crosscheck_commitment(&result, &v1).expect("crosscheck failed");

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

#[test]
fn test_batch_506093_commitment() {
    run_commitment_test(506093);
}

#[test]
fn test_batch_506169_commitment() {
    run_commitment_test(506169);
}
