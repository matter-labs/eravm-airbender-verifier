//! Integration test for the native feature-extraction half of the harness
//! (tracer + vm_compare run_fast_vm_with_tracer + batch-level features), run
//! against a real mainnet batch. `#[ignore]` because it needs the Git LFS
//! corpus — fetch it first:
//!
//! ```sh
//! ./scripts/fetch_lfs_batches.sh 506077.bin.gz
//! cargo test -p zksync_cycle_model --test native_features -- --ignored --nocapture
//! ```
use std::path::PathBuf;

use zksync_cli_utils::{load_batch, resolve_batch_inputs};
use zksync_cycle_model::{extract_features, FeatureId};

#[test]
#[ignore = "requires the LFS batch corpus (fetch 506077.bin.gz)"]
fn extract_features_on_real_batch() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/era_mainnet_batches/binary")
        .canonicalize()
        .expect("batches dir must exist");
    let inputs = resolve_batch_inputs(&dir, Some(&[PathBuf::from("506077.bin.gz")]), false)
        .expect("resolve batch");
    let envelope = load_batch(&inputs[0]).expect("load batch 506077");
    let v1 = envelope.into_v1().expect("v1 payload");

    let features = extract_features(&v1).expect("feature extraction");

    let total: u64 = features.counts.values().sum();
    assert!(total > 0, "a real batch must execute opcodes");
    assert!(
        features.get(FeatureId::TransactionCount) > 0,
        "batch must contain transactions"
    );
    assert!(
        features.get(FeatureId::MerkleLeafCount) > 0,
        "batch must touch storage slots"
    );

    // Human-readable dump so the calibration engineer can eyeball the vector.
    println!("506077 feature vector:");
    for (id, n) in &features.counts {
        println!("  {id:?}: {n}");
    }
}
