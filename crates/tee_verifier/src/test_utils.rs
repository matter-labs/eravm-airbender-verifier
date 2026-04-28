//! Test utilities for generating a **synthetic, self-consistent** `CommitmentInput`.
//!
//! The values produced here do **not** match what the sequencer / L1 would supply for
//! a real batch:
//! - `prev_meta_hash` / `prev_aux_hash` are forced to zero, so the recomputed
//!   `prev_batch_commitment` trivially matches the binding check (`lib.rs` binding
//!   branch is exercised but cannot catch a real mainnet mismatch here).
//! - `blob_versioned_hashes` are fabricated from `keccak([i] || b"test_versioned_hash")`
//!   with version byte `0x01` — they are not KZG-derived EIP-4844 versioned hashes.
//! - `blob_opening_commitments` are derived from the fake versioned hashes, so the
//!   blob opening check is self-consistent but does not prove mainnet compatibility.
//!
//! In production, `CommitmentInput` comes from the sequencer (prev_batch_commitment
//! from DB, blob data from L1 transactions). Use this only to exercise the verifier
//! pipeline end-to-end; for byte-for-byte L1 equivalence, pin values against real
//! sequencer output.

use anyhow::Context;
use zksync_types::{commitment::BlobHash, web3::keccak256, H256};

use crate::commitment::{compute_commitment, compute_pass_through_data_hash};
use crate::types::{
    CommitmentInput, V1TeeVerifierInput, V2TeeVerifierInput, TOTAL_BLOBS_IN_COMMITMENT,
};

/// Augment a V1 input with a **synthetic** `CommitmentInput` so that the verifier
/// pipeline can be exercised end-to-end without real sequencer/L1 inputs.
///
/// What's produced:
/// - `blob_hashes` carry real linear hashes (derived from the VM's pubdata) and
///   fabricated opening commitments derived from synthetic versioned hashes.
/// - `blob_versioned_hashes` are fabricated deterministically so the blob
///   opening check passes.
/// - `prev_meta_hash` / `prev_aux_hash` are forced to zero, and `prev_batch_commitment`
///   is derived from those zeros so the binding check is satisfied tautologically.
///
/// See the module-level docs for why this is **not** L1-settlement-equivalent.
/// Only use this for testing the verifier pipeline.
pub fn augment_with_synthetic_commitment(
    v1: V1TeeVerifierInput,
) -> anyhow::Result<V2TeeVerifierInput> {
    // Run the VM once to obtain pubdata; the resulting state is dropped because
    // we still need a fresh execution after `commitment_input` is filled in.
    let preliminary = crate::execute(v1.clone())?;
    let pubdata = preliminary.pubdata();
    let (blob_versioned_hashes, blob_hashes) = compute_blob_opening_data(pubdata);

    // Compute a self-consistent prev_batch_commitment from old_root_hash and
    // enumeration_index so that the prev_batch_commitment binding check passes.
    // In production these come from L1; for tests we derive them from the V1 input.
    let old_root_hash = v1.l1_batch_env.previous_batch_hash.context(
        "previous_batch_hash is missing — genesis batches are not supported by this helper",
    )?;
    let enumeration_index = v1.merkle_paths.next_enumeration_index();
    let prev_meta_hash = H256::zero();
    let prev_aux_hash = H256::zero();
    let prev_passthrough = compute_pass_through_data_hash(enumeration_index, old_root_hash);
    let prev_batch_commitment = compute_commitment(prev_passthrough, prev_meta_hash, prev_aux_hash);

    Ok(V2TeeVerifierInput {
        v1,
        commitment_input: CommitmentInput {
            prev_batch_commitment,
            prev_meta_hash,
            prev_aux_hash,
            blob_hashes,
            blob_versioned_hashes,
        },
    })
}

/// Compute self-consistent blob versioned hashes and `BlobHash` (linear +
/// opening commitment) pairs for testing.
///
/// In production, versioned hashes come from L1 blob transactions and opening
/// commitments are computed by the sequencer. For tests, we derive linear
/// hashes from the VM's pubdata, fabricate deterministic versioned hashes,
/// and call the same [`crate::commitment::compute_blob_opening_commitment`]
/// the verifier uses, so the resulting commitments pass the verifier's check
/// by construction.
pub fn compute_blob_opening_data(pubdata: &[u8]) -> (Vec<H256>, Vec<BlobHash>) {
    let linear_hashes = crate::commitment::compute_blob_linear_hashes(pubdata);
    let mut versioned_hashes = vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT];
    let mut blob_hashes = vec![BlobHash::default(); TOTAL_BLOBS_IN_COMMITMENT];

    for i in 0..TOTAL_BLOBS_IN_COMMITMENT {
        if linear_hashes[i] == H256::zero() {
            continue;
        }
        let Some(blob) = crate::commitment::padded_blob_for(pubdata, i) else {
            continue;
        };

        // Deterministic fake versioned hash.
        let mut vh = H256(keccak256(
            &[&[i as u8][..], b"test_versioned_hash"].concat(),
        ));
        vh.0[0] = 0x01; // EIP-4844 version byte
        versioned_hashes[i] = vh;

        let commitment = crate::commitment::compute_blob_opening_commitment(
            &blob,
            versioned_hashes[i],
            linear_hashes[i],
        );
        blob_hashes[i] = BlobHash {
            linear_hash: linear_hashes[i],
            commitment,
        };
    }

    (versioned_hashes, blob_hashes)
}
