//! Test utilities for generating self-consistent `CommitmentInput` from batch data.
//!
//! In production, `CommitmentInput` comes from the sequencer (prev_batch_commitment
//! from DB, blob data from L1 transactions). For tests, we compute everything from
//! the VM execution output.

use zksync_types::{web3::keccak256, H256};

use crate::commitment::{
    compute_commitment, compute_pass_through_data_hash, ZK_SYNC_BYTES_PER_BLOB,
};
use crate::types::{
    CommitmentInput, V1TeeVerifierInput, V2TeeVerifierInput, TOTAL_BLOBS_IN_COMMITMENT,
};

/// Build a `V2TeeVerifierInput` from a V1 input by running a preliminary
/// verification to obtain pubdata, then computing real blob data.
pub fn v1_to_v2_with_real_blobs(v1: V1TeeVerifierInput) -> anyhow::Result<V2TeeVerifierInput> {
    // Run full verification without blob checks to get pubdata.
    let preliminary = crate::execute_for_pubdata(v1.clone())?;
    let pubdata = preliminary.pubdata_input.as_deref().unwrap_or(&[]);
    let blob_linear_hashes = compute_blob_linear_hashes(pubdata);
    let (blob_versioned_hashes, blob_opening_commitments) =
        compute_blob_opening_data(pubdata, &blob_linear_hashes);

    // Compute a self-consistent prev_batch_commitment from old_root_hash and
    // enumeration_index so that the prev_batch_commitment binding check passes.
    // In production these come from L1; for tests we derive them from the V1 input.
    let old_root_hash = v1.l1_batch_env.previous_batch_hash.unwrap();
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
            blob_linear_hashes,
            blob_versioned_hashes,
            blob_opening_commitments,
        },
    })
}

/// Compute blob linear hashes from pubdata: keccak256 of each blob-sized chunk.
pub fn compute_blob_linear_hashes(pubdata: &[u8]) -> Vec<H256> {
    let mut result = vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT];
    if pubdata.is_empty() {
        return result;
    }
    for (i, slot) in result.iter_mut().enumerate() {
        let start = i * ZK_SYNC_BYTES_PER_BLOB;
        if start >= pubdata.len() {
            break;
        }
        let end = ((i + 1) * ZK_SYNC_BYTES_PER_BLOB).min(pubdata.len());
        let chunk = &pubdata[start..end];
        if chunk.len() == ZK_SYNC_BYTES_PER_BLOB {
            *slot = H256(keccak256(chunk));
        } else {
            let mut padded = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
            padded[..chunk.len()].copy_from_slice(chunk);
            *slot = H256(keccak256(&padded));
        }
    }
    result
}

/// Compute self-consistent blob versioned hashes and opening commitments for testing.
///
/// In production, versioned hashes come from L1 blob transactions. For tests, we
/// generate deterministic fake versioned hashes and compute the matching opening
/// commitments via BLS12-381 polynomial evaluation (same code the guest verifies).
pub fn compute_blob_opening_data(pubdata: &[u8], linear_hashes: &[H256]) -> (Vec<H256>, Vec<H256>) {
    use ark_bls12_381::Fr as Bls12_381Fr;
    use ark_ff::{BigInteger, PrimeField, Zero};

    let mut versioned_hashes = vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT];
    let mut opening_commitments = vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT];

    if pubdata.is_empty() {
        return (versioned_hashes, opening_commitments);
    }

    let num_blobs = pubdata.len().div_ceil(ZK_SYNC_BYTES_PER_BLOB);

    for i in 0..num_blobs.min(TOTAL_BLOBS_IN_COMMITMENT) {
        if linear_hashes[i] == H256::zero() {
            continue;
        }

        // Deterministic fake versioned hash.
        let mut vh = H256(keccak256(
            &[&[i as u8][..], b"test_versioned_hash"].concat(),
        ));
        vh.0[0] = 0x01; // EIP-4844 version byte
        versioned_hashes[i] = vh;

        // Get blob data.
        let start = i * ZK_SYNC_BYTES_PER_BLOB;
        let end = ((i + 1) * ZK_SYNC_BYTES_PER_BLOB).min(pubdata.len());
        let chunk = &pubdata[start..end];
        let blob_data = if chunk.len() == ZK_SYNC_BYTES_PER_BLOB {
            chunk.to_vec()
        } else {
            let mut padded = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
            padded[..chunk.len()].copy_from_slice(chunk);
            padded
        };

        // Parse polynomial.
        let poly: Vec<Bls12_381Fr> = blob_data
            .chunks(31)
            .rev()
            .map(|c| {
                let mut buf = [0u8; 32];
                buf[..c.len()].copy_from_slice(c);
                Bls12_381Fr::from_le_bytes_mod_order(&buf)
            })
            .collect();

        // Evaluation point.
        let eval_hash =
            keccak256(&[linear_hashes[i].as_bytes(), versioned_hashes[i].as_bytes()].concat());
        let mut eval_bytes = [0u8; 32];
        eval_bytes[16..32].copy_from_slice(&eval_hash[16..32]);
        let eval_point = Bls12_381Fr::from_be_bytes_mod_order(&eval_bytes);

        // Horner's rule.
        let mut opening_value = Bls12_381Fr::zero();
        for coeff in poly.iter().rev() {
            opening_value *= eval_point;
            opening_value += coeff;
        }

        // Serialize.
        let ov_bytes: [u8; 32] = opening_value
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("32 bytes");

        // output_hash = keccak256(versioned_hash || eval_point_truncated || opening_value)
        let mut preimage = Vec::with_capacity(80);
        preimage.extend_from_slice(vh.as_bytes());
        preimage.extend_from_slice(&eval_hash[16..32]);
        preimage.extend_from_slice(&ov_bytes);
        opening_commitments[i] = H256(keccak256(&preimage));
    }

    (versioned_hashes, opening_commitments)
}
