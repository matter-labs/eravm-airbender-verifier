//! Host-side helpers that synthesise inputs the host doesn't currently have a
//! real source for — primarily a `CommitmentInput` for legacy batches whose
//! on-disk dumps lack one. These belong here, and not in the production load
//! path, because the resulting `proof_public_input` is **not**
//! L1-settlement-equivalent; it's only pipeline-equivalent across native,
//! transpiler, and prover.
//!
//! Real production use will require `CommitmentInput` sourced from L1 + the
//! sequencer DB, at which point this module can go away.

use std::path::Path;

use anyhow::{Context, Result};
use zksync_airbender_verifier::types::AirbenderVerifierInput;

use crate::fri::load_verifier_input;

/// Load a legacy batch from disk and synthesize a self-consistent
/// `CommitmentInput`: real blob linear hashes from pubdata, fabricated
/// versioned hashes / opening commitments, zero prev_meta/prev_aux. See
/// `zksync_airbender_verifier::test_utils` module docs.
pub(crate) fn load_with_synthetic_commitment(batch_path: &Path) -> Result<AirbenderVerifierInput> {
    let input = load_verifier_input(batch_path)?;
    zksync_airbender_verifier::test_utils::augment_with_synthetic_commitment(input)
        .context("failed to build synthetic commitment input")
}
