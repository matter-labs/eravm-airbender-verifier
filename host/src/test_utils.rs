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
use zksync_tee_verifier::types::TeeVerifierInput;

use crate::fri::load_verifier_input;

/// Load a legacy batch from disk and synthesize a self-consistent
/// `CommitmentInput`: real blob linear hashes from pubdata, fabricated
/// versioned hashes / opening commitments, zero prev_meta/prev_aux. See
/// `zksync_tee_verifier::test_utils` module docs.
///
/// Returns the wire-shape enum so callers can hand it straight to the prover
/// (the guest reads `TeeVerifierInput`).
pub(crate) fn load_with_synthetic_commitment(batch_path: &Path) -> Result<TeeVerifierInput> {
    let v1 = load_verifier_input(batch_path)?.into_v1()?;
    let augmented = zksync_tee_verifier::test_utils::augment_with_synthetic_commitment(v1)
        .context("failed to build synthetic commitment input")?;
    Ok(TeeVerifierInput::V1(augmented))
}
