//! Host-side helpers that synthesise inputs the host doesn't currently have a
//! real source for — primarily a `CommitmentInput` for batches that arrive as
//! V1 dumps. These belong here, and not in the production load path, because
//! the resulting `proof_public_input` is **not** L1-settlement-equivalent;
//! it's only pipeline-equivalent across native, transpiler, and prover.
//!
//! Real production use will require `CommitmentInput` sourced from L1 + the
//! sequencer DB, at which point this module can go away.

use std::path::Path;

use anyhow::{Context, Result};
use zksync_airbender_verifier::types::{AirbenderVerifierInput, V2AirbenderVerifierInput};

use crate::fri::load_verifier_input;

/// Load a V1 batch from disk and lift it to V2 using a **synthetic**
/// `CommitmentInput` (real blob linear hashes from pubdata, fabricated
/// versioned hashes / opening commitments, zero prev_meta/prev_aux).
/// See `zksync_airbender_verifier::test_utils` module docs.
pub(crate) fn load_with_synthetic_commitment(
    batch_path: &Path,
) -> Result<V2AirbenderVerifierInput> {
    let v1_input = load_verifier_input(batch_path)?;
    let AirbenderVerifierInput::V1(v1) = v1_input else {
        anyhow::bail!("expected AirbenderVerifierInput::V1");
    };

    zksync_airbender_verifier::test_utils::augment_with_synthetic_commitment(v1)
        .context("failed to build synthetic commitment input")
}
