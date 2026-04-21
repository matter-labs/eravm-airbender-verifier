use crate::fri::RawFriProof;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use zkos_wrapper::{interface, serialize_to_file, BoojumWorker};

pub(crate) const SNARK_PROOF_FILE_NAME: &str = "snark_proof.json";
pub(crate) const SNARK_VK_FILE_NAME: &str = "snark_vk.json";

#[derive(Clone, Debug)]
pub struct SnarkOptions {
    pub worker_threads: Option<usize>,
    pub trusted_setup: Option<PathBuf>,
    pub use_zk: bool,
}

// ==============================================================================
// SNARK Wrapper Pipeline
// ==============================================================================
//
// The host intentionally treats the wrapper as a separate module with a narrow
// API: give it a raw Airbender proof and an output directory, and it produces
// the final SNARK artifacts. This keeps the rest of the host decoupled from the
// wrapper's intermediate proof types.

pub(crate) fn prove_snark(
    raw_proof: RawFriProof,
    options: &SnarkOptions,
    output_dir: &Path,
) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("while attempting to create {}", output_dir.display()))?;

    let worker = create_boojum_worker(options.worker_threads);
    let default_binary = None;
    let default_text = None;

    info!(
        output_dir = %output_dir.display(),
        "Starting SNARK wrapper pipeline with the built-in recursion verifier binary"
    );

    // TODO(codex): Cache wrapper setup data across proofs if repeated setup cost
    // becomes material for production throughput.
    let (risc_wrapper_proof, risc_wrapper_vk) =
        interface::run_phase1_risc_wrapper(raw_proof, &default_binary, &default_text, &worker)
            .context("while attempting to run wrapper phase 1")?;

    let (compression_proof, compression_vk) =
        interface::run_phase2_compression(risc_wrapper_proof, risc_wrapper_vk, &worker)
            .context("while attempting to run wrapper phase 2")?;

    let (snark_proof, snark_vk) = interface::run_phase3_snark(
        compression_proof,
        compression_vk,
        &options.trusted_setup,
        options.use_zk,
    )
    .context("while attempting to run wrapper phase 3")?;

    let proof_path = output_dir.join(SNARK_PROOF_FILE_NAME);
    save_wrapper_artifact(&snark_proof, &proof_path)?;

    let vk_path = output_dir.join(SNARK_VK_FILE_NAME);
    save_wrapper_artifact(&snark_vk, &vk_path)?;

    info!(
        proof_path = %proof_path.display(),
        vk_path = %vk_path.display(),
        "Finished SNARK wrapper pipeline"
    );

    Ok(())
}

fn create_boojum_worker(worker_threads: Option<usize>) -> BoojumWorker {
    match worker_threads {
        Some(worker_threads) => BoojumWorker::new_with_num_threads(worker_threads),
        None => BoojumWorker::new(),
    }
}

fn save_wrapper_artifact<T: serde::Serialize>(artifact: &T, path: &Path) -> Result<()> {
    let path_string = path.to_string_lossy().into_owned();
    serialize_to_file(artifact, &path_string)
        .with_context(|| format!("while attempting to serialize {}", path.display()))
}
