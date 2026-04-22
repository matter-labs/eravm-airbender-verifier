use crate::fri::RawFriProof;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use zkos_wrapper::{interface, serialize_to_file, BoojumWorker};

// Mirror `zkos-wrapper`'s artifact names so operators can switch between the
// standalone wrapper CLI and the integrated host without translating outputs.
pub(crate) const RISC_WRAPPER_PROOF_FILE_NAME: &str = "risc_wrapper_proof.json";
pub(crate) const RISC_WRAPPER_VK_FILE_NAME: &str = "risc_wrapper_vk.json";
pub(crate) const COMPRESSION_PROOF_FILE_NAME: &str = "compression_proof.json";
pub(crate) const COMPRESSION_VK_FILE_NAME: &str = "compression_vk.json";
pub(crate) const SNARK_PROOF_FILE_NAME: &str = "snark_proof.json";
pub(crate) const SNARK_VK_FILE_NAME: &str = "snark_vk.json";

#[derive(Clone, Debug)]
pub struct SnarkOptions {
    pub worker_threads: Option<usize>,
    pub trusted_setup: Option<PathBuf>,
    pub use_zk: bool,
    pub save_intermediates: bool,
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

    if options.save_intermediates {
        save_wrapper_artifact_pair(
            &risc_wrapper_proof,
            RISC_WRAPPER_PROOF_FILE_NAME,
            &risc_wrapper_vk,
            RISC_WRAPPER_VK_FILE_NAME,
            output_dir,
            "phase 1",
        )
        .context("while attempting to save wrapper phase 1 intermediates")?;
    }

    let (compression_proof, compression_vk) =
        interface::run_phase2_compression(risc_wrapper_proof, risc_wrapper_vk, &worker)
            .context("while attempting to run wrapper phase 2")?;

    if options.save_intermediates {
        save_wrapper_artifact_pair(
            &compression_proof,
            COMPRESSION_PROOF_FILE_NAME,
            &compression_vk,
            COMPRESSION_VK_FILE_NAME,
            output_dir,
            "phase 2",
        )
        .context("while attempting to save wrapper phase 2 intermediates")?;
    }

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

fn save_wrapper_artifact_pair<TProof, TVk>(
    proof: &TProof,
    proof_file_name: &str,
    vk: &TVk,
    vk_file_name: &str,
    output_dir: &Path,
    phase_name: &str,
) -> Result<()>
where
    TProof: serde::Serialize,
    TVk: serde::Serialize,
{
    let proof_path = output_dir.join(proof_file_name);
    save_wrapper_artifact(proof, &proof_path)?;

    let vk_path = output_dir.join(vk_file_name);
    save_wrapper_artifact(vk, &vk_path)?;

    info!(
        phase = phase_name,
        proof_path = %proof_path.display(),
        vk_path = %vk_path.display(),
        "Saved SNARK wrapper intermediate artifacts"
    );

    Ok(())
}
