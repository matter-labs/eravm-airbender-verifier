mod fri;
mod setup_download;
mod snark;
mod statistics;

use airbender_host::SecurityLevel;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use zksync_cli_utils::BatchInputFile;

pub use crate::fri::{
    default_fri_vk_path, dist_dir, load_vk_from_disk, FriPipeline, FriVerifier, ProveOutput,
    RawFriProof,
};
pub use crate::setup_download::{
    default_trusted_setup_download_url, default_trusted_setup_path,
    download_trusted_setup_if_not_present,
};
pub use crate::snark::{
    SnarkOptions, SnarkPipeline, COMPRESSION_PROOF_FILE_NAME, COMPRESSION_VK_FILE_NAME,
    SNARK_PROOF_FILE_NAME,
};
pub use zkos_wrapper::{
    deserialize_from_file, CompressionProof, CompressionVK, SnarkWrapperProof, SnarkWrapperVK,
};

use crate::fri::{build_runner, load_raw_proof, run_batch, save_raw_proof, FRI_PROOF_FILE_NAME};
use crate::statistics::StatisticsCollector;

// ==============================================================================
// Host Orchestration
// ==============================================================================
//
// The library entrypoints below keep the command behavior intentionally direct.
// Each top-level mode maps to a small loop that resolves inputs, delegates the
// actual proving work to either `fri` or `snark`, and applies the agreed output
// directory conventions.

pub fn run_batches(batch_inputs: &[BatchInputFile], jit: bool) -> Result<()> {
    let runner = build_runner(&dist_dir(), jit)?;

    for batch_input in batch_inputs {
        run_batch(&runner, batch_input.number, &batch_input.path).with_context(|| {
            format!(
                "while attempting to run batch {} from {} in transpiler",
                batch_input.number,
                batch_input.path.display()
            )
        })?;
    }

    Ok(())
}

pub fn prove_batches_fri(
    batch_inputs: &[BatchInputFile],
    worker_threads: Option<usize>,
    output_root: &Path,
    vk_path: &Path,
    security: SecurityLevel,
) -> Result<()> {
    // Host CLI is a dev/debug entry point — generate the FRI VK on the fly
    // if it isn't checked in yet, so a fresh-guest workflow doesn't require
    // the SNARK trusted setup just to FRI-prove a batch.
    let pipeline =
        FriPipeline::new_with_generated_vk(&dist_dir(), vk_path, worker_threads, security)?;
    let mut statistics = StatisticsCollector::default();

    for (index, batch_input) in batch_inputs.iter().enumerate() {
        let proof_artifact = pipeline
            .prove_batch(batch_input.number, &batch_input.path)
            .with_context(|| {
                format!(
                    "while attempting to prove batch {} from {}",
                    batch_input.number,
                    batch_input.path.display()
                )
            })?;

        let output_dir = batch_output_dir(output_root, batch_input.number);
        let proof_path = output_dir.join(FRI_PROOF_FILE_NAME);
        save_raw_proof(&proof_artifact.proof, &proof_path)?;

        statistics.add_sample(proof_artifact.proving_time, proof_artifact.cycles);
        info!(
            batch_number = batch_input.number,
            batch_file = %batch_input.path.display(),
            proof_path = %proof_path.display(),
            completed_batches = index + 1,
            total_batches = batch_inputs.len(),
            "Successfully wrote raw FRI proof"
        );
        statistics.print_stats();
    }

    Ok(())
}

/// Generates the FRI verification key for the current guest binary and
/// writes it to `output_path`, overwriting any previous file. Used by the
/// `gen-vks` host subcommand and the CI VK-check job.
pub fn generate_fri_vk(output_path: &Path, security: SecurityLevel) -> Result<()> {
    if output_path.exists() {
        std::fs::remove_file(output_path).with_context(|| {
            format!(
                "while attempting to remove stale VK at {}",
                output_path.display()
            )
        })?;
    }
    // `FriVerifier::load_or_generate` writes the VK to disk as a side effect
    // when the file is missing; that is exactly the behavior we want here.
    let _ = FriVerifier::load_or_generate(&dist_dir(), output_path, security)?;
    info!(path = %output_path.display(), "Wrote FRI verification key");
    Ok(())
}

/// Derives the SNARK wrapper VK from the trusted setup chain and writes it
/// to `output_path` as JSON. Used by the `gen-vks` host subcommand.
pub fn generate_snark_vk(output_path: &Path, snark_options: &SnarkOptions) -> Result<()> {
    use crate::snark::derive_snark_vk;
    let vk = derive_snark_vk(snark_options).context("while deriving SNARK VK")?;
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("while attempting to create {}", parent.display()))?;
        }
    }
    let path_string = output_path.to_string_lossy().into_owned();
    zkos_wrapper::serialize_to_file(&vk, &path_string)
        .with_context(|| format!("while attempting to write {}", output_path.display()))?;
    info!(path = %output_path.display(), "Wrote SNARK verification key");
    Ok(())
}

pub fn wrap_to_snark(
    proof_files: &[PathBuf],
    output_root: &Path,
    snark_options: &SnarkOptions,
    snark_vk: Option<SnarkWrapperVK>,
) -> Result<()> {
    let mut pipeline = SnarkPipeline::new(snark_options, snark_vk)?;

    for (index, proof_file) in proof_files.iter().enumerate() {
        let raw_proof = load_raw_proof(proof_file)
            .with_context(|| format!("while attempting to load {}", proof_file.display()))?;
        let output_dir = proof_file_output_dir(output_root, proof_file)?;
        pipeline
            .prove_and_save_outcome(raw_proof, &output_dir)
            .with_context(|| {
                format!(
                    "while attempting to wrap raw proof {} into a SNARK",
                    proof_file.display()
                )
            })?;

        info!(
            proof_file = %proof_file.display(),
            output_dir = %output_dir.display(),
            completed_proofs = index + 1,
            total_proofs = proof_files.len(),
            "Successfully generated SNARK proof"
        );
    }

    Ok(())
}

/// Runs wrapper phases 1 and 2 (risc wrapper + compression) on each FRI proof
/// file and writes `compression_proof.json` + `compression_vk.json` per batch.
/// Phase 3 (PLONK SNARK) is **not** run by this process — the intent is to let
/// the caller hand the saved artifacts to a separate `prove-snark-from-compression`
/// process so phase 3 starts on a GPU that no longer holds phase 1/2 buffers.
pub fn wrap_to_compression(
    proof_files: &[PathBuf],
    output_root: &Path,
    snark_options: &SnarkOptions,
) -> Result<()> {
    let mut pipeline = SnarkPipeline::new(snark_options, None)?;

    for (index, proof_file) in proof_files.iter().enumerate() {
        let raw_proof = load_raw_proof(proof_file)
            .with_context(|| format!("while attempting to load {}", proof_file.display()))?;
        let output_dir = proof_file_output_dir(output_root, proof_file)?;
        pipeline
            .prove_compression_and_save(raw_proof, &output_dir)
            .with_context(|| {
                format!(
                    "while attempting to compress raw proof {}",
                    proof_file.display()
                )
            })?;

        info!(
            proof_file = %proof_file.display(),
            output_dir = %output_dir.display(),
            completed_proofs = index + 1,
            total_proofs = proof_files.len(),
            "Successfully generated compression proof"
        );
    }

    Ok(())
}

/// Runs only wrapper phase 3 against a saved `compression_proof.json` and
/// `compression_vk.json` and writes the resulting `snark_proof.json` +
/// `snark_vk.json` into `output_dir`. The pipeline is constructed with both
/// the compression VK and the SNARK VK pre-loaded, so no phase 1/2 GPU work
/// happens in this process — that is the entire point of the split.
pub fn wrap_compression_to_snark(
    compression_proof_path: &Path,
    compression_vk_path: &Path,
    output_dir: &Path,
    snark_options: &SnarkOptions,
    snark_vk: SnarkWrapperVK,
) -> Result<()> {
    let compression_proof: CompressionProof =
        deserialize_from_file(&compression_proof_path.to_string_lossy()).with_context(|| {
            format!(
                "while attempting to load compression proof {}",
                compression_proof_path.display()
            )
        })?;

    let compression_vk: CompressionVK =
        deserialize_from_file(&compression_vk_path.to_string_lossy()).with_context(|| {
            format!(
                "while attempting to load compression VK {}",
                compression_vk_path.display()
            )
        })?;

    let mut pipeline = SnarkPipeline::new_for_snark_only(snark_options, snark_vk, compression_vk)?;
    pipeline
        .prove_snark_from_compression_and_save(compression_proof, output_dir)
        .with_context(|| {
            format!(
                "while attempting to SNARK-wrap compression proof {}",
                compression_proof_path.display()
            )
        })?;

    info!(
        compression_proof = %compression_proof_path.display(),
        output_dir = %output_dir.display(),
        "Successfully generated SNARK proof from compression proof"
    );

    Ok(())
}

fn batch_output_dir(output_root: &Path, batch_number: u64) -> PathBuf {
    output_root.join(format!("batch-{batch_number}"))
}

fn proof_file_output_dir(output_root: &Path, proof_file: &Path) -> Result<PathBuf> {
    // Standard host-exported FRI proofs live under `batch-<n>/fri_proof.json`.
    // Preserve that batch-oriented layout when we wrap those artifacts into
    // SNARKs, so `prove-fri` and `prove-snark` agree on the same output root.
    if let Some(batch_number) = batch_number_from_exported_fri_proof_path(proof_file) {
        return Ok(batch_output_dir(output_root, batch_number));
    }

    let stem = proof_file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context(
            "while attempting to derive an output directory name from the raw proof filename",
        )?;

    Ok(output_root.join(stem))
}

fn batch_number_from_exported_fri_proof_path(proof_file: &Path) -> Option<u64> {
    if proof_file.file_name()? != FRI_PROOF_FILE_NAME {
        return None;
    }

    let parent_name = proof_file.parent()?.file_name()?.to_str()?;
    let batch_number = parent_name.strip_prefix("batch-")?;
    batch_number.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{
        batch_number_from_exported_fri_proof_path, batch_output_dir, proof_file_output_dir,
    };
    use std::path::Path;

    #[test]
    fn batch_output_dir_uses_batch_prefix() {
        let output_dir = batch_output_dir(Path::new("/tmp/output"), 42);
        assert_eq!(output_dir, Path::new("/tmp/output/batch-42"));
    }

    #[test]
    fn proof_file_output_dir_uses_proof_stem() {
        let output_dir = proof_file_output_dir(
            Path::new("/tmp/output"),
            Path::new("/tmp/input/fri-proof.json"),
        )
        .expect("proof stem should be available");
        assert_eq!(output_dir, Path::new("/tmp/output/fri-proof"));
    }

    #[test]
    fn proof_file_output_dir_reuses_batch_directory_for_exported_fri_proof() {
        let output_dir = proof_file_output_dir(
            Path::new("/tmp/output"),
            Path::new("/tmp/input/batch-42/fri_proof.json"),
        )
        .expect("batch directory name should be available");
        assert_eq!(output_dir, Path::new("/tmp/output/batch-42"));
    }

    #[test]
    fn batch_number_from_exported_fri_proof_path_reads_standard_layout() {
        let batch_number = batch_number_from_exported_fri_proof_path(Path::new(
            "/tmp/input/batch-42/fri_proof.json",
        ));
        assert_eq!(batch_number, Some(42));
    }

    #[test]
    fn batch_number_from_exported_fri_proof_path_ignores_nonstandard_layout() {
        let batch_number =
            batch_number_from_exported_fri_proof_path(Path::new("/tmp/input/fri_proof.json"));
        assert_eq!(batch_number, None);
    }
}
