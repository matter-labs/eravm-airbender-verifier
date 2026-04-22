mod fri;
mod snark;
mod statistics;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use zksync_cli_utils::{load_batch_words, BatchInputFile};

pub use crate::snark::SnarkOptions;

use crate::fri::{
    build_runner, load_raw_proof, run_batch, save_raw_proof, FriPipeline, FRI_PROOF_FILE_NAME,
};
use crate::snark::prove_snark;
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
    let runner = build_runner(jit)?;

    for batch_input in batch_inputs {
        let input_words = load_batch_words(batch_input).with_context(|| {
            format!(
                "while attempting to load batch {} from {}",
                batch_input.number,
                batch_input.path.display()
            )
        })?;
        run_batch(&runner, batch_input.number, &input_words).with_context(|| {
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
) -> Result<()> {
    let pipeline = FriPipeline::new(worker_threads)?;
    let mut statistics = StatisticsCollector::default();

    for (index, batch_input) in batch_inputs.iter().enumerate() {
        let input_words = load_batch_words(batch_input).with_context(|| {
            format!(
                "while attempting to load batch {} from {}",
                batch_input.number,
                batch_input.path.display()
            )
        })?;
        let proof_artifact = pipeline
            .prove_batch(batch_input.number, &input_words)
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

pub fn wrap_to_snark(
    proof_files: &[PathBuf],
    output_root: &Path,
    snark_options: &SnarkOptions,
) -> Result<()> {
    for (index, proof_file) in proof_files.iter().enumerate() {
        let raw_proof = load_raw_proof(proof_file)
            .with_context(|| format!("while attempting to load {}", proof_file.display()))?;
        let output_dir = proof_file_output_dir(output_root, proof_file)?;
        prove_snark(raw_proof, snark_options, &output_dir).with_context(|| {
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
        let batch_number =
            batch_number_from_exported_fri_proof_path(Path::new("/tmp/input/batch-42/fri_proof.json"));
        assert_eq!(batch_number, Some(42));
    }

    #[test]
    fn batch_number_from_exported_fri_proof_path_ignores_nonstandard_layout() {
        let batch_number =
            batch_number_from_exported_fri_proof_path(Path::new("/tmp/input/fri_proof.json"));
        assert_eq!(batch_number, None);
    }
}
