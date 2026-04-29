use crate::fri::RawFriProof;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use zkos_wrapper::{serialize_to_file, SnarkWrapper, SnarkWrapperConfig};

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
// API: give it raw Airbender proofs and output directories, and it produces the
// final SNARK artifacts. Owning the stateful wrapper here lets one `prove-snark`
// invocation reuse setup and VK caches across every proof file it wraps.

pub(crate) struct SnarkPipeline {
    wrapper: SnarkWrapper,
    use_zk: bool,
    save_intermediates: bool,
}

impl SnarkPipeline {
    pub(crate) fn new(options: &SnarkOptions) -> Result<Self> {
        let wrapper = SnarkWrapper::new(SnarkWrapperConfig {
            bin: None,
            text: None,
            trusted_setup: options.trusted_setup.clone(),
            threads: options.worker_threads,
            risc_wrapper_vk: None,
            compression_vk: None,
            snark_vk: None,
        })
        .context("while attempting to initialize the SNARK wrapper")?;

        Ok(Self {
            wrapper,
            use_zk: options.use_zk,
            save_intermediates: options.save_intermediates,
        })
    }

    pub(crate) fn prove(&mut self, raw_proof: RawFriProof, output_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("while attempting to create {}", output_dir.display()))?;

        info!(
            output_dir = %output_dir.display(),
            "Starting SNARK wrapper pipeline with the built-in recursion verifier binary"
        );

        let risc_wrapper_proof = self
            .wrapper
            .prove_risc_wrapper(raw_proof)
            .context("while attempting to run wrapper phase 1")?;

        if self.save_intermediates {
            let risc_wrapper_vk = self
                .wrapper
                .risc_wrapper_vk()
                .context("while attempting to resolve wrapper phase 1 VK")?;
            save_wrapper_artifact_pair(
                &risc_wrapper_proof,
                RISC_WRAPPER_PROOF_FILE_NAME,
                risc_wrapper_vk,
                RISC_WRAPPER_VK_FILE_NAME,
                output_dir,
                "phase 1",
            )
            .context("while attempting to save wrapper phase 1 intermediates")?;
        }

        let compression_proof = self
            .wrapper
            .prove_compression(risc_wrapper_proof)
            .context("while attempting to run wrapper phase 2")?;

        if self.save_intermediates {
            let compression_vk = self
                .wrapper
                .compression_vk()
                .context("while attempting to resolve wrapper phase 2 VK")?;
            save_wrapper_artifact_pair(
                &compression_proof,
                COMPRESSION_PROOF_FILE_NAME,
                compression_vk,
                COMPRESSION_VK_FILE_NAME,
                output_dir,
                "phase 2",
            )
            .context("while attempting to save wrapper phase 2 intermediates")?;
        }

        let snark_proof = self
            .wrapper
            .prove_snark(compression_proof, self.use_zk)
            .context("while attempting to run wrapper phase 3")?;

        let proof_path = output_dir.join(SNARK_PROOF_FILE_NAME);
        save_wrapper_artifact(&snark_proof, &proof_path)?;

        let vk_path = output_dir.join(SNARK_VK_FILE_NAME);
        save_wrapper_artifact(
            self.wrapper
                .snark_vk()
                .context("while attempting to resolve wrapper phase 3 VK")?,
            &vk_path,
        )?;

        info!(
            proof_path = %proof_path.display(),
            vk_path = %vk_path.display(),
            "Finished SNARK wrapper pipeline"
        );

        Ok(())
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
