use crate::fri::{record_proof_metrics, FriVerifier, RawFriProof};
use airbender_host::Proof;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::info;
use zkos_wrapper::{serialize_to_file, SnarkWrapper, SnarkWrapperConfig};
use zksync_prover_metrics::{ProofStatus, ProofType};

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

pub struct SnarkPipeline {
    wrapper: SnarkWrapper,
    /// Optional FRI verifier; only required when the pipeline accepts FRI
    /// proofs from the network (snark-only server mode) and must validate them
    /// before wrapping. Locally generated proofs are already verified by
    /// `FriPipeline`, so this can be left unset.
    fri_verifier: Option<FriVerifier>,
    use_zk: bool,
    save_intermediates: bool,
}

impl SnarkPipeline {
    pub fn new(options: &SnarkOptions) -> Result<Self> {
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
            fri_verifier: None,
            use_zk: options.use_zk,
            save_intermediates: options.save_intermediates,
        })
    }

    /// Attaches a FRI verifier so incoming serialized proofs can be validated
    /// before SNARK wrapping. Required for the snark-only server flow.
    pub fn with_fri_verifier(mut self, verifier: FriVerifier) -> Self {
        self.fri_verifier = Some(verifier);
        self
    }

    /// Decodes a bincode-encoded `Proof` envelope, verifies it against the
    /// attached FRI verifier, and wraps the inner raw proof into a SNARK.
    /// Errors out if no verifier has been attached.
    pub fn decode_and_wrap_snark(
        &mut self,
        batch_number: u32,
        fri_proof_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let verifier = self.fri_verifier.as_ref().context(
            "decode_and_wrap_snark requires a FRI verifier; construct via `with_fri_verifier`",
        )?;
        let (proof, len): (Proof, usize) =
            bincode::serde::decode_from_slice(fri_proof_bytes, bincode::config::standard())
                .context("failed to bincode-decode incoming FRI proof envelope")?;
        if len != fri_proof_bytes.len() {
            anyhow::bail!("incoming FRI proof envelope has trailing bytes");
        }
        verifier
            .verify_envelope(batch_number as u64, &proof)
            .context("incoming FRI proof failed verification")?;
        info!(batch_number, "Verified incoming FRI proof");
        let raw_proof = match proof {
            Proof::Real(real) => real.into_inner(),
            Proof::Dev(_) => {
                anyhow::bail!("received development FRI proof; refusing to wrap into SNARK")
            }
        };
        self.wrap_snark(batch_number, raw_proof)
    }

    /// Wraps a raw FRI proof into a SNARK, records prover metrics, and returns
    /// the JSON-encoded proof + VK bytes ready for transport. Reuses the cached
    /// wrapper setup across calls. Companion to [`Self::prove`], which writes
    /// the same artifacts to disk.
    pub fn wrap_snark(
        &mut self,
        batch_number: u32,
        raw_proof: RawFriProof,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        info!(batch_number, "Starting SNARK wrapping...");
        let started_at = Instant::now();
        let result = (|| {
            let risc_wrapper_proof = self
                .wrapper
                .prove_risc_wrapper(raw_proof)
                .context("while attempting to run wrapper phase 1")?;
            let compression_proof = self
                .wrapper
                .prove_compression(risc_wrapper_proof)
                .context("while attempting to run wrapper phase 2")?;
            let snark_proof = self
                .wrapper
                .prove_snark(compression_proof, self.use_zk)
                .context("while attempting to run wrapper phase 3")?;

            let snark_proof_bytes = serde_json::to_vec(&snark_proof)
                .context("while attempting to JSON-encode the SNARK proof for transport")?;
            let snark_vk = self
                .wrapper
                .snark_vk()
                .context("while attempting to resolve wrapper phase 3 VK")?;
            let snark_vk_bytes = serde_json::to_vec(snark_vk)
                .context("while attempting to JSON-encode the SNARK VK for transport")?;
            Ok::<_, anyhow::Error>((snark_proof_bytes, snark_vk_bytes))
        })();

        let status = if result.is_ok() {
            ProofStatus::Success
        } else {
            ProofStatus::Failure
        };
        record_proof_metrics(batch_number, ProofType::Snark, status, started_at.elapsed());

        let (snark_proof, snark_vk) = result.map_err(|err| err.context("SNARK wrap failed"))?;
        info!(
            batch_number,
            snark_proof_bytes = snark_proof.len(),
            snark_vk_bytes = snark_vk.len(),
            "SNARK wrap complete"
        );
        Ok((snark_proof, snark_vk))
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
