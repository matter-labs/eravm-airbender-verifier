use crate::fri::RawFriProof;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use zkos_wrapper::{
    calculate_verification_key_hash, deserialize_from_file, serialize_to_file, CompressionVK,
    RiscWrapperVK, SnarkWrapper, SnarkWrapperConfig, SnarkWrapperVK,
};

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
    /// Directory holding pre-generated VK JSON files using the same names that
    /// `generate_vks` writes (`risc_wrapper_vk.json`, `compression_vk.json`,
    /// `snark_vk.json`). When set, `SnarkPipeline::new` reads any of those that
    /// exist and feeds them to `SnarkWrapperConfig`, skipping the multi-minute
    /// VK derivation; missing files are computed and written back so a second
    /// process start sees the full cache.
    pub vk_cache_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct GenerateVkOptions {
    pub worker_threads: Option<usize>,
    pub trusted_setup: Option<PathBuf>,
}

// ==============================================================================
// Verification Key Generation
// ==============================================================================
//
// VK generation follows the same setup chain that proving relies on, but stops
// after each phase produces its key. Reusing `SnarkWrapper` keeps the artifact
// names and key derivation in sync with `prove-snark` so operators can publish
// VKs once and trust them across runs.

pub(crate) fn generate_vks(output_dir: &Path, options: &GenerateVkOptions) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("while attempting to create {}", output_dir.display()))?;

    let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
        bin: None,
        text: None,
        trusted_setup: options.trusted_setup.clone(),
        threads: options.worker_threads,
        risc_wrapper_vk: None,
        compression_vk: None,
        snark_vk: None,
    })
    .context("while attempting to initialize the SNARK wrapper")?;

    info!(
        output_dir = %output_dir.display(),
        "Generating SNARK wrapper verification keys"
    );

    let risc_wrapper_vk_path = output_dir.join(RISC_WRAPPER_VK_FILE_NAME);
    save_wrapper_artifact(
        wrapper
            .risc_wrapper_vk()
            .context("while attempting to resolve wrapper phase 1 VK")?,
        &risc_wrapper_vk_path,
    )?;
    info!(path = %risc_wrapper_vk_path.display(), "Saved RISC wrapper VK");

    let compression_vk_path = output_dir.join(COMPRESSION_VK_FILE_NAME);
    save_wrapper_artifact(
        wrapper
            .compression_vk()
            .context("while attempting to resolve wrapper phase 2 VK")?,
        &compression_vk_path,
    )?;
    info!(path = %compression_vk_path.display(), "Saved compression VK");

    let snark_vk = wrapper
        .snark_vk()
        .context("while attempting to resolve wrapper phase 3 VK")?
        .clone();
    let snark_vk_path = output_dir.join(SNARK_VK_FILE_NAME);
    save_wrapper_artifact(&snark_vk, &snark_vk_path)?;
    info!(path = %snark_vk_path.display(), "Saved SNARK VK");

    let vk_hash = calculate_verification_key_hash(snark_vk);
    info!(?vk_hash, "SNARK VK hash");

    Ok(())
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
    use_zk: bool,
    save_intermediates: bool,
}

impl SnarkPipeline {
    pub fn new(options: &SnarkOptions) -> Result<Self> {
        let (risc_wrapper_vk, compression_vk, snark_vk) =
            load_cached_vks(options.vk_cache_dir.as_deref())?;

        let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
            bin: None,
            text: None,
            trusted_setup: options.trusted_setup.clone(),
            threads: options.worker_threads,
            risc_wrapper_vk,
            compression_vk,
            snark_vk,
        })
        .context("while attempting to initialize the SNARK wrapper")?;

        // For any VK that wasn't on disk, compute it now and write it back so
        // the next process start picks it up from the cache instead of redoing
        // the multi-minute derivation. Order matters: the wrapper computes
        // each phase lazily and earlier-phase VKs are inputs to later ones.
        if let Some(dir) = options.vk_cache_dir.as_deref() {
            populate_vk_cache(&mut wrapper, dir)
                .context("while attempting to populate the SNARK VK cache")?;
        }

        Ok(Self {
            wrapper,
            use_zk: options.use_zk,
            save_intermediates: options.save_intermediates,
        })
    }

    /// Wrap a raw FRI proof into a SNARK and return the serialized SNARK proof
    /// bytes, without writing any artifacts to disk. Suitable for a streaming
    /// server pipeline where the SNARK proof is forwarded over the network.
    pub fn wrap_proof_to_bytes(&mut self, raw_proof: RawFriProof) -> Result<Vec<u8>> {
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
        serde_json::to_vec(&snark_proof).context("while attempting to serialize SNARK proof")
    }

    pub fn prove(&mut self, raw_proof: RawFriProof, output_dir: &Path) -> Result<()> {
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

fn load_cached_vks(
    dir: Option<&Path>,
) -> Result<(
    Option<RiscWrapperVK>,
    Option<CompressionVK>,
    Option<SnarkWrapperVK>,
)> {
    let Some(dir) = dir else {
        return Ok((None, None, None));
    };

    Ok((
        load_optional_vk::<RiscWrapperVK>(&dir.join(RISC_WRAPPER_VK_FILE_NAME))?,
        load_optional_vk::<CompressionVK>(&dir.join(COMPRESSION_VK_FILE_NAME))?,
        load_optional_vk::<SnarkWrapperVK>(&dir.join(SNARK_VK_FILE_NAME))?,
    ))
}

fn load_optional_vk<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let path_string = path.to_string_lossy().into_owned();
    let vk = deserialize_from_file::<T>(&path_string)
        .with_context(|| format!("while attempting to load cached VK from {}", path.display()))?;
    info!(path = %path.display(), "Loaded cached SNARK wrapper VK");
    Ok(Some(vk))
}

/// Eagerly walk the wrapper through every VK derivation, writing any that
/// weren't already present in the cache directory. Each `*_vk()` accessor on
/// the wrapper is a no-op when the VK is already known (loaded or computed).
fn populate_vk_cache(wrapper: &mut SnarkWrapper, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("while attempting to create {}", dir.display()))?;

    let risc_wrapper_path = dir.join(RISC_WRAPPER_VK_FILE_NAME);
    if !risc_wrapper_path.exists() {
        let vk = wrapper
            .risc_wrapper_vk()
            .context("while attempting to compute wrapper phase 1 VK")?;
        save_wrapper_artifact(vk, &risc_wrapper_path)?;
        info!(path = %risc_wrapper_path.display(), "Cached RISC wrapper VK");
    }

    let compression_path = dir.join(COMPRESSION_VK_FILE_NAME);
    if !compression_path.exists() {
        let vk = wrapper
            .compression_vk()
            .context("while attempting to compute wrapper phase 2 VK")?;
        save_wrapper_artifact(vk, &compression_path)?;
        info!(path = %compression_path.display(), "Cached compression VK");
    }

    let snark_path = dir.join(SNARK_VK_FILE_NAME);
    if !snark_path.exists() {
        let vk = wrapper
            .snark_vk()
            .context("while attempting to compute wrapper phase 3 VK")?
            .clone();
        save_wrapper_artifact(&vk, &snark_path)?;
        let vk_hash = calculate_verification_key_hash(vk);
        info!(path = %snark_path.display(), ?vk_hash, "Cached SNARK VK");
    }

    Ok(())
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
