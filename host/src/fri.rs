use airbender_host::{
    GpuProver, Program, Proof, Prover, ProverLevel, RealVerifier, Runner, TranspilerRunner,
    VerificationKey, VerificationRequest, Verifier,
};
use anyhow::{Context, Result};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;

/// The guest returns `[u32; 8]` — the proof public input hash.
/// We no longer check against a fixed expected output; any non-zero output
/// indicates successful execution + commitment computation.
/// The actual value is batch-specific and verified by L1 against stored commitments.
pub(crate) const FRI_PROOF_FILE_NAME: &str = "fri_proof.json";

pub(crate) type RawFriProof = airbender_host::raw::UnrolledProgramProof;

pub(crate) struct FriProofArtifact {
    pub(crate) proof: RawFriProof,
    pub(crate) proving_time: Duration,
    pub(crate) cycles: u64,
}

// ==============================================================================
// FRI Pipeline
// ==============================================================================
//
// This module keeps all Airbender-specific behavior in one place so the rest of
// the host can talk in terms of "run batch", "prove batch", and "load/save raw
// proof" without needing to know how the guest program, GPU prover, or VK cache
// are assembled.

pub(crate) struct FriPipeline {
    prover: GpuProver,
    verifier: RealVerifier,
    vk: VerificationKey,
}

impl FriPipeline {
    pub(crate) fn new(worker_threads: Option<usize>) -> Result<Self> {
        let program =
            Program::load(dist_dir()).context("while attempting to load guest program")?;
        let verifier = program
            .real_verifier(ProverLevel::RecursionUnified)
            .build()
            .context("while attempting to build real verifier")?;

        let cache_path = vk_cache_path(&program)
            .context("while attempting to resolve verification key cache path")?;
        let vk = load_or_generate_vk(&verifier, &cache_path).with_context(|| {
            format!(
                "while attempting to prepare verification key cache {}",
                cache_path.display()
            )
        })?;

        let mut prover = program
            .gpu_prover()
            .with_level(ProverLevel::RecursionUnified);
        if let Some(worker_threads) = worker_threads {
            prover = prover.with_worker_threads(worker_threads);
        }

        let prover = prover
            .build()
            .context("while attempting to build GPU prover")?;

        Ok(Self {
            prover,
            verifier,
            vk,
        })
    }

    pub(crate) fn prove_batch(
        &self,
        batch_number: u64,
        input_words: &[u32],
    ) -> Result<FriProofArtifact> {
        let proving_started_at = Instant::now();
        let prove_result = self.prover.prove(input_words).with_context(|| {
            format!("while attempting to generate proof for batch {batch_number}")
        })?;
        let proving_time = proving_started_at.elapsed();
        let cycles = prove_result.cycles;
        let output = prove_result.receipt.output;

        info!(
            batch_number,
            cycles,
            proving_time_secs = proving_time.as_secs_f64(),
            ?output,
            "Finished FRI proof generation"
        );

        if output == [0u32; 8] {
            anyhow::bail!(
                "batch {batch_number} proof returned zero output — verification or commitment failed"
            );
        }

        self.verifier
            .verify(
                &prove_result.proof,
                &self.vk,
                VerificationRequest::real(&output),
            )
            .with_context(|| {
                format!("while attempting to verify proof for batch {batch_number}")
            })?;

        info!(batch_number, "Finished FRI proof verification");

        let proof = match prove_result.proof {
            Proof::Real(proof) => proof.into_inner(),
            Proof::Dev(_) => {
                anyhow::bail!("GPU prover returned a development proof unexpectedly")
            }
        };

        Ok(FriProofArtifact {
            proof,
            proving_time,
            cycles,
        })
    }
}

pub(crate) fn build_runner(jit: bool) -> Result<TranspilerRunner> {
    let program = Program::load(dist_dir()).context("while attempting to load guest program")?;
    let mut runner_builder = program.transpiler_runner().with_cycles(usize::MAX);

    if jit {
        runner_builder = runner_builder.with_jit();
    }

    runner_builder
        .build()
        .context("while attempting to build transpiler runner")
}

pub(crate) fn run_batch(
    runner: &TranspilerRunner,
    batch_number: u64,
    input_words: &[u32],
) -> Result<()> {
    let execution = runner
        .run(input_words)
        .with_context(|| format!("while attempting to execute batch {batch_number}"))?;
    let output = execution.receipt.output;

    info!(
        batch_number,
        cycles = execution.cycles_executed,
        reached_end = execution.reached_end,
        ?output,
        "Finished transpiler run"
    );

    if output == [0u32; 8] {
        anyhow::bail!(
            "batch {batch_number} returned zero output — verification or commitment failed"
        );
    }

    Ok(())
}

pub(crate) fn save_raw_proof(proof: &RawFriProof, path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("while attempting to derive the parent directory for the raw FRI proof file")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("while attempting to create {}", parent.display()))?;

    let file = std::fs::File::create(path)
        .with_context(|| format!("while attempting to create {}", path.display()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, proof)
        .with_context(|| format!("while attempting to serialize {}", path.display()))
}

pub(crate) fn load_raw_proof(path: &Path) -> Result<RawFriProof> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("while attempting to open {}", path.display()))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader)
        .with_context(|| format!("while attempting to deserialize {}", path.display()))
}

fn load_or_generate_vk(verifier: &RealVerifier, cache_path: &Path) -> Result<VerificationKey> {
    if cache_path.exists() {
        let bytes = std::fs::read(cache_path)
            .with_context(|| format!("while attempting to read {}", cache_path.display()))?;
        let (vk, decoded_len): (VerificationKey, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).with_context(
                || {
                    format!(
                        "while attempting to decode verification key cache {}",
                        cache_path.display()
                    )
                },
            )?;
        if decoded_len != bytes.len() {
            anyhow::bail!(
                "verification key cache {} has trailing bytes",
                cache_path.display()
            );
        }

        info!(path = %cache_path.display(), "Loaded verification key from cache");
        return Ok(vk);
    }

    let vk = verifier
        .generate_vk()
        .context("while attempting to generate verification key")?;
    let encoded = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .context("while attempting to bincode-encode verification key cache payload")?;
    std::fs::write(cache_path, encoded)
        .with_context(|| format!("while attempting to write {}", cache_path.display()))?;

    info!(path = %cache_path.display(), "Generated and cached verification key");
    Ok(vk)
}

fn vk_cache_path(program: &Program) -> Result<PathBuf> {
    let manifest_sha256 = program.manifest().bin.sha256.trim();
    if manifest_sha256.is_empty() {
        anyhow::bail!(
            "guest manifest has empty bin_sha256, cannot derive verification key cache path"
        );
    }

    Ok(PathBuf::from(format!("vk-{manifest_sha256}.bin")))
}

fn dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}
