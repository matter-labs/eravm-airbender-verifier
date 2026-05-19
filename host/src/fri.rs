use airbender_host::{
    GpuProver, Inputs, Program, Proof, Prover, ProverLevel, RealVerifier, Runner, SecurityLevel,
    TranspilerRunner, VerificationKey, VerificationRequest, Verifier,
};
use anyhow::{Context, Result};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_airbender_verifier::Verify;
use zksync_prover_metrics::{ProofLabels, ProofStatus, ProofType, METRICS};

/// The guest returns `[u32; 8]` — the proof public input hash.
/// We no longer check against a fixed expected output; any non-zero output
/// indicates successful execution + commitment computation.
/// The actual value is batch-specific and verified by L1 against stored commitments.
pub(crate) const FRI_PROOF_FILE_NAME: &str = "fri_proof.json";

pub type RawFriProof = airbender_host::raw::UnrolledProgramProof;

pub(crate) struct FriProofArtifact {
    pub(crate) proof: RawFriProof,
    pub(crate) proving_time: Duration,
    pub(crate) cycles: u64,
}

/// Result of running the FRI prover on an encoded input.
///
/// `proof` is the full `Proof` envelope (real or dev variant) so callers can
/// either serialize it directly (server flow) or strip it to the raw inner
/// proof for on-disk storage (host flow).
pub struct ProveOutput {
    pub proof: Proof,
    pub cycles: u64,
    pub proving_time: Duration,
    pub output: [u32; 8],
}

// ==============================================================================
// FRI Pipeline
// ==============================================================================
//
// This module keeps all Airbender-specific behavior in one place so the rest of
// the host can talk in terms of "run batch", "prove batch", and "load/save raw
// proof" without needing to know how the guest program, GPU prover, or VK cache
// are assembled.

/// Verifier-only counterpart to [`FriPipeline`]. Holds the real verifier and a
/// cached/generated verification key, but no GPU prover — built when callers
/// (like the `snark-only` server mode) need to validate incoming FRI proofs
/// without proving anything themselves.
pub struct FriVerifier {
    verifier: RealVerifier,
    vk: VerificationKey,
}

impl FriVerifier {
    pub fn new(dist_dir: &Path, security: SecurityLevel) -> Result<Self> {
        let program = Program::load(dist_dir).context("while attempting to load guest program")?;
        let verifier = program
            .real_verifier(ProverLevel::RecursionUnified)
            .build()
            .context("while attempting to build real verifier")?;

        let cache_path = vk_cache_path(&program, security)
            .context("while attempting to resolve verification key cache path")?;
        let vk = load_or_generate_vk(&verifier, &cache_path, security).with_context(|| {
            format!(
                "while attempting to prepare verification key cache {}",
                cache_path.display()
            )
        })?;

        Ok(Self { verifier, vk })
    }

    /// Verifies a FRI proof envelope against the cached VK, binding it to a
    /// specific guest output. The output must be non-zero — a zero output
    /// signals the guest's own verification + commitment step failed.
    pub fn verify(&self, batch_number: u64, proof: &Proof, output: [u32; 8]) -> Result<()> {
        if output == [0u32; 8] {
            anyhow::bail!(
                "batch {batch_number} proof returned zero output — verification or commitment failed"
            );
        }
        self.verifier
            .verify(proof, &self.vk, VerificationRequest::real(&output))
            .with_context(|| format!("while attempting to verify proof for batch {batch_number}"))
    }
}

pub struct FriPipeline {
    prover: GpuProver,
    verifier: FriVerifier,
}

impl FriPipeline {
    pub fn new(
        dist_dir: &Path,
        worker_threads: Option<usize>,
        security: SecurityLevel,
    ) -> Result<Self> {
        let verifier = FriVerifier::new(dist_dir, security)?;
        // Reload the program for the prover builder. Cheap relative to GPU init.
        let program = Program::load(dist_dir).context("while attempting to load guest program")?;

        let mut prover = program
            .gpu_prover()
            .with_level(ProverLevel::RecursionUnified)
            .with_security(security);
        if let Some(worker_threads) = worker_threads {
            prover = prover.with_worker_threads(worker_threads);
        }

        let prover = prover
            .build()
            .context("while attempting to build GPU prover")?;

        Ok(Self { prover, verifier })
    }

    /// Proves a preencoded input word stream, checks the output is non-zero,
    /// and verifies the proof against the cached VK. Returns the full `Proof`
    /// envelope so callers can choose how to persist it.
    pub fn prove_input(&self, batch_number: u64, input_words: &[u32]) -> Result<ProveOutput> {
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

        self.verifier
            .verify(batch_number, &prove_result.proof, output)?;

        info!(batch_number, "Finished FRI proof verification");

        Ok(ProveOutput {
            proof: prove_result.proof,
            cycles,
            proving_time,
            output,
        })
    }

    /// Proves a preencoded input word stream, records prover metrics, and
    /// returns the in-memory `Proof` envelope. Callers serialize it for
    /// transport when needed; the SNARK pipeline accepts it as-is.
    pub fn prove_fri(&self, batch_number: u32, input_words: &[u32]) -> Result<Proof> {
        info!(batch_number, "Starting FRI proof...");
        let started_at = Instant::now();
        let output = match self.prove_input(batch_number as u64, input_words) {
            Ok(out) => {
                record_proof_metrics(
                    batch_number,
                    ProofType::Fri,
                    ProofStatus::Success,
                    started_at.elapsed(),
                );
                out
            }
            Err(err) => {
                record_proof_metrics(
                    batch_number,
                    ProofType::Fri,
                    ProofStatus::Failure,
                    started_at.elapsed(),
                );
                return Err(err.context("FRI proving failed"));
            }
        };

        info!(
            batch_number,
            cycles = output.cycles,
            output = ?output.output,
            "FRI proof complete"
        );
        Ok(output.proof)
    }

    /// Proves an `AirbenderVerifierInput` by encoding it to the prover word
    /// stream first, then delegating to [`Self::prove_input`].
    pub fn prove_verifier_input(
        &self,
        batch_number: u64,
        input: &AirbenderVerifierInput,
    ) -> Result<ProveOutput> {
        let mut prover_input = Inputs::new();
        prover_input
            .push(input)
            .context("failed to encode AirbenderVerifierInput")?;
        self.prove_input(batch_number, prover_input.words())
    }

    pub(crate) fn prove_batch(
        &self,
        batch_number: u64,
        batch_path: &Path,
    ) -> Result<FriProofArtifact> {
        let input = load_verifier_input(batch_path).with_context(|| {
            format!(
                "failed to load batch {batch_number} from {}",
                batch_path.display()
            )
        })?;
        let ProveOutput {
            proof,
            cycles,
            proving_time,
            ..
        } = self.prove_verifier_input(batch_number, &input)?;

        let proof = match proof {
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

pub(crate) fn record_proof_metrics(
    batch_number: u32,
    proof_type: ProofType,
    status: ProofStatus,
    elapsed: Duration,
) {
    let labels = ProofLabels {
        batch_number,
        proof_type,
        status,
    };
    METRICS.proof_duration[&labels].observe(elapsed);
    METRICS.proof_count[&labels].inc();
}

pub(crate) fn build_runner(dist_dir: &Path, jit: bool) -> Result<TranspilerRunner> {
    let program = Program::load(dist_dir).context("while attempting to load guest program")?;
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
    batch_path: &Path,
) -> Result<()> {
    let input = load_verifier_input(batch_path).with_context(|| {
        format!(
            "failed to load batch {batch_number} from {}",
            batch_path.display()
        )
    })?;

    let native_result = input
        .clone()
        .verify()
        .context("native verification failed")?;

    info!(
        batch_number,
        ?native_result.commitment,
        ?native_result.proof_public_input,
        "Native verification + commitment succeeded"
    );

    // Re-run on the transpiler with the same input; the public input must match.
    let mut transpiler_input = Inputs::new();
    transpiler_input
        .push(&input)
        .context("failed to encode AirbenderVerifierInput")?;

    let execution = runner
        .run(transpiler_input.words())
        .with_context(|| format!("while attempting to execute batch {batch_number}"))?;
    let output = execution.receipt.output;

    info!(
        batch_number,
        cycles = execution.cycles_executed,
        reached_end = execution.reached_end,
        ?output,
        "Finished transpiler run"
    );

    // Verify transpiler output matches native verification.
    anyhow::ensure!(
        output == native_result.proof_public_input,
        "batch {batch_number}: transpiler output {output:?} doesn't match native {0:?}",
        native_result.proof_public_input
    );

    info!(
        batch_number,
        "Transpiler output matches native verification"
    );

    Ok(())
}

/// Load and deserialize an `AirbenderVerifierInput` from a batch file. The
/// corpus ships with `commitment_input` baked in, so callers can `verify()`
/// directly — no runtime synthesis step.
pub(crate) fn load_verifier_input(
    batch_path: &Path,
) -> Result<zksync_airbender_verifier::types::AirbenderVerifierInput> {
    let parent_dir = batch_path.parent().with_context(|| {
        format!(
            "batch path {} has no parent directory",
            batch_path.display()
        )
    })?;
    let batch_input = zksync_cli_utils::resolve_batch_inputs(
        parent_dir,
        Some(&[batch_path.to_path_buf()]),
        false,
    )?
    .into_iter()
    .next()
    .context("resolve_batch_inputs returned no entries")?;
    zksync_cli_utils::load_batch(&batch_input)
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

fn load_or_generate_vk(
    verifier: &RealVerifier,
    cache_path: &Path,
    security: SecurityLevel,
) -> Result<VerificationKey> {
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
        .generate_vk(security)
        .context("while attempting to generate verification key")?;
    let encoded = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .context("while attempting to bincode-encode verification key cache payload")?;
    std::fs::write(cache_path, encoded)
        .with_context(|| format!("while attempting to write {}", cache_path.display()))?;

    info!(path = %cache_path.display(), "Generated and cached verification key");
    Ok(vk)
}

fn vk_cache_path(program: &Program, security: SecurityLevel) -> Result<PathBuf> {
    let manifest_sha256 = program.manifest().bin.sha256.trim();
    if manifest_sha256.is_empty() {
        anyhow::bail!(
            "guest manifest has empty bin_sha256, cannot derive verification key cache path"
        );
    }

    // The VK depends on the security level — keep separate caches so an old
    // 80-bit VK isn't reused when the prover is now producing 100-bit proofs.
    Ok(PathBuf::from(format!(
        "vk-{manifest_sha256}-{security}.bin"
    )))
}

/// Resolves the guest dist directory: `ERAVM_PROVER_HOST_GUEST_DIR` env var if
/// set, otherwise the workspace-relative path baked in at compile time. Lets a
/// binary built on one machine find the guest dist on another (e.g. the CI
/// prove-batch flow builds host on a CPU runner and runs it on the GPU runner).
pub fn dist_dir() -> PathBuf {
    if let Ok(p) = std::env::var("ERAVM_PROVER_HOST_GUEST_DIR") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}
