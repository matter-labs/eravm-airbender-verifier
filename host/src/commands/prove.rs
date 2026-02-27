use airbender_host::{
    GpuProver, Program, Prover, ProverLevel, RealVerifier, VerificationKey, VerificationRequest,
    Verifier,
};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;

use crate::batches::load_batch_words;
use crate::statistics::StatisticsCollector;

use super::EXPECTED_OUTPUT;

pub fn prove_batches(
    program: &Program,
    batches_dir: &Path,
    batch_numbers: &[u64],
    worker_threads: Option<usize>,
) -> Result<()> {
    // We build proving primitives once and reuse them for every batch so the
    // per-batch measurements mostly reflect proving/verification work.
    let verifier = program
        .real_verifier(ProverLevel::RecursionUnified)
        .build()
        .context("while attempting to build real verifier")?;

    let cache_path = vk_cache_path(program)
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

    let mut batches_proven = 0;
    let total_batches = batch_numbers.len();
    let mut statistics = StatisticsCollector::default();

    // TODO: Keep proving sequential for now; add explicit GPU scheduling before
    // introducing multi-batch parallelism.
    for &batch_number in batch_numbers {
        let input_words = load_batch_words(batches_dir, batch_number)
            .with_context(|| format!("while attempting to load batch {batch_number}"))?;
        let proving_stats = prove_batch(&prover, &verifier, &vk, batch_number, &input_words)
            .with_context(|| format!("while attempting to prove batch {batch_number}"))?;
        statistics.add_sample(proving_stats.proving_time, proving_stats.cycles);

        info!(batch_number, "Successfully proved batch");
        batches_proven += 1;
        info!("Batches proven: {batches_proven}/{total_batches}");
        statistics.print_stats();
    }

    Ok(())
}

fn prove_batch(
    prover: &GpuProver,
    verifier: &RealVerifier,
    vk: &VerificationKey,
    batch_number: u64,
    input_words: &[u32],
) -> Result<ProofBatchStats> {
    let proving_started_at = Instant::now();
    let prove_result = prover
        .prove(input_words)
        .with_context(|| format!("while attempting to generate proof for batch {batch_number}"))?;
    let proving_time = proving_started_at.elapsed();
    let cycles = prove_result.cycles;
    let output = prove_result.receipt.output[0];

    info!(
        batch_number,
        cycles,
        proving_time_secs = proving_time.as_secs_f64(),
        output,
        "Finished proof generation"
    );

    if output != EXPECTED_OUTPUT {
        bail!(
            "batch {batch_number} proof output {output} does not match expected {EXPECTED_OUTPUT}"
        );
    }

    verifier
        .verify(
            &prove_result.proof,
            vk,
            VerificationRequest::real(&EXPECTED_OUTPUT),
        )
        .with_context(|| format!("while attempting to verify proof for batch {batch_number}"))?;

    info!(batch_number, "Finished proof verification");
    Ok(ProofBatchStats {
        proving_time,
        cycles,
    })
}

struct ProofBatchStats {
    proving_time: Duration,
    cycles: u64,
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
            bail!(
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
        bail!("guest manifest has empty bin_sha256, cannot derive verification key cache path");
    }

    Ok(PathBuf::from(format!("vk-{manifest_sha256}.bin")))
}
