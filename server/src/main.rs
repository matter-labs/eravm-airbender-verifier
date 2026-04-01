use airbender_host::{GpuProver, Program, Prover, ProverLevel};
use anyhow::{Context, Result};
use clap::Parser;
use core::time;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, warn};
use zksync_tee_verifier::types::TeeVerifierInput;

#[derive(Debug, Parser)]
#[command(version, about = "Prover server: polls for jobs and submits prove results")]
struct Cli {
    /// Base URL of the job server (e.g. http://localhost:8080)
    #[arg(long, env = "PROVER_SERVER_URL")]
    server_url: String,

    /// How long to wait between polls when no job is available (milliseconds)
    #[arg(long, env = "PROVER_POLL_INTERVAL_MS", default_value = "5000")]
    poll_interval_ms: u64,

    /// Number of worker threads for the GPU prover
    #[arg(long, env = "PROVER_WORKER_THREADS")]
    worker_threads: Option<usize>,

    /// Number of attempts to submit a prove result before giving up
    #[arg(long, env = "PROVER_SUBMIT_ATTEMPTS", default_value = "3")]
    submit_attempts: usize,
}

/// A proving job received from the server.
struct Job {
    batch_number: u32,
    input_words: Vec<u32>,
}

/// Mirrors `SubmitAirbenderProofRequest` from zksync-era.
/// The `proof` bytes are hex-encoded in JSON, matching the `#[serde_as(as = "Hex")]` annotation.
#[serde_with::serde_as]
#[derive(serde::Serialize)]
struct SubmitProofRequest {
    #[serde_as(as = "serde_with::hex::Hex")]
    proof: Vec<u8>,
}

fn main() -> Result<()> {
    init_tracing()?;
    let cli = Cli::parse();

    let program = Program::load(dist_dir()).context("while loading guest program")?;
    let mut prover_builder = program
        .gpu_prover()
        .with_level(ProverLevel::RecursionUnified);
    if let Some(threads) = cli.worker_threads {
        prover_builder = prover_builder.with_worker_threads(threads);
    }
    let prover = prover_builder.build().context("while building GPU prover")?;

    let client = reqwest::blocking::Client::new();
    let poll_interval = Duration::from_millis(cli.poll_interval_ms);

    info!(server_url = %cli.server_url, "Starting prover server loop");

    run_loop(&prover, &client, &cli.server_url, poll_interval, cli.submit_attempts)
}

fn run_loop(
    prover: &GpuProver,
    client: &reqwest::blocking::Client,
    server_url: &str,
    poll_interval: Duration,
    submit_attempts: usize,
) -> Result<()> {
    loop {
        match fetch_job(client, server_url) {
            Err(err) => {
                warn!(?err, "Failed to fetch job, retrying after poll interval");
                std::thread::sleep(poll_interval);
            }
            Ok(None) => {
                info!("No jobs available, waiting...");
                std::thread::sleep(poll_interval);
            }
            Ok(Some(job)) => {
                info!(batch_number = job.batch_number, "Received job, proving...");
                match prover.prove(&job.input_words) {
                    Err(err) => {
                        error!(batch_number = job.batch_number, ?err, "Failed to prove batch");
                    }
                    Ok(prove_result) => {
                        let proof_bytes = match bincode::serialize(&prove_result.proof)
                            .context("while serializing proof")
                        {
                            Ok(b) => b,
                            Err(err) => {
                                error!(
                                    batch_number = job.batch_number,
                                    ?err,
                                    "Failed to serialize proof"
                                );
                                continue;
                            }
                        };

                        match submit_result_with_retries(
                            client,
                            server_url,
                            job.batch_number,
                            &proof_bytes,
                            submit_attempts,
                        ) {
                            Err(err) => {
                                error!(
                                    batch_number = job.batch_number,
                                    ?err,
                                    "Failed to submit result after {submit_attempts} attempt(s)"
                                );
                            }
                            Ok(()) => {
                                info!(
                                    batch_number = job.batch_number,
                                    cycles = prove_result.cycles,
                                    "Successfully proved and submitted batch"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Polls `POST /airbender/proof_inputs` for a new job.
///
/// Returns `None` on 204 No Content (no jobs available).
/// The response body mirrors `AirbenderProofGenerationDataResponse(Box<AirbenderVerifierInput>)`
/// from zksync-era, which serializes as JSON-encoded `TeeVerifierInput`.
fn fetch_job(client: &reqwest::blocking::Client, base_url: &str) -> Result<Option<Job>> {
    let url = format!("{base_url}/airbender/proof_inputs");
    let response = client
        .post(&url)
        .send()
        .with_context(|| format!("while polling {url}"))?;

    match response.status() {
        reqwest::StatusCode::OK => {
            let input = response
                .json::<TeeVerifierInput>()
                .context("while deserializing proof generation data")?;
            let batch_number = batch_number_from_input(&input)?;
            let input_words = input_to_words(&input)?;
            Ok(Some(Job {
                batch_number,
                input_words,
            }))
        }
        reqwest::StatusCode::NO_CONTENT => Ok(None),
        status => {
            warn!(%status, "Unexpected status from job server");
            Ok(None)
        }
    }
}

/// Extracts the L1 batch number from the verifier input.
fn batch_number_from_input(input: &TeeVerifierInput) -> Result<u32> {
    let TeeVerifierInput::V1(v1) = input else {
        anyhow::bail!("expected TeeVerifierInput::V1, got V0");
    };
    Ok(v1.vm_run_data.l1_batch_number.0)
}

/// Serializes `TeeVerifierInput` to the `Vec<u32>` word stream expected by the prover.
///
/// The guest program deserializes its input by reading words from the virtual UART,
/// so the input must be bincode-serialized and then split into big-endian u32 words
/// (matching the format used in the test batch `.bin` files).
fn input_to_words(input: &TeeVerifierInput) -> Result<Vec<u32>> {
    let bytes = bincode::serialize(input).context("while serializing TeeVerifierInput")?;
    // Pad to a multiple of 4 bytes.
    let rem = bytes.len() % 4;
    let padded = if rem == 0 {
        bytes
    } else {
        let mut v = bytes;
        v.resize(v.len() + (4 - rem), 0);
        v
    };
    Ok(padded
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
        .collect())
}

fn submit_result_with_retries(
    client: &reqwest::blocking::Client,
    base_url: &str,
    batch_number: u32,
    proof_bytes: &[u8],
    attempts: usize,
) -> Result<()> {
    let mut last_err = anyhow::anyhow!("no attempts made");
    for attempt in 1..=attempts {
        match submit_result(client, base_url, batch_number, proof_bytes) {
            Ok(()) => return Ok(()),
            Err(err) => {
                warn!(batch_number, attempt, attempts, ?err, "Submit attempt failed");
                last_err = err;
            }
        }
        std::thread::sleep(time::Duration::from_millis(100));
    }
    Err(last_err)
}

/// Submits a proof to `POST /airbender/submit_proofs/{l1_batch_number}`.
///
/// The body mirrors `SubmitAirbenderProofRequest` from zksync-era:
/// `{ "proof": "<hex-encoded bytes>" }`.
fn submit_result(
    client: &reqwest::blocking::Client,
    base_url: &str,
    batch_number: u32,
    proof_bytes: &[u8],
) -> Result<()> {
    let url = format!("{base_url}/airbender/submit_proofs/{batch_number}");
    let payload = SubmitProofRequest {
        proof: proof_bytes.to_vec(),
    };
    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .with_context(|| format!("while submitting proof to {url}"))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "server returned {} when submitting proof for batch {batch_number}",
            response.status()
        );
    }
    Ok(())
}

fn init_tracing() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|err| anyhow::anyhow!("failed to initialize tracing: {err}"))?;
    Ok(())
}

fn dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}
