use airbender_host::{GpuProver, Program, Prover, ProverLevel};
use anyhow::{Context, Result};
use clap::Parser;
use core::time;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use zksync_prover_metrics::{ProofLabels, ProofStatus, METRICS};
use zksync_airbender_verifier::types::AirbenderVerifierInput;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Prover server: polls for jobs and submits prove results"
)]
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

    /// Port to expose Prometheus metrics on (disabled if not set)
    #[arg(long, env = "PROVER_METRICS_PORT")]
    metrics_port: Option<u16>,
}

/// A proving job received from the server.
struct Job {
    batch_number: u32,
    protocol_version: u16,
    input_words: Vec<u32>,
}

/// A completed proof ready to be submitted.
struct CompletedProof {
    batch_number: u32,
    proof_bytes: Vec<u8>,
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

    if let Some(port) = cli.metrics_port {
        zksync_prover_metrics::start_metrics_server(port);
        info!(port, "Metrics server started");
    }

    let program = Program::load(dist_dir()).context("while loading guest program")?;
    let mut prover_builder = program
        .gpu_prover()
        .with_level(ProverLevel::RecursionUnified);
    if let Some(threads) = cli.worker_threads {
        prover_builder = prover_builder.with_worker_threads(threads);
    }
    let prover = prover_builder
        .build()
        .context("while building GPU prover")?;

    let client = reqwest::blocking::Client::new();
    let poll_interval = Duration::from_millis(cli.poll_interval_ms);

    // Channel capacity 1: the network worker can buffer one job ahead while the prover is busy.
    let (job_tx, job_rx) = mpsc::sync_channel::<Job>(1);
    // Channel capacity 1: the prover sends one result at a time.
    let (result_tx, result_rx) = mpsc::sync_channel::<CompletedProof>(1);

    let shutdown = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let shutdown = Arc::clone(&shutdown);
        move || {
            info!("Shutdown signal received, stopping after current job...");
            shutdown.store(true, Ordering::Relaxed);
        }
    })
    .context("while setting Ctrl-C handler")?;

    info!(server_url = %cli.server_url, "Starting prover server");

    let prover_handle = std::thread::spawn(move || {
        prover_worker(prover, job_rx, result_tx);
    });

    network_worker(
        job_tx,
        result_rx,
        client,
        cli.server_url,
        poll_interval,
        cli.submit_attempts,
        shutdown,
    );

    info!("Waiting for prover to finish current job...");
    prover_handle.join().expect("prover thread panicked");
    Ok(())
}

/// Receives jobs, proves them, and sends completed proofs back to the network worker.
///
/// Runs independently so the network worker can submit the previous proof and pre-fetch
/// the next job while this thread is busy proving.
fn prover_worker(prover: GpuProver, job_rx: Receiver<Job>, result_tx: SyncSender<CompletedProof>) {
    for job in job_rx {
        info!(batch_number = job.batch_number, "Starting proof...");
        let started_at = Instant::now();
        match prover.prove(&job.input_words) {
            Err(err) => {
                let elapsed = started_at.elapsed();
                let labels = ProofLabels {
                    batch_number: job.batch_number,
                    protocol_version: job.protocol_version,
                    status: ProofStatus::Failure,
                };
                METRICS.proof_duration[&labels].observe(elapsed);
                METRICS.proof_count[&labels].inc();
                error!(
                    batch_number = job.batch_number,
                    ?err,
                    "Failed to prove batch"
                );
            }
            Ok(prove_result) => {
                let elapsed = started_at.elapsed();
                let labels = ProofLabels {
                    batch_number: job.batch_number,
                    protocol_version: job.protocol_version,
                    status: ProofStatus::Success,
                };
                METRICS.proof_duration[&labels].observe(elapsed);
                METRICS.proof_count[&labels].inc();

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
                info!(
                    batch_number = job.batch_number,
                    cycles = prove_result.cycles,
                    "Proof complete, forwarding to network worker"
                );
                if result_tx
                    .send(CompletedProof {
                        batch_number: job.batch_number,
                        proof_bytes,
                    })
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

/// Fetches jobs from the server, forwards them to the prover, and submits completed proofs.
///
/// Uses a one-slot pending buffer so a job can be pre-fetched while the prover is busy,
/// and proof submission does not block the next fetch cycle.
fn network_worker(
    job_tx: SyncSender<Job>,
    result_rx: Receiver<CompletedProof>,
    client: reqwest::blocking::Client,
    server_url: String,
    poll_interval: Duration,
    submit_attempts: usize,
    shutdown: Arc<AtomicBool>,
) {
    let mut pending_job: Option<Job> = None;

    loop {
        let shutting_down = shutdown.load(Ordering::Relaxed);
        let mut did_work = false;

        // Forward a pending job to the prover if it has capacity.
        if !shutting_down {
            if let Some(job) = pending_job.take() {
                match job_tx.try_send(job) {
                    Ok(()) => {
                        did_work = true;
                    }
                    Err(TrySendError::Full(job)) => {
                        // Prover is still busy; hold the job and retry next iteration.
                        pending_job = Some(job);
                    }
                    Err(TrySendError::Disconnected(_)) => break,
                }
            }
        }

        // Submit any completed proof that the prover has finished.
        match result_rx.try_recv() {
            Ok(result) => {
                match submit_result_with_retries(
                    &client,
                    &server_url,
                    result.batch_number,
                    &result.proof_bytes,
                    submit_attempts,
                ) {
                    Err(err) => {
                        error!(
                            batch_number = result.batch_number,
                            ?err,
                            "Failed to submit proof after {submit_attempts} attempt(s)"
                        );
                    }
                    Ok(()) => {
                        info!(
                            batch_number = result.batch_number,
                            "Successfully submitted proof"
                        );
                    }
                }
                METRICS.pending_jobs.dec_by(1);
                did_work = true;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => break,
        }

        // On shutdown: stop after submitting any proof that was already ready.
        if shutting_down {
            break;
        }

        // Fetch a new job from the server if we have no pending job buffered.
        if pending_job.is_none() {
            match fetch_job(&client, &server_url) {
                Ok(Some(job)) => {
                    info!(batch_number = job.batch_number, "Received job");
                    METRICS.pending_jobs.inc_by(1);
                    pending_job = Some(job);
                    did_work = true;
                }
                Ok(None) => {
                    info!("No jobs available, waiting...");
                }
                Err(err) => {
                    warn!(?err, "Failed to fetch job, retrying after poll interval");
                }
            }
        }

        if !did_work {
            std::thread::sleep(poll_interval);
        }
    }
}

/// Polls `POST /airbender/proof_inputs` for a new job.
///
/// Returns `None` on 204 No Content (no jobs available).
/// The response body mirrors `AirbenderProofGenerationDataResponse(Box<AirbenderVerifierInput>)`
/// from zksync-era, serialized as JSON.
fn fetch_job(client: &reqwest::blocking::Client, base_url: &str) -> Result<Option<Job>> {
    let url = format!("{base_url}/airbender/proof_inputs");
    let response = client
        .post(&url)
        .send()
        .with_context(|| format!("while polling {url}"))?;

    match response.status() {
        reqwest::StatusCode::OK => {
            let input = response
                .json::<AirbenderVerifierInput>()
                .context("while deserializing proof generation data")?;
            let batch_number = batch_number_from_input(&input)?;
            let protocol_version = protocol_version_from_input(&input)?;
            let input_words = input_to_words(&input)?;
            Ok(Some(Job {
                batch_number,
                protocol_version,
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
fn batch_number_from_input(input: &AirbenderVerifierInput) -> Result<u32> {
    let AirbenderVerifierInput::V1(v1) = input else {
        anyhow::bail!("expected AirbenderVerifierInput::V1, got V0");
    };
    Ok(v1.vm_run_data.l1_batch_number.0)
}

/// Extracts the protocol version from the verifier input.
fn protocol_version_from_input(input: &AirbenderVerifierInput) -> Result<u16> {
    let AirbenderVerifierInput::V1(v1) = input else {
        anyhow::bail!("expected AirbenderVerifierInput::V1, got V0");
    };
    Ok(v1.vm_run_data.protocol_version as u16)
}

/// Serializes `AirbenderVerifierInput` to the `Vec<u32>` word stream expected by the prover.
///
/// Format: the first word is the byte length of the serialized input, followed by the
/// bincode-serialized data packed into big-endian u32 words (last word zero-padded if needed).
/// This matches `encode_to_words` from the `airbender_prover_interface` crate in zksync-era.
fn input_to_words(input: &AirbenderVerifierInput) -> Result<Vec<u32>> {
    let bytes = bincode::serialize(input).context("while serializing AirbenderVerifierInput")?;
    let mut words = Vec::with_capacity(1 + bytes.len().div_ceil(4));
    let byte_len = u32::try_from(bytes.len()).context("serialized input exceeds 4 GiB")?;
    words.push(byte_len);
    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_be_bytes(buf));
    }
    Ok(words)
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
                warn!(
                    batch_number,
                    attempt,
                    attempts,
                    ?err,
                    "Submit attempt failed"
                );
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
