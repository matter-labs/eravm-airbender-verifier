use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_prover_metrics::METRICS;

use crate::types::{CompletedProof, Job, SubmitProofRequest};

pub struct NetworkWorkerConfig {
    pub job_tx: SyncSender<Job>,
    pub result_rx: Receiver<CompletedProof>,
    pub client: reqwest::blocking::Client,
    pub server_url: String,
    pub poll_interval: Duration,
    pub submit_attempts: usize,
    pub shutdown: Arc<AtomicBool>,
}

/// Fetches jobs from the server, forwards them to the prover, and submits completed proofs.
///
/// Uses a one-slot pending buffer so a job can be pre-fetched while the prover is busy,
/// and proof submission does not block the next fetch cycle.
pub fn network_worker(cfg: NetworkWorkerConfig) {
    let mut pending_job: Option<Job> = None;

    loop {
        let shutting_down = cfg.shutdown.load(Ordering::Relaxed);
        let mut did_work = false;

        // Forward a pending job to the prover if it has capacity.
        if !shutting_down {
            if let Some(job) = pending_job.take() {
                match cfg.job_tx.try_send(job) {
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
        match cfg.result_rx.try_recv() {
            Ok(result) => {
                submit_proof(&cfg, &result);
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
            match fetch_job(&cfg.client, &cfg.server_url) {
                Ok(Some(job)) => {
                    info!(batch_number = job.batch_number, "Received job");
                    METRICS.pending_jobs.inc_by(1);
                    pending_job = Some(job);
                    did_work = true;
                }
                Ok(None) => {
                    debug!("No jobs available, waiting...");
                }
                Err(err) => {
                    warn!(?err, "Failed to fetch job, retrying after poll interval");
                }
            }
        }

        if !did_work {
            std::thread::sleep(cfg.poll_interval);
        }
    }
}

fn submit_proof(cfg: &NetworkWorkerConfig, result: &CompletedProof) {
    match submit_result_with_retries(
        &cfg.client,
        &cfg.server_url,
        result.batch_number,
        &result.proof_bytes,
        cfg.submit_attempts,
    ) {
        Err(err) => {
            error!(
                batch_number = result.batch_number,
                submit_attempts = cfg.submit_attempts,
                ?err,
                "Failed to submit proof after all attempts"
            );
        }
        Ok(()) => {
            info!(
                batch_number = result.batch_number,
                "Successfully submitted proof"
            );
        }
    }
}

/// Polls `POST /airbender/proof_inputs` for a new job.
///
/// Returns `None` on 204 No Content (no jobs available).
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
            let (batch_number, protocol_version) = extract_v1_fields(&input)?;
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

/// Extracts batch number and protocol version from the verifier input.
fn extract_v1_fields(input: &AirbenderVerifierInput) -> Result<(u32, u16)> {
    let AirbenderVerifierInput::V1(v1) = input else {
        anyhow::bail!("expected AirbenderVerifierInput::V1");
    };
    Ok((
        v1.vm_run_data.l1_batch_number.0,
        v1.vm_run_data.protocol_version as u16,
    ))
}

/// Serializes `AirbenderVerifierInput` to the `Vec<u32>` word stream expected by the prover.
///
/// Format: the first word is the byte length of the serialized input, followed by the
/// bincode-serialized data packed into big-endian u32 words (last word zero-padded if needed).
/// This matches `encode_to_words` from the `airbender_prover_interface` crate in zksync-era.
fn input_to_words(input: &AirbenderVerifierInput) -> Result<Vec<u32>> {
    let bytes = bincode::serialize(input).context("while serializing AirbenderVerifierInput")?;
    let byte_len = u32::try_from(bytes.len()).context("serialized input exceeds 4 GiB")?;
    let mut words = Vec::with_capacity(1 + bytes.len().div_ceil(4));
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
                if attempt < attempts {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
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
    let payload = SubmitProofRequest { proof: proof_bytes };
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
