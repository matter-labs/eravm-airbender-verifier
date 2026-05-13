use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use airbender_host::Inputs;
use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_prover_metrics::METRICS;

use crate::types::{
    CompletedFriProof, CompletedSnarkProof, CompletedWork, FriJob, ProverMode, SnarkInputResponse,
    SnarkJob, SubmitFriProofRequest, SubmitSnarkProofRequest,
};
use crate::worker::WorkerJob;

pub struct NetworkWorkerConfig {
    pub mode: ProverMode,
    pub job_tx: SyncSender<WorkerJob>,
    pub result_rx: Receiver<CompletedWork>,
    pub client: reqwest::blocking::Client,
    pub server_url: String,
    pub prover_id: String,
    pub poll_interval: Duration,
    pub submit_attempts: usize,
    pub shutdown: Arc<AtomicBool>,
}

/// Fetches jobs from the server, forwards them to the prover, and submits completed proofs.
///
/// Uses a one-slot pending buffer so a job can be pre-fetched while the prover is busy,
/// and proof submission does not block the next fetch cycle.
pub fn network_worker(cfg: NetworkWorkerConfig) {
    let mut pending_job: Option<WorkerJob> = None;

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

        // Submit any completed work the prover has finished.
        match cfg.result_rx.try_recv() {
            Ok(CompletedWork::Fri(result)) => {
                submit_fri_proof(&cfg, &result);
                METRICS.pending_jobs.dec_by(1);
                did_work = true;
            }
            Ok(CompletedWork::Snark(result)) => {
                submit_snark_proof(&cfg, &result);
                // In fri+snark mode the same job decremented pending on FRI completion;
                // in snark-only mode the SNARK output is the only completion event.
                if cfg.mode == ProverMode::SnarkOnly {
                    METRICS.pending_jobs.dec_by(1);
                }
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
            match fetch_job(&cfg.client, &cfg.server_url, cfg.mode) {
                Ok(Some(job)) => {
                    let batch_number = match &job {
                        WorkerJob::Fri(j) => j.batch_number,
                        WorkerJob::Snark(j) => j.batch_number,
                    };
                    info!(batch_number, "Received job");
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

fn submit_fri_proof(cfg: &NetworkWorkerConfig, result: &CompletedFriProof) {
    let outcome = submit_with_retries(cfg.submit_attempts, |attempt| {
        let attempt_info = (result.batch_number, attempt, cfg.submit_attempts);
        submit_fri_result(
            &cfg.client,
            &cfg.server_url,
            &cfg.prover_id,
            result.batch_number,
            &result.proof_bytes,
            attempt_info,
        )
    });

    match outcome {
        Err(err) => {
            error!(
                batch_number = result.batch_number,
                submit_attempts = cfg.submit_attempts,
                ?err,
                "Failed to submit FRI proof after all attempts"
            );
        }
        Ok(()) => {
            info!(
                batch_number = result.batch_number,
                "Successfully submitted FRI proof"
            );
        }
    }
}

fn submit_snark_proof(cfg: &NetworkWorkerConfig, result: &CompletedSnarkProof) {
    let outcome = submit_with_retries(cfg.submit_attempts, |attempt| {
        let attempt_info = (result.batch_number, attempt, cfg.submit_attempts);
        submit_snark_result(
            &cfg.client,
            &cfg.server_url,
            &cfg.prover_id,
            result.batch_number,
            &result.snark_proof_bytes,
            &result.snark_vk_bytes,
            attempt_info,
        )
    });

    match outcome {
        Err(err) => {
            error!(
                batch_number = result.batch_number,
                submit_attempts = cfg.submit_attempts,
                ?err,
                "Failed to submit SNARK proof after all attempts"
            );
        }
        Ok(()) => {
            info!(
                batch_number = result.batch_number,
                "Successfully submitted SNARK proof"
            );
        }
    }
}

fn fetch_job(
    client: &reqwest::blocking::Client,
    base_url: &str,
    mode: ProverMode,
) -> Result<Option<WorkerJob>> {
    match mode {
        ProverMode::FriOnly | ProverMode::FriSnark => {
            fetch_fri_job(client, base_url).map(|opt| opt.map(WorkerJob::Fri))
        }
        ProverMode::SnarkOnly => {
            fetch_snark_job(client, base_url).map(|opt| opt.map(WorkerJob::Snark))
        }
    }
}

/// Polls `POST /airbender/proof_inputs` for a new FRI job.
///
/// Returns `None` on 204 No Content (no jobs available).
fn fetch_fri_job(client: &reqwest::blocking::Client, base_url: &str) -> Result<Option<FriJob>> {
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
            let AirbenderVerifierInput::V1(ref v1) = input else {
                anyhow::bail!("expected AirbenderVerifierInput::V1");
            };
            let batch_number = v1.vm_run_data.l1_batch_number.0;
            let protocol_version = v1.vm_run_data.protocol_version as u16;
            let mut inputs = Inputs::new();
            inputs
                .push(&input)
                .context("failed to encode AirbenderVerifierInput")?;
            Ok(Some(FriJob {
                batch_number,
                protocol_version,
                input_words: inputs.words().to_vec(),
            }))
        }
        reqwest::StatusCode::NO_CONTENT => Ok(None),
        status => {
            warn!(%status, "Unexpected status from FRI job server");
            Ok(None)
        }
    }
}

/// Polls `POST /airbender/snark_inputs` for a ready FRI proof to wrap.
fn fetch_snark_job(client: &reqwest::blocking::Client, base_url: &str) -> Result<Option<SnarkJob>> {
    let url = format!("{base_url}/airbender/snark_inputs");
    let response = client
        .post(&url)
        .send()
        .with_context(|| format!("while polling {url}"))?;

    match response.status() {
        reqwest::StatusCode::OK => {
            let body = response
                .json::<SnarkInputResponse>()
                .context("while deserializing SNARK input")?;
            Ok(Some(SnarkJob {
                batch_number: body.l1_batch_number,
                protocol_version: body.protocol_version,
                fri_proof_bytes: body.fri_proof,
            }))
        }
        reqwest::StatusCode::NO_CONTENT => Ok(None),
        status => {
            warn!(%status, "Unexpected status from SNARK job server");
            Ok(None)
        }
    }
}

fn submit_with_retries<F>(attempts: usize, mut once: F) -> Result<()>
where
    F: FnMut(usize) -> Result<(), (Option<reqwest::StatusCode>, anyhow::Error)>,
{
    let mut last_err = anyhow::anyhow!("no attempts made");
    for attempt in 1..=attempts {
        match once(attempt) {
            Ok(()) => return Ok(()),
            Err((status, err)) => {
                let retriable = status.is_none_or(|s| {
                    s == reqwest::StatusCode::TOO_MANY_REQUESTS || s.is_server_error()
                });
                if !retriable {
                    return Err(err);
                }
                last_err = err;
                if attempt < attempts {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    Err(last_err)
}

/// Submits a FRI proof to `POST /airbender/submit_proofs`. See `SubmitFriProofRequest`.
fn submit_fri_result(
    client: &reqwest::blocking::Client,
    base_url: &str,
    prover_id: &str,
    batch_number: u32,
    proof_bytes: &[u8],
    attempt_info: (u32, usize, usize),
) -> Result<(), (Option<reqwest::StatusCode>, anyhow::Error)> {
    let url = format!("{base_url}/airbender/submit_proofs");
    let payload = SubmitFriProofRequest {
        l1_batch_number: batch_number,
        prover_id: prover_id.to_owned(),
        proof: proof_bytes,
    };
    info!(
        batch_number,
        proof_bytes = proof_bytes.len(),
        attempt = attempt_info.1,
        attempts = attempt_info.2,
        "Submitting FRI proof"
    );
    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .with_context(|| format!("while submitting FRI proof to {url}"))
        .map_err(|e| (None, e))?;

    let status = response.status();
    if !status.is_success() {
        return Err((
            Some(status),
            anyhow::anyhow!(
                "server returned {status} when submitting FRI proof for batch {batch_number}"
            ),
        ));
    }
    Ok(())
}

/// Submits a SNARK proof + VK to `POST /airbender/submit_snark_proofs`.
fn submit_snark_result(
    client: &reqwest::blocking::Client,
    base_url: &str,
    prover_id: &str,
    batch_number: u32,
    snark_proof_bytes: &[u8],
    snark_vk_bytes: &[u8],
    attempt_info: (u32, usize, usize),
) -> Result<(), (Option<reqwest::StatusCode>, anyhow::Error)> {
    let url = format!("{base_url}/airbender/submit_snark_proofs");
    let payload = SubmitSnarkProofRequest {
        l1_batch_number: batch_number,
        prover_id: prover_id.to_owned(),
        snark_proof: snark_proof_bytes,
        snark_vk: snark_vk_bytes,
    };
    info!(
        batch_number,
        snark_proof_bytes = snark_proof_bytes.len(),
        snark_vk_bytes = snark_vk_bytes.len(),
        attempt = attempt_info.1,
        attempts = attempt_info.2,
        "Submitting SNARK proof"
    );
    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .with_context(|| format!("while submitting SNARK proof to {url}"))
        .map_err(|e| (None, e))?;

    let status = response.status();
    if !status.is_success() {
        return Err((
            Some(status),
            anyhow::anyhow!(
                "server returned {status} when submitting SNARK proof for batch {batch_number}"
            ),
        ));
    }
    Ok(())
}
