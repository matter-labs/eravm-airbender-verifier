use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use airbender_host::Inputs;
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, error, info, warn};
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_prover_metrics::METRICS;

use crate::types::{
    Artifact, FriJob, Outcome, ProverMode, SnarkInputResponse, SnarkJob, SubmitFriProofRequest,
    SubmitSnarkProofRequest,
};
use crate::worker::WorkerJob;

const FRI_INPUTS_PATH: &str = "/airbender/proof_inputs";
const SNARK_INPUTS_PATH: &str = "/airbender/snark_inputs";
const SUBMIT_FRI_PATH: &str = "/airbender/submit_proofs";
const SUBMIT_SNARK_PATH: &str = "/airbender/submit_snark_proofs";

const FRI_LABEL: &str = "FRI";
const SNARK_LABEL: &str = "SNARK";

/// Status code + error pair returned by request-level helpers; `None` for
/// transport-level errors that have no server status.
type RequestResult = Result<(), (Option<reqwest::StatusCode>, anyhow::Error)>;

pub struct NetworkWorker {
    pub mode: ProverMode,
    pub job_tx: SyncSender<WorkerJob>,
    pub result_rx: Receiver<Outcome>,
    /// HTTP client used for polling job inputs (shorter timeout).
    pub poll_client: reqwest::blocking::Client,
    /// HTTP client used for submitting proof results (longer timeout for large SNARK payloads).
    pub submit_client: reqwest::blocking::Client,
    pub server_url: String,
    pub prover_id: String,
    pub poll_interval: Duration,
    pub submit_attempts: usize,
    pub shutdown: Arc<AtomicBool>,
}

impl NetworkWorker {
    /// Fetches jobs from the server, forwards them to the prover, and submits
    /// completed proofs. Uses a one-slot pending buffer so a job can be
    /// pre-fetched while the prover is busy.
    pub fn run(self) {
        let mut pending_job: Option<WorkerJob> = None;

        loop {
            let shutting_down = self.shutdown.load(Ordering::Relaxed);
            let mut did_work = false;

            if !shutting_down {
                if let Some(job) = pending_job.take() {
                    match self.job_tx.try_send(job) {
                        Ok(()) => did_work = true,
                        Err(TrySendError::Full(job)) => pending_job = Some(job),
                        Err(TrySendError::Disconnected(_)) => break,
                    }
                }
            }

            match self.result_rx.try_recv() {
                Ok(outcome) => {
                    self.handle_outcome(outcome);
                    did_work = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => break,
            }

            if shutting_down {
                break;
            }

            if pending_job.is_none() {
                match self.fetch_job() {
                    Ok(Some(job)) => {
                        info!(batch_number = job.batch_number(), %job, "Received job");
                        METRICS.pending_jobs.inc_by(1);
                        pending_job = Some(job);
                        did_work = true;
                    }
                    Ok(None) => debug!("No jobs available, waiting..."),
                    Err(err) => warn!(?err, "Failed to fetch job, retrying after poll interval"),
                }
            }

            if !did_work {
                std::thread::sleep(self.poll_interval);
            }
        }
    }

    fn handle_outcome(&self, outcome: Outcome) {
        let settles = outcome.settles_job(self.mode);
        match outcome.result {
            Ok(Artifact::Fri { proof }) => self.submit_fri(outcome.batch_number, &proof),
            Ok(Artifact::Snark { proof, vk }) => {
                self.submit_snark(outcome.batch_number, &proof, &vk)
            }
            Err(reason) => error!(
                batch_number = outcome.batch_number,
                kind = %outcome.kind,
                %reason,
                "Job failed; will not be submitted",
            ),
        }
        if settles {
            METRICS.pending_jobs.dec_by(1);
        }
    }

    // ----- fetch ---------------------------------------------------------

    fn fetch_job(&self) -> Result<Option<WorkerJob>> {
        match self.mode {
            ProverMode::FriOnly | ProverMode::FriSnark => {
                Ok(self.fetch_fri_job()?.map(WorkerJob::Fri))
            }
            ProverMode::SnarkOnly => Ok(self.fetch_snark_job()?.map(WorkerJob::Snark)),
        }
    }

    fn fetch_fri_job(&self) -> Result<Option<FriJob>> {
        let Some(input) = self.poll_json::<AirbenderVerifierInput>(FRI_INPUTS_PATH, FRI_LABEL)?
        else {
            return Ok(None);
        };
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

    fn fetch_snark_job(&self) -> Result<Option<SnarkJob>> {
        let Some(body) = self.poll_json::<SnarkInputResponse>(SNARK_INPUTS_PATH, SNARK_LABEL)?
        else {
            return Ok(None);
        };
        Ok(Some(SnarkJob {
            batch_number: body.l1_batch_number,
            protocol_version: body.protocol_version,
            fri_proof_bytes: body.fri_proof,
        }))
    }

    /// POSTs to `path` and decodes the JSON body. Returns `None` on 204 No
    /// Content. Unexpected statuses are logged and yield `None` (treated as
    /// "no job available" so the caller backs off).
    fn poll_json<R: DeserializeOwned>(&self, path: &str, label: &str) -> Result<Option<R>> {
        let url = format!("{}{path}", self.server_url);
        let response = self
            .poll_client
            .post(&url)
            .send()
            .with_context(|| format!("while polling {url}"))?;
        match response.status() {
            reqwest::StatusCode::OK => {
                Ok(Some(response.json::<R>().with_context(|| {
                    format!("while deserializing {label} input")
                })?))
            }
            reqwest::StatusCode::NO_CONTENT => Ok(None),
            status => {
                warn!(%status, label, "Unexpected status from job server");
                Ok(None)
            }
        }
    }

    // ----- submit --------------------------------------------------------

    fn submit_fri(&self, batch_number: u32, proof: &[u8]) {
        self.submit_with_retries(FRI_LABEL, batch_number, |attempt, attempts| {
            info!(
                batch_number,
                proof_bytes = proof.len(),
                attempt,
                attempts,
                "Submitting FRI proof"
            );
            let payload = SubmitFriProofRequest {
                l1_batch_number: batch_number,
                prover_id: self.prover_id.clone(),
                proof,
            };
            self.post_payload(FRI_LABEL, batch_number, SUBMIT_FRI_PATH, &payload)
        });
    }

    fn submit_snark(&self, batch_number: u32, proof: &[u8], vk: &[u8]) {
        self.submit_with_retries(SNARK_LABEL, batch_number, |attempt, attempts| {
            info!(
                batch_number,
                snark_proof_bytes = proof.len(),
                snark_vk_bytes = vk.len(),
                attempt,
                attempts,
                "Submitting SNARK proof"
            );
            let payload = SubmitSnarkProofRequest {
                l1_batch_number: batch_number,
                prover_id: self.prover_id.clone(),
                snark_proof: proof,
                snark_vk: vk,
            };
            self.post_payload(SNARK_LABEL, batch_number, SUBMIT_SNARK_PATH, &payload)
        });
    }

    /// POSTs `payload` as JSON and checks for HTTP success. Returns the status
    /// alongside any error so the caller can decide whether to retry.
    fn post_payload<P: Serialize>(
        &self,
        label: &str,
        batch_number: u32,
        path: &str,
        payload: &P,
    ) -> RequestResult {
        let url = format!("{}{path}", self.server_url);
        let response = self
            .submit_client
            .post(&url)
            .json(payload)
            .send()
            .with_context(|| format!("while submitting {label} proof to {url}"))
            .map_err(|e| (None, e))?;
        let status = response.status();
        if !status.is_success() {
            return Err((
                Some(status),
                anyhow::anyhow!(
                    "server returned {status} when submitting {label} proof for batch {batch_number}"
                ),
            ));
        }
        Ok(())
    }

    /// Retries `attempt_fn` up to `submit_attempts` times for retriable errors
    /// (transport-level or 429/5xx). Emits per-attempt warnings on failure
    /// and a single final success/error log.
    fn submit_with_retries<F>(&self, label: &str, batch_number: u32, mut attempt_fn: F)
    where
        F: FnMut(usize, usize) -> RequestResult,
    {
        let attempts = self.submit_attempts;
        let mut last_err = anyhow::anyhow!("no attempts made");
        for attempt in 1..=attempts {
            match attempt_fn(attempt, attempts) {
                Ok(()) => {
                    info!(batch_number, label, "Successfully submitted proof");
                    return;
                }
                Err((status, err)) => {
                    let retriable = status.is_none_or(|s| {
                        s == reqwest::StatusCode::TOO_MANY_REQUESTS || s.is_server_error()
                    });
                    if !retriable {
                        error!(
                            batch_number,
                            label,
                            ?err,
                            "Failed to submit proof (non-retriable status)"
                        );
                        return;
                    }
                    warn!(
                        label,
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
        error!(
            batch_number,
            label,
            submit_attempts = attempts,
            err = ?last_err,
            "Failed to submit proof after all attempts"
        );
    }
}
