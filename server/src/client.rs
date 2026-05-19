use std::time::Duration;

use airbender_host::Inputs;
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{error, info, warn};
use zksync_airbender_verifier::types::AirbenderVerifierInput;

use crate::types::{
    FriJob, SnarkInputResponse, SnarkJob, SubmitFriProofRequest, SubmitSnarkProofRequest,
};

const FRI_INPUTS_PATH: &str = "/airbender/proof_inputs";
const SNARK_INPUTS_PATH: &str = "/airbender/snark_inputs";
const SUBMIT_FRI_PATH: &str = "/airbender/submit_proofs";
const SUBMIT_SNARK_PATH: &str = "/airbender/submit_snark_proofs";

const FRI_LABEL: &str = "FRI";
const SNARK_LABEL: &str = "SNARK";

/// Status code + error pair returned by request-level helpers; `None` for
/// transport-level errors that have no server status.
type RequestResult = Result<(), (Option<reqwest::StatusCode>, anyhow::Error)>;

/// Thin HTTP client for the job server: fetches inputs and submits results.
/// Stateless beyond its configured endpoints and HTTP clients — owns no
/// scheduling, channels, or in-flight job state.
pub struct JobServerClient {
    /// Used for polling job inputs (shorter timeout).
    poll_client: reqwest::blocking::Client,
    /// Used for submitting proof results (longer timeout for large SNARK payloads).
    submit_client: reqwest::blocking::Client,
    server_url: String,
    prover_id: String,
    submit_attempts: usize,
}

impl JobServerClient {
    pub fn new(
        prover_id: String,
        submit_attempts: usize,
        server_url: String,
        connection_timeout: Duration,
        poll_timeout: Duration,
        submit_timeout: Duration,
    ) -> Self {
        let poll_client = reqwest::blocking::Client::builder()
            .connect_timeout(connection_timeout)
            .timeout(poll_timeout)
            .build()
            .expect("while building poll HTTP client");
        let submit_client = reqwest::blocking::Client::builder()
            .connect_timeout(connection_timeout)
            .timeout(submit_timeout)
            .build()
            .expect("while building submit HTTP client");
        Self {
            poll_client,
            submit_client,
            server_url,
            prover_id,
            submit_attempts,
        }
    }

    pub fn fetch_fri_job(&self) -> Result<Option<FriJob>> {
        let Some(input) = self.poll_json::<AirbenderVerifierInput>(FRI_INPUTS_PATH, FRI_LABEL)?
        else {
            return Ok(None);
        };
        let AirbenderVerifierInput::V1(ref v1) = input else {
            anyhow::bail!("expected AirbenderVerifierInput::V1");
        };
        let batch_number = v1.vm_run_data.l1_batch_number.0;
        let mut inputs = Inputs::new();
        inputs
            .push(&input)
            .context("failed to encode AirbenderVerifierInput")?;
        Ok(Some(FriJob {
            batch_number,
            input_words: inputs.words().to_vec(),
        }))
    }

    pub fn fetch_snark_job(&self) -> Result<Option<SnarkJob>> {
        let Some(body) = self.poll_json::<SnarkInputResponse>(SNARK_INPUTS_PATH, SNARK_LABEL)?
        else {
            return Ok(None);
        };
        Ok(Some(SnarkJob {
            batch_number: body.l1_batch_number,
            fri_proof_bytes: body.fri_proof,
        }))
    }

    pub fn submit_fri(&self, batch_number: u32, proof: &[u8]) {
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

    pub fn submit_snark(&self, batch_number: u32, proof: &[u8], vk: &[u8]) {
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
