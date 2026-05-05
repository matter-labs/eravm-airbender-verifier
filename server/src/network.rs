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
        &cfg.prover_id,
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
            let batch_number = input.vm_run_data.l1_batch_number.0;
            let protocol_version = input.vm_run_data.protocol_version as u16;
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

/// Serializes `AirbenderVerifierInput` to the `Vec<u32>` word stream expected by the prover.
///
/// Format: the first word is the byte length of the serialized input, followed by the
/// bincode-serialized data packed into big-endian u32 words (last word zero-padded if needed).
/// This matches `encode_to_words` from the `airbender_prover_interface` crate in zksync-era.
fn input_to_words(input: &AirbenderVerifierInput) -> Result<Vec<u32>> {
    let bytes = bincode::serde::encode_to_vec(input, bincode::config::standard())
        .context("while serializing AirbenderVerifierInput")?;
    frame_bytes(&bytes)
}

/// Frames a byte slice into the packed u32 word format expected by the guest.
///
/// Layout: `[byte_len as u32] ++ [bytes packed into big-endian u32 words, last zero-padded]`.
/// Matches `encode_to_words` from the `airbender_prover_interface` crate in zksync-era.
fn frame_bytes(bytes: &[u8]) -> Result<Vec<u32>> {
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

/// Inverts `frame_bytes`: strips the length word and returns the original bytes.
#[cfg(test)]
fn unframe_words(words: &[u32]) -> Result<Vec<u8>> {
    let (&byte_len_word, payload) = words
        .split_first()
        .context("framed payload has no length word")?;
    let byte_len = byte_len_word as usize;
    let available = payload.len() * 4;
    if byte_len > available {
        anyhow::bail!("declared length {byte_len} exceeds available bytes {available}");
    }
    let mut bytes: Vec<u8> = payload.iter().flat_map(|w| w.to_be_bytes()).collect();
    bytes.truncate(byte_len);
    Ok(bytes)
}

fn submit_result_with_retries(
    client: &reqwest::blocking::Client,
    base_url: &str,
    prover_id: &str,
    batch_number: u32,
    proof_bytes: &[u8],
    attempts: usize,
) -> Result<()> {
    let mut last_err = anyhow::anyhow!("no attempts made");
    for attempt in 1..=attempts {
        match submit_result(client, base_url, prover_id, batch_number, proof_bytes) {
            Ok(()) => return Ok(()),
            Err((status, err)) => {
                // 4xx errors (other than 429 Too Many Requests) are not retriable —
                // the same payload will be rejected every time.
                let retriable = status.is_none_or(|s| {
                    s == reqwest::StatusCode::TOO_MANY_REQUESTS || s.is_server_error()
                });
                if !retriable {
                    return Err(err);
                }
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

/// Submits a proof to `POST /airbender/submit_proofs`.
///
/// The body mirrors `SubmitAirbenderProofRequest` from zksync-era:
/// `{ "l1_batch_number": <u32>, "prover_id": "<string>", "proof": "<hex-encoded bytes>" }`.
///
/// Returns `Ok(())` on success, or `Err((status, err))` where `status` is the HTTP status code
/// if the server responded (or `None` for transport-level errors).
fn submit_result(
    client: &reqwest::blocking::Client,
    base_url: &str,
    prover_id: &str,
    batch_number: u32,
    proof_bytes: &[u8],
) -> Result<(), (Option<reqwest::StatusCode>, anyhow::Error)> {
    let url = format!("{base_url}/airbender/submit_proofs");
    let payload = SubmitProofRequest {
        l1_batch_number: batch_number,
        prover_id: prover_id.to_owned(),
        proof: proof_bytes,
    };
    info!(
        batch_number,
        proof_bytes = proof_bytes.len(),
        "Submitting proof"
    );
    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .with_context(|| format!("while submitting proof to {url}"))
        .map_err(|e| (None, e))?;

    let status = response.status();
    if !status.is_success() {
        return Err((
            Some(status),
            anyhow::anyhow!(
                "server returned {status} when submitting proof for batch {batch_number}"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zksync_airbender_verifier::types::{
        AirbenderVerifierInput, VMRunWitnessInputData, WitnessInputMerklePaths,
    };
    use zksync_contracts::{BaseSystemContracts, SystemContractCode};
    use zksync_multivm::interface::{L1BatchEnv, L2BlockEnv, SystemEnv, TxExecutionMode};
    use zksync_types::H256;

    use super::{frame_bytes, input_to_words, unframe_words};

    // --- framing unit tests (mirror the reference implementation's test suite) ---

    #[test]
    fn frame_with_padding() {
        let input = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let words = frame_bytes(&input).unwrap();
        assert_eq!(words[0], 5);
        assert_eq!(words.len(), 3);
        assert_eq!(words[1], 0x01020304);
        assert_eq!(words[2], 0x05000000);
        assert_eq!(unframe_words(&words).unwrap(), input);
    }

    #[test]
    fn frame_exact_multiple_of_four() {
        let input = [0xAAu8, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
        let words = frame_bytes(&input).unwrap();
        assert_eq!(words[0], 8);
        assert_eq!(words.len(), 3);
        assert_eq!(words[1], 0xAABBCCDD);
        assert_eq!(words[2], 0x11223344);
        assert_eq!(unframe_words(&words).unwrap(), input);
    }

    #[test]
    fn frame_empty() {
        let words = frame_bytes(&[]).unwrap();
        assert_eq!(words, vec![0]);
        assert!(unframe_words(&words).unwrap().is_empty());
    }

    #[test]
    fn frame_single_byte() {
        let input = [0xABu8];
        let words = frame_bytes(&input).unwrap();
        assert_eq!(words[0], 1);
        assert_eq!(words[1], 0xAB000000);
        assert_eq!(unframe_words(&words).unwrap(), input);
    }

    // --- integration: input_to_words round-trips through bincode ---

    #[test]
    fn input_to_words_roundtrip() {
        let input = make_test_input();
        let words = input_to_words(&input).unwrap();

        // First word is the byte length.
        let byte_len = words[0] as usize;
        assert!(byte_len > 0, "serialized input should be non-empty");

        // Unframe and deserialize back.
        let bytes = unframe_words(&words).unwrap();
        assert_eq!(bytes.len(), byte_len);
        let (decoded, n): (AirbenderVerifierInput, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(n, bytes.len(), "no trailing bytes after deserialization");
        assert_eq!(decoded, input);
    }

    fn make_test_input() -> AirbenderVerifierInput {
        AirbenderVerifierInput {
            vm_run_data: VMRunWitnessInputData {
                l1_batch_number: Default::default(),
                used_bytecodes: Default::default(),
                initial_heap_content: vec![],
                protocol_version: Default::default(),
                bootloader_code: vec![],
                default_account_code_hash: Default::default(),
                evm_emulator_code_hash: Some(Default::default()),
                storage_refunds: vec![],
                pubdata_costs: vec![],
                witness_block_state: Default::default(),
            },
            merkle_paths: WitnessInputMerklePaths::new(0),
            l2_blocks_execution_data: vec![],
            l1_batch_env: L1BatchEnv {
                previous_batch_hash: Some(H256([1; 32])),
                number: Default::default(),
                timestamp: 0,
                fee_input: Default::default(),
                fee_account: Default::default(),
                enforced_base_fee: None,
                first_l2_block: L2BlockEnv {
                    number: 0,
                    timestamp: 0,
                    prev_block_hash: H256([1; 32]),
                    max_virtual_blocks_to_create: 0,
                    interop_roots: vec![],
                },
            },
            system_env: SystemEnv {
                zk_porter_available: false,
                version: Default::default(),
                base_system_smart_contracts: BaseSystemContracts {
                    bootloader: SystemContractCode {
                        code: vec![1; 32],
                        hash: H256([1; 32]),
                    },
                    default_aa: SystemContractCode {
                        code: vec![1; 32],
                        hash: H256([1; 32]),
                    },
                    evm_emulator: None,
                },
                bootloader_gas_limit: 0,
                execution_mode: TxExecutionMode::VerifyExecute,
                default_validation_computational_gas_limit: 0,
                chain_id: Default::default(),
            },
            pubdata_params: Default::default(),
            commitment_input: None,
        }
    }
}
