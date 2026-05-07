use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant};

use airbender_host::{GpuProver, Proof, Prover};
use anyhow::{Context, Result};
use eravm_prover_host::{RawFriProof, SnarkPipeline};
use tracing::{error, info};
use zksync_prover_metrics::{ProofLabels, ProofStatus, METRICS};

use crate::types::{CompletedProof, Job, JobInput};

/// Per-mode pipeline state owned by the prover thread. Variants reflect which
/// stages run end-to-end on this server instance:
/// - `Fri`: prove FRI, submit FRI bytes (no SNARK).
/// - `FriSnark`: prove FRI, then wrap to SNARK locally.
/// - `Snark`: wrap an externally-supplied FRI proof.
pub enum Pipeline {
    Fri {
        prover: GpuProver,
    },
    FriSnark {
        prover: GpuProver,
        snark: SnarkPipeline,
    },
    Snark {
        snark: SnarkPipeline,
    },
}

/// Receives jobs, runs them through the configured pipeline, and ships completed
/// proofs back to the network worker.
///
/// Runs on its own thread so the network worker can submit the previous proof
/// and pre-fetch the next job while this thread is busy.
pub fn prover_worker(
    mut pipeline: Pipeline,
    job_rx: Receiver<Job>,
    result_tx: SyncSender<CompletedProof>,
) {
    for job in job_rx {
        if let Some(completed) = process_job(&mut pipeline, job) {
            if result_tx.send(completed).is_err() {
                break;
            }
        }
    }
}

fn process_job(pipeline: &mut Pipeline, job: Job) -> Option<CompletedProof> {
    let Job {
        batch_number,
        protocol_version,
        input,
    } = job;
    info!(batch_number, "Starting proof...");
    let started_at = Instant::now();

    let result: Result<SerializedProof> = match (pipeline, input) {
        (Pipeline::Fri { prover }, JobInput::Input(input_words)) => {
            run_fri(prover, &input_words).map(Into::into)
        }
        (Pipeline::FriSnark { prover, snark }, JobInput::Input(input_words)) => {
            run_fri(prover, &input_words).and_then(|prove| run_snark(snark, prove.fri_proof))
        }
        (Pipeline::Snark { snark }, JobInput::FriProof(raw)) => run_snark(snark, *raw),
        (Pipeline::Fri { .. } | Pipeline::FriSnark { .. }, JobInput::FriProof(_)) => Err(
            anyhow::anyhow!("received a FriProof job in a mode that proves FRI from input words"),
        ),
        (Pipeline::Snark { .. }, JobInput::Input(_)) => Err(anyhow::anyhow!(
            "received an Input job in snark-only mode (which expects a FRI proof)"
        )),
    };

    let elapsed = started_at.elapsed();
    match result {
        Ok(serialized) => {
            record_metrics(
                batch_number,
                protocol_version,
                ProofStatus::Success,
                elapsed,
            );
            info!(
                batch_number,
                bytes = serialized.bytes.len(),
                kind = serialized.kind,
                "Proof complete, forwarding to network worker"
            );
            Some(CompletedProof {
                batch_number,
                proof_bytes: serialized.bytes,
            })
        }
        Err(err) => {
            record_metrics(
                batch_number,
                protocol_version,
                ProofStatus::Failure,
                elapsed,
            );
            error!(batch_number, ?err, "Failed to produce proof");
            None
        }
    }
}

struct FriProveOutput {
    bytes: Vec<u8>,
    fri_proof: RawFriProof,
}

fn run_fri(prover: &GpuProver, input_words: &[u32]) -> Result<FriProveOutput> {
    let prove_result = prover
        .prove(input_words)
        .context("while attempting to generate FRI proof")?;
    let bytes = bincode::serde::encode_to_vec(&prove_result.proof, bincode::config::standard())
        .context("while attempting to serialize FRI proof")?;
    let fri_proof = match prove_result.proof {
        Proof::Real(proof) => proof.into_inner(),
        Proof::Dev(_) => anyhow::bail!("GPU prover returned a development proof unexpectedly"),
    };
    Ok(FriProveOutput { bytes, fri_proof })
}

struct SerializedProof {
    bytes: Vec<u8>,
    kind: &'static str,
}

impl From<FriProveOutput> for SerializedProof {
    fn from(value: FriProveOutput) -> Self {
        Self {
            bytes: value.bytes,
            kind: "fri",
        }
    }
}

fn run_snark(snark: &mut SnarkPipeline, fri_proof: RawFriProof) -> Result<SerializedProof> {
    let bytes = snark
        .wrap_proof_to_bytes(fri_proof)
        .context("while attempting to wrap FRI proof into a SNARK")?;
    Ok(SerializedProof {
        bytes,
        kind: "snark",
    })
}

fn record_metrics(
    batch_number: u32,
    protocol_version: u16,
    status: ProofStatus,
    elapsed: Duration,
) {
    let labels = ProofLabels {
        batch_number,
        protocol_version,
        status,
    };
    METRICS.proof_duration[&labels].observe(elapsed);
    METRICS.proof_count[&labels].inc();
}
