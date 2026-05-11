use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant};

use eravm_prover_host::FriPipeline;
use tracing::{error, info};
use zksync_prover_metrics::{ProofLabels, ProofStatus, METRICS};

use crate::types::{CompletedProof, Job};

/// Receives jobs, proves them, and sends completed proofs back to the network worker.
///
/// Runs independently so the network worker can submit the previous proof and pre-fetch
/// the next job while this thread is busy proving.
pub fn prover_worker(
    pipeline: FriPipeline,
    job_rx: Receiver<Job>,
    result_tx: SyncSender<CompletedProof>,
) {
    for job in job_rx {
        if let Some(completed) = prove_job(&pipeline, &job) {
            if result_tx.send(completed).is_err() {
                break;
            }
        }
    }
}

fn prove_job(pipeline: &FriPipeline, job: &Job) -> Option<CompletedProof> {
    info!(batch_number = job.batch_number, "Starting proof...");
    let started_at = Instant::now();

    match pipeline.prove_input(job.batch_number as u64, &job.input_words) {
        Err(err) => {
            record_metrics(job, ProofStatus::Failure, started_at.elapsed());
            error!(
                batch_number = job.batch_number,
                ?err,
                "Failed to prove batch"
            );
            None
        }
        Ok(prove_output) => {
            record_metrics(job, ProofStatus::Success, started_at.elapsed());
            match bincode::serde::encode_to_vec(&prove_output.proof, bincode::config::standard()) {
                Err(err) => {
                    error!(
                        batch_number = job.batch_number,
                        ?err,
                        "Failed to serialize proof"
                    );
                    None
                }
                Ok(proof_bytes) => {
                    info!(
                        batch_number = job.batch_number,
                        cycles = prove_output.cycles,
                        output = ?prove_output.output,
                        "Proof complete, forwarding to network worker"
                    );
                    Some(CompletedProof {
                        batch_number: job.batch_number,
                        proof_bytes,
                    })
                }
            }
        }
    }
}

fn record_metrics(job: &Job, status: ProofStatus, elapsed: Duration) {
    let labels = ProofLabels {
        batch_number: job.batch_number,
        protocol_version: job.protocol_version,
        status,
    };
    METRICS.proof_duration[&labels].observe(elapsed);
    METRICS.proof_count[&labels].inc();
}
