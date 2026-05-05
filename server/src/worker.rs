use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant};

#[cfg(feature = "gpu")]
use airbender_host::Prover as _;
#[cfg(not(feature = "gpu"))]
use airbender_host::Runner as _;
use tracing::{error, info};
use zksync_prover_metrics::{ProofLabels, ProofStatus, METRICS};

use crate::types::{CompletedProof, Job};

/// The concrete prover used by `prover_worker`. GPU build links the FRI prover;
/// non-GPU build uses the RISC-V transpiler/interpreter (no real proof produced).
#[cfg(feature = "gpu")]
pub type ProverImpl = airbender_host::GpuProver;
#[cfg(not(feature = "gpu"))]
pub type ProverImpl = airbender_host::TranspilerRunner;

/// Receives jobs, proves (or simulates) them, and sends completed proofs back to the network worker.
///
/// Runs independently so the network worker can submit the previous proof and pre-fetch
/// the next job while this thread is busy.
pub fn prover_worker(
    prover: ProverImpl,
    job_rx: Receiver<Job>,
    result_tx: SyncSender<CompletedProof>,
) {
    for job in job_rx {
        if let Some(completed) = prove_job(&prover, &job) {
            if result_tx.send(completed).is_err() {
                break;
            }
        }
    }
}

#[cfg(feature = "gpu")]
fn prove_job(prover: &ProverImpl, job: &Job) -> Option<CompletedProof> {
    info!(batch_number = job.batch_number, "Starting proof...");
    let started_at = Instant::now();

    match prover.prove(&job.input_words) {
        Err(err) => {
            record_metrics(job, ProofStatus::Failure, started_at.elapsed());
            error!(
                batch_number = job.batch_number,
                ?err,
                "Failed to prove batch"
            );
            None
        }
        Ok(prove_result) => {
            record_metrics(job, ProofStatus::Success, started_at.elapsed());
            match bincode::serde::encode_to_vec(&prove_result.proof, bincode::config::standard()) {
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
                        cycles = prove_result.cycles,
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

#[cfg(not(feature = "gpu"))]
fn prove_job(prover: &ProverImpl, job: &Job) -> Option<CompletedProof> {
    info!(batch_number = job.batch_number, "Starting simulation...");
    let started_at = Instant::now();

    match prover.run(&job.input_words) {
        Err(err) => {
            record_metrics(job, ProofStatus::Failure, started_at.elapsed());
            error!(batch_number = job.batch_number, ?err, "Simulator failed");
            None
        }
        Ok(execution) => {
            if !execution.reached_end {
                record_metrics(job, ProofStatus::Failure, started_at.elapsed());
                error!(
                    batch_number = job.batch_number,
                    cycles = execution.cycles_executed,
                    "Simulator did not reach end of program"
                );
                return None;
            }
            record_metrics(job, ProofStatus::Success, started_at.elapsed());
            info!(
                batch_number = job.batch_number,
                cycles = execution.cycles_executed,
                "Simulation complete (no proof generated, submitting empty bytes)"
            );
            Some(CompletedProof {
                batch_number: job.batch_number,
                proof_bytes: vec![],
            })
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
