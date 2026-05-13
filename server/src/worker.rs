use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant};

use airbender_host::Proof;
use anyhow::{Context, Result};
use eravm_prover_host::{FriPipeline, FriVerifier, RawFriProof, SnarkPipeline};
use tracing::{error, info};
use zksync_prover_metrics::{ProofLabels, ProofStatus, METRICS};

use crate::types::{
    CompletedFriProof, CompletedSnarkProof, CompletedWork, FriJob, ProverMode, SnarkJob,
};

/// Jobs received from the network worker. The variant in flight is driven by
/// the configured [`ProverMode`].
pub enum WorkerJob {
    Fri(FriJob),
    Snark(SnarkJob),
}

/// Prover pipelines available to the worker; populated per mode.
pub struct WorkerPipelines {
    pub mode: ProverMode,
    pub fri: Option<FriPipeline>,
    pub fri_verifier: Option<FriVerifier>,
    pub snark: Option<SnarkPipeline>,
}

/// Receives jobs, proves them according to the configured mode, and sends
/// completed work back to the network worker.
pub fn prover_worker(
    mut pipelines: WorkerPipelines,
    job_rx: Receiver<WorkerJob>,
    result_tx: SyncSender<CompletedWork>,
) {
    for job in job_rx {
        let outputs = match (pipelines.mode, job) {
            (ProverMode::FriOnly, WorkerJob::Fri(fri_job)) => run_fri_only(&pipelines, &fri_job),
            (ProverMode::FriSnark, WorkerJob::Fri(fri_job)) => {
                run_fri_then_snark(&mut pipelines, &fri_job)
            }
            (ProverMode::SnarkOnly, WorkerJob::Snark(snark_job)) => {
                run_snark_only(&mut pipelines, &snark_job)
            }
            (mode, job) => {
                let kind = match job {
                    WorkerJob::Fri(_) => "FRI",
                    WorkerJob::Snark(_) => "SNARK",
                };
                error!(?mode, kind, "Worker received job that does not match mode");
                continue;
            }
        };

        for output in outputs {
            if result_tx.send(output).is_err() {
                return;
            }
        }
    }
}

fn run_fri_only(pipelines: &WorkerPipelines, job: &FriJob) -> Vec<CompletedWork> {
    let fri = pipelines.fri.as_ref().expect("FRI pipeline missing");
    match prove_fri(fri, job) {
        Some(completed) => vec![CompletedWork::Fri(completed)],
        None => Vec::new(),
    }
}

fn run_fri_then_snark(pipelines: &mut WorkerPipelines, job: &FriJob) -> Vec<CompletedWork> {
    let fri = pipelines.fri.as_ref().expect("FRI pipeline missing");
    let Some(fri_output) = prove_fri_full(fri, job) else {
        return Vec::new();
    };

    let mut outputs = vec![CompletedWork::Fri(CompletedFriProof {
        batch_number: job.batch_number,
        proof_bytes: fri_output.proof_bytes,
    })];

    let raw_proof = match fri_output.proof {
        Proof::Real(real) => real.into_inner(),
        Proof::Dev(_) => {
            error!(
                batch_number = job.batch_number,
                "GPU prover returned a development proof unexpectedly; skipping SNARK wrap"
            );
            return outputs;
        }
    };

    let snark = pipelines.snark.as_mut().expect("SNARK pipeline missing");
    match prove_snark(snark, job.batch_number, job.protocol_version, raw_proof) {
        Some(snark_completed) => outputs.push(CompletedWork::Snark(snark_completed)),
        None => {
            // FRI is already in `outputs`; submitting it alone is still useful.
        }
    }
    outputs
}

fn run_snark_only(pipelines: &mut WorkerPipelines, job: &SnarkJob) -> Vec<CompletedWork> {
    let raw_proof = match decode_and_verify_fri_proof(pipelines, job) {
        Ok(raw) => raw,
        Err(err) => {
            error!(
                batch_number = job.batch_number,
                ?err,
                "Rejected FRI proof input for SNARK wrapping"
            );
            return Vec::new();
        }
    };

    let snark = pipelines.snark.as_mut().expect("SNARK pipeline missing");
    match prove_snark(snark, job.batch_number, job.protocol_version, raw_proof) {
        Some(completed) => vec![CompletedWork::Snark(completed)],
        None => Vec::new(),
    }
}

fn decode_and_verify_fri_proof(pipelines: &WorkerPipelines, job: &SnarkJob) -> Result<RawFriProof> {
    let (proof, decoded_len): (Proof, usize) =
        bincode::serde::decode_from_slice(&job.fri_proof_bytes, bincode::config::standard())
            .context("failed to bincode-decode incoming FRI proof envelope")?;
    if decoded_len != job.fri_proof_bytes.len() {
        anyhow::bail!("incoming FRI proof envelope has trailing bytes");
    }

    let verifier = pipelines
        .fri_verifier
        .as_ref()
        .context("snark-only mode is missing the FRI verifier")?;
    verifier.verify_envelope(job.batch_number as u64, &proof)?;
    info!(
        batch_number = job.batch_number,
        "Verified incoming FRI proof"
    );

    match proof {
        Proof::Real(real) => Ok(real.into_inner()),
        Proof::Dev(_) => anyhow::bail!("snark-only mode received a dev proof"),
    }
}

struct FriOutputBytes {
    proof: Proof,
    proof_bytes: Vec<u8>,
}

fn prove_fri(pipeline: &FriPipeline, job: &FriJob) -> Option<CompletedFriProof> {
    prove_fri_full(pipeline, job).map(|out| CompletedFriProof {
        batch_number: job.batch_number,
        proof_bytes: out.proof_bytes,
    })
}

fn prove_fri_full(pipeline: &FriPipeline, job: &FriJob) -> Option<FriOutputBytes> {
    info!(batch_number = job.batch_number, "Starting FRI proof...");
    let started_at = Instant::now();

    match pipeline.prove_input(job.batch_number as u64, &job.input_words) {
        Err(err) => {
            record_fri_metrics(job, ProofStatus::Failure, started_at.elapsed());
            error!(
                batch_number = job.batch_number,
                ?err,
                "Failed to prove batch"
            );
            None
        }
        Ok(prove_output) => {
            record_fri_metrics(job, ProofStatus::Success, started_at.elapsed());
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
                        "FRI proof complete"
                    );
                    Some(FriOutputBytes {
                        proof: prove_output.proof,
                        proof_bytes,
                    })
                }
            }
        }
    }
}

fn prove_snark(
    pipeline: &mut SnarkPipeline,
    batch_number: u32,
    protocol_version: u16,
    raw_proof: RawFriProof,
) -> Option<CompletedSnarkProof> {
    info!(batch_number, "Starting SNARK wrapping...");
    let started_at = Instant::now();
    match pipeline.prove_to_bytes(raw_proof) {
        Err(err) => {
            record_snark_metrics(
                batch_number,
                protocol_version,
                ProofStatus::Failure,
                started_at.elapsed(),
            );
            error!(batch_number, ?err, "Failed to wrap batch into SNARK");
            None
        }
        Ok(artifact) => {
            record_snark_metrics(
                batch_number,
                protocol_version,
                ProofStatus::Success,
                started_at.elapsed(),
            );
            info!(
                batch_number,
                snark_proof_bytes = artifact.snark_proof.len(),
                snark_vk_bytes = artifact.snark_vk.len(),
                "SNARK wrap complete"
            );
            Some(CompletedSnarkProof {
                batch_number,
                snark_proof_bytes: artifact.snark_proof,
                snark_vk_bytes: artifact.snark_vk,
            })
        }
    }
}

fn record_fri_metrics(job: &FriJob, status: ProofStatus, elapsed: Duration) {
    let labels = ProofLabels {
        batch_number: job.batch_number,
        protocol_version: job.protocol_version,
        status,
    };
    METRICS.proof_duration[&labels].observe(elapsed);
    METRICS.proof_count[&labels].inc();
}

fn record_snark_metrics(
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
