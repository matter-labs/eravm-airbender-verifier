use std::sync::mpsc::{Receiver, SendError, SyncSender};
use std::time::{Duration, Instant};

use airbender_host::Proof;
use anyhow::Context;
use eravm_prover_host::{FriPipeline, FriVerifier, RawFriProof, SnarkPipeline};
use tracing::{error, info};
use zksync_prover_metrics::{ProofLabels, ProofStatus, ProofType, METRICS};

use crate::types::{Artifact, FriJob, Outcome, ProofKind, SnarkJob};

/// Jobs received from the network worker. The variant is implied by
/// `PipelineMode`; a mismatch is a network-worker bug.
pub enum WorkerJob {
    Fri(FriJob),
    Snark(SnarkJob),
}

impl WorkerJob {
    pub fn batch_number(&self) -> u32 {
        match self {
            WorkerJob::Fri(j) => j.batch_number,
            WorkerJob::Snark(j) => j.batch_number,
        }
    }
}

impl std::fmt::Display for WorkerJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerJob::Fri(_) => f.write_str("FRI"),
            WorkerJob::Snark(_) => f.write_str("SNARK"),
        }
    }
}

/// Pipelines required by each operating mode. Owning the pipelines in the
/// variant means a missing pipeline is impossible at runtime.
pub enum PipelineMode {
    FriOnly(FriPipeline),
    FriSnark(FriPipeline, SnarkPipeline),
    SnarkOnly(FriVerifier, SnarkPipeline),
}

pub struct ProverWorker {
    mode: PipelineMode,
    job_rx: Receiver<WorkerJob>,
    result_tx: SyncSender<Outcome>,
}

impl ProverWorker {
    pub fn new(
        mode: PipelineMode,
        job_rx: Receiver<WorkerJob>,
        result_tx: SyncSender<Outcome>,
    ) -> Self {
        Self {
            mode,
            job_rx,
            result_tx,
        }
    }

    /// Receives jobs and streams settlement outcomes back. Exits when either
    /// channel is closed.
    pub fn run(mut self) {
        while let Ok(job) = self.job_rx.recv() {
            if self.process(job).is_err() {
                return;
            }
        }
    }

    fn process(&mut self, job: WorkerJob) -> Result<(), SendError<Outcome>> {
        match (&mut self.mode, job) {
            (PipelineMode::FriOnly(fri), WorkerJob::Fri(j)) => {
                prove_fri(fri, &j, &self.result_tx).map(|_| ())
            }
            (PipelineMode::FriSnark(fri, snark), WorkerJob::Fri(j)) => {
                let Some(proof) = prove_fri(fri, &j, &self.result_tx)? else {
                    return Ok(());
                };
                let raw = match unwrap_real_proof(proof, j.batch_number) {
                    Ok(raw) => raw,
                    Err(outcome) => return self.result_tx.send(outcome),
                };
                let outcome = wrap_snark(snark, j.batch_number, j.protocol_version, raw);
                self.result_tx.send(outcome)
            }
            (PipelineMode::SnarkOnly(verifier, snark), WorkerJob::Snark(j)) => {
                let raw = match decode_and_verify(verifier, &j) {
                    Ok(raw) => raw,
                    Err(reason) => {
                        return self.result_tx.send(Outcome {
                            batch_number: j.batch_number,
                            kind: ProofKind::Snark,
                            result: Err(reason),
                        });
                    }
                };
                let outcome = wrap_snark(snark, j.batch_number, j.protocol_version, raw);
                self.result_tx.send(outcome)
            }
            _ => unreachable!("network worker fetched a job that doesn't match PipelineMode"),
        }
    }
}

/// Runs the FRI prover and emits exactly one `Outcome` (kind = `Fri`).
/// Returns the in-memory `Proof` so `FriSnark` mode can wrap it without
/// re-decoding the serialized bytes.
fn prove_fri(
    pipeline: &FriPipeline,
    job: &FriJob,
    tx: &SyncSender<Outcome>,
) -> Result<Option<Proof>, SendError<Outcome>> {
    info!(batch_number = job.batch_number, "Starting FRI proof...");
    let started_at = Instant::now();

    let output = match pipeline.prove_input(job.batch_number as u64, &job.input_words) {
        Ok(o) => {
            record_metrics(
                job.batch_number,
                job.protocol_version,
                ProofType::Fri,
                ProofStatus::Success,
                started_at.elapsed(),
            );
            o
        }
        Err(err) => {
            record_metrics(
                job.batch_number,
                job.protocol_version,
                ProofType::Fri,
                ProofStatus::Failure,
                started_at.elapsed(),
            );
            error!(
                batch_number = job.batch_number,
                ?err,
                "Failed to prove batch"
            );
            tx.send(Outcome {
                batch_number: job.batch_number,
                kind: ProofKind::Fri,
                result: Err("FRI proving failed".to_owned()),
            })?;
            return Ok(None);
        }
    };

    let proof_bytes =
        match bincode::serde::encode_to_vec(&output.proof, bincode::config::standard()) {
            Ok(b) => b,
            Err(err) => {
                error!(
                    batch_number = job.batch_number,
                    ?err,
                    "Failed to serialize proof"
                );
                tx.send(Outcome {
                    batch_number: job.batch_number,
                    kind: ProofKind::Fri,
                    result: Err("FRI proof serialization failed".to_owned()),
                })?;
                return Ok(None);
            }
        };

    info!(
        batch_number = job.batch_number,
        cycles = output.cycles,
        output = ?output.output,
        "FRI proof complete"
    );
    tx.send(Outcome {
        batch_number: job.batch_number,
        kind: ProofKind::Fri,
        result: Ok(Artifact::Fri { proof: proof_bytes }),
    })?;
    Ok(Some(output.proof))
}

fn wrap_snark(
    pipeline: &mut SnarkPipeline,
    batch_number: u32,
    protocol_version: u16,
    raw_proof: RawFriProof,
) -> Outcome {
    info!(batch_number, "Starting SNARK wrapping...");
    let started_at = Instant::now();
    match pipeline.wrap_fri(raw_proof) {
        Ok(artifact) => {
            record_metrics(
                batch_number,
                protocol_version,
                ProofType::Snark,
                ProofStatus::Success,
                started_at.elapsed(),
            );
            info!(
                batch_number,
                snark_proof_bytes = artifact.snark_proof.len(),
                snark_vk_bytes = artifact.snark_vk.len(),
                "SNARK wrap complete"
            );
            Outcome {
                batch_number,
                kind: ProofKind::Snark,
                result: Ok(Artifact::Snark {
                    proof: artifact.snark_proof,
                    vk: artifact.snark_vk,
                }),
            }
        }
        Err(err) => {
            record_metrics(
                batch_number,
                protocol_version,
                ProofType::Snark,
                ProofStatus::Failure,
                started_at.elapsed(),
            );
            error!(batch_number, ?err, "Failed to wrap batch into SNARK");
            Outcome {
                batch_number,
                kind: ProofKind::Snark,
                result: Err("SNARK wrap failed".to_owned()),
            }
        }
    }
}

/// Unwraps a Real proof for SNARK wrapping; a Dev proof in production is a bug
/// that yields a SNARK-phase failure outcome.
fn unwrap_real_proof(proof: Proof, batch_number: u32) -> Result<RawFriProof, Outcome> {
    match proof {
        Proof::Real(real) => Ok(real.into_inner()),
        Proof::Dev(_) => {
            error!(
                batch_number,
                "GPU prover returned a development proof unexpectedly; skipping SNARK wrap"
            );
            Err(Outcome {
                batch_number,
                kind: ProofKind::Snark,
                result: Err("GPU prover returned a development proof".to_owned()),
            })
        }
    }
}

fn decode_and_verify(verifier: &FriVerifier, job: &SnarkJob) -> Result<RawFriProof, String> {
    let (proof, len): (Proof, usize) =
        bincode::serde::decode_from_slice(&job.fri_proof_bytes, bincode::config::standard())
            .context("failed to bincode-decode incoming FRI proof envelope")
            .map_err(|err| format!("{err:#}"))?;
    if len != job.fri_proof_bytes.len() {
        return Err("incoming FRI proof envelope has trailing bytes".to_owned());
    }
    verifier
        .verify_envelope(job.batch_number as u64, &proof)
        .map_err(|err| format!("FRI verification failed: {err:#}"))?;
    info!(
        batch_number = job.batch_number,
        "Verified incoming FRI proof"
    );
    match proof {
        Proof::Real(real) => Ok(real.into_inner()),
        Proof::Dev(_) => Err("snark-only mode received a dev proof".to_owned()),
    }
}

fn record_metrics(
    batch_number: u32,
    protocol_version: u16,
    proof_type: ProofType,
    status: ProofStatus,
    elapsed: Duration,
) {
    let labels = ProofLabels {
        batch_number,
        protocol_version,
        proof_type,
        status,
    };
    METRICS.proof_duration[&labels].observe(elapsed);
    METRICS.proof_count[&labels].inc();
}
