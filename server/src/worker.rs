use std::sync::mpsc::{Receiver, SendError, SyncSender};
use std::time::{Duration, Instant};

use airbender_host::Proof;
use anyhow::{Context, Result};
use eravm_prover_host::{FriPipeline, FriVerifier, RawFriProof, SnarkPipeline};
use tracing::info;
use zksync_prover_metrics::{ProofLabels, ProofStatus, ProofType, METRICS};

use crate::types::{FriJob, Outcome, ProofKind, SnarkJob};

/// Jobs received from the network worker. The variant is implied by
/// [`PipelineMode`]; a mismatch is a network-worker bug.
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

/// Internal pipeline state, derived from the builder at construction time.
/// Each variant carries exactly the pipelines that mode needs, so `process`
/// can match exhaustively without `Option` unwraps.
enum PipelineMode {
    FriOnly {
        fri: FriPipeline,
    },
    FriSnark {
        fri: FriPipeline,
        snark: SnarkPipeline,
    },
    SnarkOnly {
        verifier: FriVerifier,
        snark: SnarkPipeline,
    },
}

pub struct ProverWorker {
    mode: PipelineMode,
    job_rx: Receiver<WorkerJob>,
    result_tx: SyncSender<Outcome>,
}

/// Fluent builder for [`ProverWorker`]. Pipelines are added one at a time; the
/// combination is validated by [`Self::build`] against the supported modes.
#[derive(Default)]
pub struct ProverWorkerBuilder {
    fri: Option<FriPipeline>,
    fri_verifier: Option<FriVerifier>,
    snark: Option<SnarkPipeline>,
}

impl ProverWorkerBuilder {
    pub fn with_fri(mut self, fri: FriPipeline) -> Self {
        self.fri = Some(fri);
        self
    }

    pub fn with_fri_verifier(mut self, verifier: FriVerifier) -> Self {
        self.fri_verifier = Some(verifier);
        self
    }

    pub fn with_snark(mut self, snark: SnarkPipeline) -> Self {
        self.snark = Some(snark);
        self
    }

    /// Validates the configured pipelines against the supported modes and
    /// returns a ready-to-run [`ProverWorker`].
    ///
    /// Valid combinations: `fri-only` (FRI), `fri-snark` (FRI + SNARK),
    /// `snark-only` (FRI verifier + SNARK).
    pub fn build(
        self,
        job_rx: Receiver<WorkerJob>,
        result_tx: SyncSender<Outcome>,
    ) -> Result<ProverWorker> {
        let mode = match (self.fri, self.fri_verifier, self.snark) {
            (Some(fri), None, None) => PipelineMode::FriOnly { fri },
            (Some(fri), None, Some(snark)) => PipelineMode::FriSnark { fri, snark },
            (None, Some(verifier), Some(snark)) => PipelineMode::SnarkOnly { verifier, snark },
            (Some(_), Some(_), _) => {
                anyhow::bail!("ProverWorker builder: cannot set both `fri` and `fri_verifier`",)
            }
            (None, Some(_), None) => {
                anyhow::bail!("ProverWorker builder: `fri_verifier` requires `snark`")
            }
            (None, None, _) => {
                anyhow::bail!("ProverWorker builder: must set either `fri` or `fri_verifier`")
            }
        };
        Ok(ProverWorker {
            mode,
            job_rx,
            result_tx,
        })
    }
}

impl ProverWorker {
    pub fn builder() -> ProverWorkerBuilder {
        ProverWorkerBuilder::default()
    }

    /// Receives jobs and streams outcomes back. Exits when either channel closes.
    pub fn run(mut self) {
        while let Ok(job) = self.job_rx.recv() {
            if self.process(job).is_err() {
                return;
            }
        }
    }

    fn process(&mut self, job: WorkerJob) -> Result<(), SendError<Outcome>> {
        match (&mut self.mode, job) {
            (PipelineMode::FriOnly { fri }, WorkerJob::Fri(j)) => {
                let outcome = match prove_fri(fri, &j) {
                    Ok((proof, _)) => Outcome::fri_success(j.batch_number, proof),
                    Err(err) => Outcome::failed(j.batch_number, ProofKind::Fri, err),
                };
                self.result_tx.send(outcome)
            }
            (PipelineMode::FriSnark { fri, snark }, WorkerJob::Fri(j)) => {
                let (proof_bytes, proof) = match prove_fri(fri, &j) {
                    Ok(pair) => pair,
                    Err(err) => {
                        return self.result_tx.send(Outcome::failed(
                            j.batch_number,
                            ProofKind::Fri,
                            err,
                        ));
                    }
                };
                self.result_tx
                    .send(Outcome::fri_success(j.batch_number, proof_bytes))?;

                let snark_result = unwrap_real_proof(proof)
                    .and_then(|raw| wrap_snark(snark, j.batch_number, j.protocol_version, raw));
                self.result_tx
                    .send(snark_outcome(j.batch_number, snark_result))
            }
            (PipelineMode::SnarkOnly { verifier, snark }, WorkerJob::Snark(j)) => {
                let result = decode_and_verify(verifier, &j)
                    .and_then(|raw| wrap_snark(snark, j.batch_number, j.protocol_version, raw));
                self.result_tx.send(snark_outcome(j.batch_number, result))
            }
            _ => unreachable!("network worker fetched a job that doesn't match PipelineMode"),
        }
    }
}

/// Runs the FRI prover and bincode-serializes the result.
///
/// Returns both the serialized proof bytes (for submission) and the in-memory
/// [`Proof`] (for in-process SNARK wrapping in `fri-snark` mode).
fn prove_fri(pipeline: &FriPipeline, job: &FriJob) -> Result<(Vec<u8>, Proof)> {
    info!(batch_number = job.batch_number, "Starting FRI proof...");
    let started_at = Instant::now();
    let output = match pipeline.prove_input(job.batch_number as u64, &job.input_words) {
        Ok(out) => {
            record_metrics(
                job.batch_number,
                job.protocol_version,
                ProofType::Fri,
                ProofStatus::Success,
                started_at.elapsed(),
            );
            out
        }
        Err(err) => {
            record_metrics(
                job.batch_number,
                job.protocol_version,
                ProofType::Fri,
                ProofStatus::Failure,
                started_at.elapsed(),
            );
            return Err(err.context("FRI proving failed"));
        }
    };

    let proof_bytes = bincode::serde::encode_to_vec(&output.proof, bincode::config::standard())
        .context("failed to bincode-serialize FRI proof")?;

    info!(
        batch_number = job.batch_number,
        cycles = output.cycles,
        output = ?output.output,
        "FRI proof complete"
    );
    Ok((proof_bytes, output.proof))
}

fn wrap_snark(
    pipeline: &mut SnarkPipeline,
    batch_number: u32,
    protocol_version: u16,
    raw_proof: RawFriProof,
) -> Result<(Vec<u8>, Vec<u8>)> {
    info!(batch_number, "Starting SNARK wrapping...");
    let started_at = Instant::now();
    let artifact = match pipeline.wrap_fri(raw_proof) {
        Ok(a) => {
            record_metrics(
                batch_number,
                protocol_version,
                ProofType::Snark,
                ProofStatus::Success,
                started_at.elapsed(),
            );
            a
        }
        Err(err) => {
            record_metrics(
                batch_number,
                protocol_version,
                ProofType::Snark,
                ProofStatus::Failure,
                started_at.elapsed(),
            );
            return Err(err.context("SNARK wrap failed"));
        }
    };
    info!(
        batch_number,
        snark_proof_bytes = artifact.snark_proof.len(),
        snark_vk_bytes = artifact.snark_vk.len(),
        "SNARK wrap complete"
    );
    Ok((artifact.snark_proof, artifact.snark_vk))
}

fn unwrap_real_proof(proof: Proof) -> Result<RawFriProof> {
    match proof {
        Proof::Real(real) => Ok(real.into_inner()),
        Proof::Dev(_) => {
            anyhow::bail!("GPU prover returned a development proof; refusing to wrap into SNARK")
        }
    }
}

fn decode_and_verify(verifier: &FriVerifier, job: &SnarkJob) -> Result<RawFriProof> {
    let (proof, len): (Proof, usize) =
        bincode::serde::decode_from_slice(&job.fri_proof_bytes, bincode::config::standard())
            .context("failed to bincode-decode incoming FRI proof envelope")?;
    if len != job.fri_proof_bytes.len() {
        anyhow::bail!("incoming FRI proof envelope has trailing bytes");
    }
    verifier
        .verify_envelope(job.batch_number as u64, &proof)
        .context("incoming FRI proof failed verification")?;
    info!(
        batch_number = job.batch_number,
        "Verified incoming FRI proof"
    );
    unwrap_real_proof(proof)
}

fn snark_outcome(batch_number: u32, result: Result<(Vec<u8>, Vec<u8>)>) -> Outcome {
    match result {
        Ok((proof, vk)) => Outcome::snark_success(batch_number, proof, vk),
        Err(err) => Outcome::failed(batch_number, ProofKind::Snark, err),
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
