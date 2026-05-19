use std::sync::mpsc::{Receiver, SendError, SyncSender};

use airbender_host::Proof;
use anyhow::{Context, Result};
use eravm_prover_host::{FriPipeline, FriVerifier, RawFriProof, SnarkPipeline};
use tracing::info;

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
                let outcome =
                    match fri.prove_fri(j.batch_number, j.protocol_version, &j.input_words) {
                        Ok((proof, _)) => Outcome::fri_success(j.batch_number, proof),
                        Err(err) => Outcome::failed(j.batch_number, ProofKind::Fri, err),
                    };
                self.result_tx.send(outcome)
            }
            (PipelineMode::FriSnark { fri, snark }, WorkerJob::Fri(j)) => {
                let (proof_bytes, proof) =
                    match fri.prove_fri(j.batch_number, j.protocol_version, &j.input_words) {
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
                    .and_then(|raw| snark.wrap_snark(j.batch_number, j.protocol_version, raw));
                self.result_tx
                    .send(snark_outcome(j.batch_number, snark_result))
            }
            (PipelineMode::SnarkOnly { verifier, snark }, WorkerJob::Snark(j)) => {
                let result = decode_and_verify(verifier, &j)
                    .and_then(|raw| snark.wrap_snark(j.batch_number, j.protocol_version, raw));
                self.result_tx.send(snark_outcome(j.batch_number, result))
            }
            _ => unreachable!("network worker fetched a job that doesn't match PipelineMode"),
        }
    }
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
