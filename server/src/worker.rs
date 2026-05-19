use std::sync::mpsc::{Receiver, SendError, SyncSender};
use std::time::{Duration, Instant};

use airbender_host::Proof;
use anyhow::Result;
use eravm_prover_host::{FriPipeline, SnarkPipeline};
use zksync_prover_metrics::{ProofLabels, ProofStatus, ProofType, METRICS};

use crate::types::{FailedProof, ProofKind, ProofOutcome, ProverResult, WorkerJob};

pub struct ProverWorker {
    fri: Option<FriPipeline>,
    snark: Option<SnarkPipeline>,
    job_rx: Receiver<WorkerJob>,
    result_tx: SyncSender<ProverResult>,
}

/// Fluent builder for [`ProverWorker`]. Pipelines are added one at a time; the
/// combination is validated by [`Self::build`] against the supported modes.
#[derive(Default)]
pub struct ProverWorkerBuilder {
    fri: Option<FriPipeline>,
    snark: Option<SnarkPipeline>,
}

impl ProverWorkerBuilder {
    pub fn with_fri(mut self, fri: FriPipeline) -> Self {
        self.fri = Some(fri);
        self
    }

    pub fn with_snark(mut self, snark: SnarkPipeline) -> Self {
        self.snark = Some(snark);
        self
    }

    /// Validates that at least one pipeline is configured and returns a
    /// ready-to-run [`ProverWorker`]. Valid combinations: `fri-only`,
    /// `fri-snark` (both pipelines), `snark-only` (SNARK pipeline with an
    /// attached FRI verifier).
    pub fn build(
        self,
        job_rx: Receiver<WorkerJob>,
        result_tx: SyncSender<ProverResult>,
    ) -> Result<ProverWorker> {
        if self.fri.is_none() && self.snark.is_none() {
            anyhow::bail!("ProverWorker builder: must set at least one of `fri` or `snark`");
        }
        Ok(ProverWorker {
            fri: self.fri,
            snark: self.snark,
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

    fn process(&mut self, job: WorkerJob) -> Result<(), SendError<ProverResult>> {
        let result = match job {
            WorkerJob::Fri {
                batch_number,
                input_words,
            } => {
                let started = Instant::now();
                let result = self
                    .fri
                    .as_mut()
                    .unwrap()
                    .prove_input(batch_number as u64, &input_words)
                    .map(|out| out.proof);
                record_proof_metrics(
                    batch_number,
                    ProofType::Fri,
                    status_of(&result),
                    started.elapsed(),
                );
                result
                    .map(|proof| ProofOutcome::Fri {
                        batch_number,
                        proof: Box::new(proof),
                    })
                    .map_err(|err| FailedProof::new(batch_number, ProofKind::Fri, err))
            }
            WorkerJob::Snark {
                batch_number,
                proof,
            } => match into_raw_fri_proof(*proof) {
                Ok(raw_proof) => {
                    let started = Instant::now();
                    let result = self.snark.as_mut().unwrap().run_wrap_pipeline(raw_proof);
                    record_proof_metrics(
                        batch_number,
                        ProofType::Snark,
                        status_of(&result),
                        started.elapsed(),
                    );
                    result
                        .map(|proof| ProofOutcome::Snark {
                            batch_number,
                            proof: Box::new(proof),
                        })
                        .map_err(|err| FailedProof::new(batch_number, ProofKind::Snark, err))
                }
                Err(err) => Err(FailedProof::new(batch_number, ProofKind::Snark, err)),
            },
        };
        self.result_tx.send(result)
    }
}

fn into_raw_fri_proof(proof: Proof) -> Result<eravm_prover_host::RawFriProof> {
    match proof {
        Proof::Real(real) => Ok(real.into_inner()),
        Proof::Dev(_) => {
            anyhow::bail!("received development FRI proof; refusing to wrap into SNARK")
        }
    }
}

fn status_of<T>(result: &Result<T>) -> ProofStatus {
    if result.is_ok() {
        ProofStatus::Success
    } else {
        ProofStatus::Failure
    }
}

fn record_proof_metrics(
    batch_number: u32,
    proof_type: ProofType,
    status: ProofStatus,
    elapsed: Duration,
) {
    let labels = ProofLabels {
        batch_number,
        proof_type,
        status,
    };
    METRICS.proof_duration[&labels].observe(elapsed);
    METRICS.proof_count[&labels].inc();
}
