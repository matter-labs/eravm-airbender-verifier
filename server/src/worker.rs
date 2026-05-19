use std::sync::mpsc::{Receiver, SendError, SyncSender};

use anyhow::Result;
use eravm_prover_host::{FriPipeline, SnarkPipeline};

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
            } => self
                .fri
                .as_mut()
                .unwrap()
                .prove_fri(batch_number, &input_words)
                .map(|(proof, _)| ProofOutcome::Fri {
                    batch_number,
                    proof,
                })
                .map_err(|err| FailedProof::new(batch_number, ProofKind::Fri, err)),
            WorkerJob::Snark {
                batch_number,
                fri_proof_bytes,
            } => self
                .snark
                .as_mut()
                .unwrap()
                .decode_and_wrap_snark(batch_number, &fri_proof_bytes)
                .map(|(proof, vk)| ProofOutcome::Snark {
                    batch_number,
                    proof,
                    vk,
                })
                .map_err(|err| FailedProof::new(batch_number, ProofKind::Snark, err)),
        };
        self.result_tx.send(result)
    }
}
