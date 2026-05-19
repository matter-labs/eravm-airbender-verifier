use std::sync::mpsc::{Receiver, SendError, SyncSender};

use anyhow::Result;
use eravm_prover_host::{FriPipeline, SnarkPipeline};

use crate::types::{FriJob, ProofKind, ProofOutcome, SnarkJob};

/// Jobs received from the job worker. Which variant is expected is implied
/// by which pipelines the worker was built with; a mismatch is a job-worker bug.
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

pub struct ProverWorker {
    fri: Option<FriPipeline>,
    snark: Option<SnarkPipeline>,
    job_rx: Receiver<WorkerJob>,
    result_tx: SyncSender<ProofOutcome>,
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
        result_tx: SyncSender<ProofOutcome>,
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

    fn process(&mut self, job: WorkerJob) -> Result<(), SendError<ProofOutcome>> {
        match job {
            WorkerJob::Fri(j) => {
                let outcome = match self
                    .fri
                    .as_mut()
                    .unwrap()
                    .prove_fri(j.batch_number, &j.input_words)
                {
                    Ok((proof, _)) => ProofOutcome::fri_success(j.batch_number, proof),
                    Err(err) => ProofOutcome::failed(j.batch_number, ProofKind::Fri, err),
                };
                self.result_tx.send(outcome)?;
            }
            WorkerJob::Snark(j) => {
                let snark = self.snark.as_mut().unwrap();
                let snark_result = snark.decode_and_wrap_snark(j.batch_number, &j.fri_proof_bytes);
                self.result_tx
                    .send(snark_outcome(j.batch_number, snark_result))?;
            }
        }
        Ok(())
    }
}

fn snark_outcome(batch_number: u32, result: Result<(Vec<u8>, Vec<u8>)>) -> ProofOutcome {
    match result {
        Ok((proof, vk)) => ProofOutcome::snark_success(batch_number, proof, vk),
        Err(err) => ProofOutcome::failed(batch_number, ProofKind::Snark, err),
    }
}
