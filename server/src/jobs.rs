use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{debug, error, info, warn};
use zksync_prover_metrics::METRICS;

use crate::client::JobServerClient;
use crate::types::{Artifact, ProofOutcome, ProverMode, SnarkJob};
use crate::worker::WorkerJob;

/// Orchestrates the network side of the prover: fetches jobs from the
/// [`JobServerClient`], forwards them to the prover thread, and submits
/// completed proofs through the client. Uses a one-slot pending buffer so a
/// job can be pre-fetched while the prover is busy.
pub struct JobWorker {
    mode: ProverMode,
    client: JobServerClient,
    job_tx: SyncSender<WorkerJob>,
    result_rx: Receiver<ProofOutcome>,
    poll_interval: Duration,
    shutdown: Arc<AtomicBool>,
    pending_job: Option<WorkerJob>,
}

impl JobWorker {
    pub fn new(
        client: JobServerClient,
        job_tx: SyncSender<WorkerJob>,
        result_rx: Receiver<ProofOutcome>,
        shutdown: Arc<AtomicBool>,
        mode: ProverMode,
        poll_interval: Duration,
    ) -> Self {
        Self {
            mode,
            client,
            job_tx,
            result_rx,
            poll_interval,
            shutdown,
            pending_job: None,
        }
    }

    pub fn run(mut self) {
        loop {
            let shutting_down = self.shutdown.load(Ordering::Relaxed);
            let mut did_work = false;

            if !shutting_down {
                if let Some(job) = self.pending_job.take() {
                    match self.job_tx.try_send(job) {
                        Ok(()) => did_work = true,
                        Err(TrySendError::Full(job)) => self.pending_job = Some(job),
                        Err(TrySendError::Disconnected(_)) => break,
                    }
                }
            }

            match self.result_rx.try_recv() {
                Ok(outcome) => {
                    self.handle_outcome(outcome);
                    did_work = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => break,
            }

            if shutting_down {
                break;
            }

            if self.pending_job.is_none() {
                match self.fetch_job() {
                    Ok(Some(job)) => {
                        info!(batch_number = job.batch_number(), %job, "Received job");
                        METRICS.pending_jobs.inc_by(1);
                        self.pending_job = Some(job);
                        did_work = true;
                    }
                    Ok(None) => debug!("No jobs available, waiting..."),
                    Err(err) => warn!(?err, "Failed to fetch job, retrying after poll interval"),
                }
            }

            if !did_work {
                std::thread::sleep(self.poll_interval);
            }
        }
    }

    fn fetch_job(&self) -> Result<Option<WorkerJob>> {
        match self.mode {
            ProverMode::FriOnly | ProverMode::FriSnark => {
                Ok(self.client.fetch_fri_job()?.map(WorkerJob::Fri))
            }
            ProverMode::SnarkOnly => Ok(self.client.fetch_snark_job()?.map(WorkerJob::Snark)),
        }
    }

    fn handle_outcome(&mut self, outcome: ProofOutcome) {
        let settles = outcome.settles_job(self.mode);
        match outcome.result {
            Ok(Artifact::Fri { proof }) => {
                self.client.submit_fri(outcome.batch_number, &proof);
                // In `fri-snark` mode, the SNARK job depends on the FRI proof bytes, so we can set the new pending job immediately instead of waiting for the next fetch cycle.
                if self.mode == ProverMode::FriSnark {
                    self.pending_job = Some(WorkerJob::Snark(SnarkJob {
                        batch_number: outcome.batch_number,
                        fri_proof_bytes: proof,
                    }));
                }
            }
            Ok(Artifact::Snark { proof, vk }) => {
                self.client.submit_snark(outcome.batch_number, &proof, &vk)
            }
            Err(failure) => error!(
                batch_number = outcome.batch_number,
                kind = %failure.kind,
                reason = %failure.reason,
                "Job failed; will not be submitted",
            ),
        }
        if settles {
            METRICS.pending_jobs.dec_by(1);
        }
    }
}
