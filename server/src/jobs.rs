use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{debug, error, info, warn};
use zksync_prover_metrics::METRICS;

use crate::client::JobServerClient;
use crate::types::{ProofKind, ProofOutcome, ProverMode, ProverResult, WorkerJob};

/// Orchestrates the network side of the prover: fetches jobs from the
/// [`JobServerClient`], forwards them to the prover thread, and submits
/// completed proofs through the client. Uses a one-slot pending buffer so a
/// server-fetched FRI job can be pre-fetched while the prover is busy. In
/// `fri-snark` mode, a finished FRI produces a local SNARK follow-up that
/// lives in its own slot so it never clobbers the prefetched FRI.
pub struct JobWorker {
    mode: ProverMode,
    client: JobServerClient,
    job_tx: SyncSender<WorkerJob>,
    result_rx: Receiver<ProverResult>,
    poll_interval: Duration,
    shutdown: Arc<AtomicBool>,
    pending_job: Option<WorkerJob>,
    snark_followup: Option<WorkerJob>,
}

impl JobWorker {
    pub fn new(
        client: JobServerClient,
        job_tx: SyncSender<WorkerJob>,
        result_rx: Receiver<ProverResult>,
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
            snark_followup: None,
        }
    }

    pub fn run(mut self) {
        loop {
            let shutting_down = self.shutdown.load(Ordering::Relaxed);
            let mut did_work = false;

            if !shutting_down {
                // Drain the local SNARK follow-up before the prefetched FRI:
                // it represents work whose FRI half is already settled, and
                // keeping the order stable means a fresh prefetched FRI can
                // sit safely in `pending_job` until the prover is free again.
                if let Some(job) = self.snark_followup.take() {
                    match self.job_tx.try_send(job) {
                        Ok(()) => did_work = true,
                        Err(TrySendError::Full(job)) => self.snark_followup = Some(job),
                        Err(TrySendError::Disconnected(_)) => break,
                    }
                }
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
                    if let Err(err) = self.handle_prover_result(outcome) {
                        error!(?err, "Failed to handle prover outcome");
                    }
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
                        info!(batch_number = job.batch_number(), kind = %job.kind(), "Received job");
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
            ProverMode::FriOnly | ProverMode::FriSnark => self.client.fetch_fri_job(),
            ProverMode::SnarkOnly => self.client.fetch_snark_job(),
        }
    }

    fn handle_prover_result(&mut self, outcome: ProverResult) -> Result<()> {
        let kind = match &outcome {
            Ok(o) => o.kind(),
            Err(f) => f.kind,
        };
        let settles = matches!(
            (self.mode, kind),
            (ProverMode::FriOnly | ProverMode::FriSnark, ProofKind::Fri)
                | (ProverMode::SnarkOnly, ProofKind::Snark)
        );
        if settles {
            METRICS.pending_jobs.dec_by(1);
        }
        let batch_number = match outcome {
            Ok(ProofOutcome::Fri {
                batch_number,
                proof,
            }) => {
                self.client.submit_fri(batch_number, proof.as_ref())?;
                // In `fri-snark` mode, the SNARK job needs the FRI proof, so we can set the new pending job immediately instead of waiting for the next fetch cycle. The in-memory `Proof` is fed directly to the SNARK pipeline without an extra encode/decode round trip.
                if self.mode == ProverMode::FriSnark {
                    // FRI jobs are processed serially, so the previous SNARK
                    // follow-up must have been drained before this one lands.
                    self.snark_followup = Some(WorkerJob::Snark {
                        batch_number,
                        proof,
                    });
                }
                batch_number
            }
            Ok(ProofOutcome::Snark {
                batch_number,
                proof,
            }) => {
                self.client.submit_snark(batch_number, proof.as_ref())?;
                batch_number
            }
            Err(failure) => {
                anyhow::bail!(
                    "prover job for batch {} ({}) failed: {}",
                    failure.batch_number,
                    failure.kind,
                    failure.reason,
                );
            }
        };
        info!(batch_number, kind = %kind, "Successfully submitted proof");
        Ok(())
    }
}
