use std::sync::mpsc::{Receiver, SendError, SyncSender};
use std::time::{Duration, Instant};

/// Returned by handlers; the only error case is the result channel being
/// disconnected — the run loop short-circuits on it and exits.
type HandlerResult = Result<(), SendError<CompletedWork>>;

use airbender_host::Proof;
use anyhow::{Context, Result};
use eravm_prover_host::{FriPipeline, FriVerifier, RawFriProof, SnarkPipeline};
use tracing::{error, info};
use zksync_prover_metrics::{ProofLabels, ProofStatus, METRICS};

use crate::types::{CompletedFriProof, CompletedSnarkProof, CompletedWork, FriJob, SnarkJob};

/// Jobs received from the network worker. The variant in flight is driven by
/// the configured [`ProverMode`].
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

/// Prover pipelines available to the worker; which ones are populated
/// implicitly encodes the operating mode (see [`ProverMode`][crate::types::ProverMode]).
#[derive(Default)]
pub struct WorkerPipelines {
    pub fri: Option<FriPipeline>,
    pub fri_verifier: Option<FriVerifier>,
    pub snark: Option<SnarkPipeline>,
}

impl WorkerPipelines {
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
}

struct FriOutput {
    proof: Proof,
    proof_bytes: Vec<u8>,
}

pub struct ProverWorker {
    pipelines: WorkerPipelines,
    job_rx: Receiver<WorkerJob>,
    result_tx: SyncSender<CompletedWork>,
}

impl ProverWorker {
    pub fn new(
        pipelines: WorkerPipelines,
        job_rx: Receiver<WorkerJob>,
        result_tx: SyncSender<CompletedWork>,
    ) -> Self {
        Self {
            pipelines,
            job_rx,
            result_tx,
        }
    }

    /// Receives jobs, proves them according to the configured mode, and streams
    /// completed work back to the network worker as soon as each piece is ready —
    /// in `fri-snark` mode the FRI proof is sent before SNARK wrapping starts,
    /// so the network worker can submit it to the job server in parallel.
    pub fn run(mut self) {
        while let Ok(job) = self.job_rx.recv() {
            let result = match job {
                WorkerJob::Fri(j) => self.handle_fri(&j),
                WorkerJob::Snark(j) => self.handle_snark(&j),
            };
            if result.is_err() {
                return;
            }
        }
    }

    /// FRI-only and FRI+SNARK both start here. In FRI+SNARK the FRI proof is
    /// streamed out before the SNARK wrap starts, so the network worker can
    /// submit it in parallel.
    fn handle_fri(&mut self, job: &FriJob) -> HandlerResult {
        let Some(fri_output) = self.prove_fri(job) else {
            return Ok(());
        };

        self.result_tx.send(CompletedWork::Fri(CompletedFriProof {
            batch_number: job.batch_number,
            proof_bytes: fri_output.proof_bytes,
        }))?;

        if self.pipelines.snark.is_none() {
            return Ok(());
        }

        let raw_proof = match fri_output.proof {
            Proof::Real(real) => real.into_inner(),
            Proof::Dev(_) => {
                error!(
                    batch_number = job.batch_number,
                    "GPU prover returned a development proof unexpectedly; skipping SNARK wrap"
                );
                return Ok(());
            }
        };

        let Some(snark_completed) =
            self.wrap_to_snark(job.batch_number, job.protocol_version, raw_proof)
        else {
            // FRI was already streamed out; nothing more to do for this job.
            return Ok(());
        };
        self.result_tx.send(CompletedWork::Snark(snark_completed))
    }

    /// snark-only entry point: verifies the incoming FRI proof, wraps it, ships
    /// the SNARK back to the network worker.
    fn handle_snark(&mut self, job: &SnarkJob) -> HandlerResult {
        let raw_proof = match self.decode_and_verify_fri_proof(job) {
            Ok(raw) => raw,
            Err(err) => {
                error!(
                    batch_number = job.batch_number,
                    ?err,
                    "Rejected FRI proof input for SNARK wrapping"
                );
                return Ok(());
            }
        };

        let Some(completed) = self.wrap_to_snark(job.batch_number, job.protocol_version, raw_proof)
        else {
            return Ok(());
        };
        self.result_tx.send(CompletedWork::Snark(completed))
    }

    fn prove_fri(&self, job: &FriJob) -> Option<FriOutput> {
        let pipeline = self.pipelines.fri.as_ref().expect("FRI pipeline missing");
        info!(batch_number = job.batch_number, "Starting FRI proof...");
        let started_at = Instant::now();

        let prove_output = match pipeline.prove_input(job.batch_number as u64, &job.input_words) {
            Err(err) => {
                Self::record_metrics(
                    job.batch_number,
                    job.protocol_version,
                    ProofStatus::Failure,
                    started_at.elapsed(),
                );
                error!(
                    batch_number = job.batch_number,
                    ?err,
                    "Failed to prove batch"
                );
                return None;
            }
            Ok(out) => out,
        };

        Self::record_metrics(
            job.batch_number,
            job.protocol_version,
            ProofStatus::Success,
            started_at.elapsed(),
        );

        let proof_bytes =
            match bincode::serde::encode_to_vec(&prove_output.proof, bincode::config::standard()) {
                Err(err) => {
                    error!(
                        batch_number = job.batch_number,
                        ?err,
                        "Failed to serialize proof"
                    );
                    return None;
                }
                Ok(bytes) => bytes,
            };

        info!(
            batch_number = job.batch_number,
            cycles = prove_output.cycles,
            output = ?prove_output.output,
            "FRI proof complete"
        );
        Some(FriOutput {
            proof: prove_output.proof,
            proof_bytes,
        })
    }

    fn wrap_to_snark(
        &mut self,
        batch_number: u32,
        protocol_version: u16,
        raw_proof: RawFriProof,
    ) -> Option<CompletedSnarkProof> {
        let pipeline = self
            .pipelines
            .snark
            .as_mut()
            .expect("SNARK pipeline missing");
        info!(batch_number, "Starting SNARK wrapping...");
        let started_at = Instant::now();

        match pipeline.wrap_fri(raw_proof) {
            Err(err) => {
                Self::record_metrics(
                    batch_number,
                    protocol_version,
                    ProofStatus::Failure,
                    started_at.elapsed(),
                );
                error!(batch_number, ?err, "Failed to wrap batch into SNARK");
                None
            }
            Ok(artifact) => {
                Self::record_metrics(
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

    fn decode_and_verify_fri_proof(&self, job: &SnarkJob) -> Result<RawFriProof> {
        let (proof, decoded_len): (Proof, usize) =
            bincode::serde::decode_from_slice(&job.fri_proof_bytes, bincode::config::standard())
                .context("failed to bincode-decode incoming FRI proof envelope")?;
        if decoded_len != job.fri_proof_bytes.len() {
            anyhow::bail!("incoming FRI proof envelope has trailing bytes");
        }

        let verifier = self
            .pipelines
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

    fn record_metrics(
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
}
