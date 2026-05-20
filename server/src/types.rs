use airbender_host::Proof;
use clap::ValueEnum;
use eravm_prover_host::SnarkWrapperProof;
use zksync_prover_metrics::ProofType;

/// Jobs received from the job worker. Which variant is expected is implied
/// by which pipelines the worker was built with; a mismatch is a job-worker bug.
pub enum WorkerJob {
    Fri {
        batch_number: u32,
        input_words: Vec<u32>,
    },
    Snark {
        batch_number: u32,
        proof: Box<Proof>,
    },
}

impl WorkerJob {
    pub fn batch_number(&self) -> u32 {
        match self {
            WorkerJob::Fri { batch_number, .. } | WorkerJob::Snark { batch_number, .. } => {
                *batch_number
            }
        }
    }

    pub fn kind(&self) -> ProofKind {
        match self {
            WorkerJob::Fri { .. } => ProofKind::Fri,
            WorkerJob::Snark { .. } => ProofKind::Snark,
        }
    }
}

/// Operating mode for the prover server.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum ProverMode {
    /// Poll for FRI inputs, run the FRI prover, submit FRI proofs.
    FriOnly,
    /// Poll for FRI inputs, run FRI + SNARK back-to-back, submit both.
    FriSnark,
    /// Poll for ready FRI proofs, run the SNARK wrapper, submit SNARK proofs.
    SnarkOnly,
}

/// Which phase of the pipeline an outcome came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProofKind {
    Fri,
    Snark,
}

impl std::fmt::Display for ProofKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofKind::Fri => f.write_str("FRI"),
            ProofKind::Snark => f.write_str("SNARK"),
        }
    }
}

impl From<ProofKind> for ProofType {
    fn from(kind: ProofKind) -> Self {
        match kind {
            ProofKind::Fri => ProofType::Fri,
            ProofKind::Snark => ProofType::Snark,
        }
    }
}

/// Successful proving outcome emitted by the prover worker. Failures travel
/// as the `Err` arm of [`ProverResult`] over the same channel. Every fetched
/// job produces at least one [`ProverResult`] — failures included — so the
/// job worker can account for it exactly once. In `fri-snark` mode a single
/// fetched job emits two results (FRI then SNARK); each settles its own
/// `pending_jobs` bucket (FRI then SNARK) as it lands.
pub enum ProofOutcome {
    Fri {
        batch_number: u32,
        proof: Box<Proof>,
    },
    Snark {
        batch_number: u32,
        proof: Box<SnarkWrapperProof>,
    },
}

impl ProofOutcome {
    pub fn kind(&self) -> ProofKind {
        match self {
            ProofOutcome::Fri { .. } => ProofKind::Fri,
            ProofOutcome::Snark { .. } => ProofKind::Snark,
        }
    }
}

/// Failure detail carried in the `Err` arm of [`ProverResult`]. Holds the
/// kind and batch number so the job worker can route the failure log without
/// inspecting the success type.
pub struct FailedProof {
    pub batch_number: u32,
    pub kind: ProofKind,
    /// Full anyhow error chain (`{err:#}`) captured at the point of failure.
    pub reason: String,
}

impl FailedProof {
    pub fn new(batch_number: u32, kind: ProofKind, err: anyhow::Error) -> Self {
        Self {
            batch_number,
            kind,
            reason: format!("{err:#}"),
        }
    }
}

/// Message type sent by the prover worker: either a successful
/// [`ProofOutcome`] or a [`FailedProof`].
pub type ProverResult = Result<ProofOutcome, FailedProof>;

/// Mirrors `SubmitAirbenderProofRequest` from zksync-era.
/// The `proof` bytes are hex-encoded in JSON, matching the `#[serde_as(as = "Hex")]` annotation.
#[serde_with::serde_as]
#[derive(serde::Serialize)]
pub struct SubmitFriProofRequest<'a> {
    pub l1_batch_number: u32,
    pub prover_id: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub proof: &'a [u8],
}

/// SNARK submission payload. The VK is resolved once at startup and is not
/// included here; the receiver is expected to know it out of band.
#[serde_with::serde_as]
#[derive(serde::Serialize)]
pub struct SubmitSnarkProofRequest<'a> {
    pub l1_batch_number: u32,
    pub prover_id: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub snark_proof: &'a [u8],
}
