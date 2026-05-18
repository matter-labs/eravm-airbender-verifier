use clap::ValueEnum;

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

/// A FRI proving job received from the server.
pub struct FriJob {
    pub batch_number: u32,
    pub protocol_version: u16,
    pub input_words: Vec<u32>,
}

/// A SNARK-wrapping job received from the server: a FRI proof envelope to wrap.
pub struct SnarkJob {
    pub batch_number: u32,
    pub protocol_version: u16,
    /// Bincode-encoded `airbender_host::Proof`, as produced by the FRI prover
    /// and stored by the job server.
    pub fri_proof_bytes: Vec<u8>,
}

/// A completed FRI proof ready to be submitted.
pub struct CompletedFriProof {
    pub batch_number: u32,
    /// Bincode-encoded `airbender_host::Proof`.
    pub proof_bytes: Vec<u8>,
}

/// A completed SNARK proof + verification key ready to be submitted.
pub struct CompletedSnarkProof {
    pub batch_number: u32,
    /// JSON-encoded SNARK wrapper proof.
    pub snark_proof_bytes: Vec<u8>,
    /// JSON-encoded SNARK wrapper verification key.
    pub snark_vk_bytes: Vec<u8>,
}

/// Which phase of the pipeline emitted an outcome.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProofPhase {
    Fri,
    Snark,
}

impl std::fmt::Display for ProofPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofPhase::Fri => f.write_str("FRI"),
            ProofPhase::Snark => f.write_str("SNARK"),
        }
    }
}

/// Successfully produced artifact ready to be submitted.
pub enum CompletedArtifact {
    Fri(CompletedFriProof),
    Snark(CompletedSnarkProof),
}

/// A job that did not produce an artifact. Carries enough context for the
/// network worker to log and settle the job locally.
pub struct FailedJob {
    pub batch_number: u32,
    pub phase: ProofPhase,
    pub reason: String,
}

/// Settlement event emitted by the prover worker. Every fetched job results
/// in at least one `WorkerOutcome` — failures included — so the network
/// worker can account for it exactly once.
///
/// In `fri-snark` mode a single job emits two outcomes (FRI then SNARK);
/// the FRI outcome is the one that settles the job's accounting, and the
/// SNARK outcome follows as a post-settlement step.
pub enum WorkerOutcome {
    Completed(CompletedArtifact),
    Failed(FailedJob),
}

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

/// SNARK submission payload. Both `snark_proof` and `snark_vk` are hex-encoded.
#[serde_with::serde_as]
#[derive(serde::Serialize)]
pub struct SubmitSnarkProofRequest<'a> {
    pub l1_batch_number: u32,
    pub prover_id: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub snark_proof: &'a [u8],
    #[serde_as(as = "serde_with::hex::Hex")]
    pub snark_vk: &'a [u8],
}

/// SNARK input poll response (server -> prover). The `fri_proof` is the same
/// hex-encoded bincode payload the FRI prover originally submitted.
#[serde_with::serde_as]
#[derive(serde::Deserialize)]
pub struct SnarkInputResponse {
    pub l1_batch_number: u32,
    #[serde(default)]
    pub protocol_version: u16,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub fri_proof: Vec<u8>,
}
