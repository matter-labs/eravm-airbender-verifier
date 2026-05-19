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
    pub input_words: Vec<u32>,
}

/// A SNARK-wrapping job received from the server: a FRI proof envelope to wrap.
pub struct SnarkJob {
    pub batch_number: u32,
    /// Bincode-encoded `airbender_host::Proof`, as produced by the FRI prover
    /// and stored by the job server.
    pub fri_proof_bytes: Vec<u8>,
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

/// Submission payload produced on success.
pub enum Artifact {
    Fri { proof: Vec<u8> },
    Snark { proof: Vec<u8>, vk: Vec<u8> },
}

impl Artifact {
    pub fn kind(&self) -> ProofKind {
        match self {
            Artifact::Fri { .. } => ProofKind::Fri,
            Artifact::Snark { .. } => ProofKind::Snark,
        }
    }
}

/// Failure detail carried in the error arm of [`ProofOutcome`]. Holds the kind so
/// callers can route the failure log without inspecting the outcome variant.
pub struct FailedProof {
    pub kind: ProofKind,
    /// Full anyhow error chain (`{err:#}`) captured at the point of failure.
    pub reason: String,
}

/// Settlement event emitted by the prover worker. Every fetched job produces
/// at least one outcome — failures included — so the job worker can
/// account for it exactly once. In `fri-snark` mode a single fetched job emits
/// two outcomes (FRI then SNARK); the FRI outcome settles accounting and the
/// SNARK outcome is a post-settlement step.
pub struct ProofOutcome {
    pub batch_number: u32,
    pub result: Result<Artifact, FailedProof>,
}

impl ProofOutcome {
    pub fn fri_success(batch_number: u32, proof: Vec<u8>) -> Self {
        Self {
            batch_number,
            result: Ok(Artifact::Fri { proof }),
        }
    }

    pub fn snark_success(batch_number: u32, proof: Vec<u8>, vk: Vec<u8>) -> Self {
        Self {
            batch_number,
            result: Ok(Artifact::Snark { proof, vk }),
        }
    }

    pub fn failed(batch_number: u32, kind: ProofKind, err: anyhow::Error) -> Self {
        Self {
            batch_number,
            result: Err(FailedProof {
                kind,
                reason: format!("{err:#}"),
            }),
        }
    }

    pub fn kind(&self) -> ProofKind {
        match &self.result {
            Ok(artifact) => artifact.kind(),
            Err(failure) => failure.kind,
        }
    }

    pub fn settles_job(&self, mode: ProverMode) -> bool {
        matches!(
            (mode, self.kind()),
            (ProverMode::FriOnly | ProverMode::FriSnark, ProofKind::Fri)
                | (ProverMode::SnarkOnly, ProofKind::Snark)
        )
    }
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
    #[serde_as(as = "serde_with::hex::Hex")]
    pub fri_proof: Vec<u8>,
}
