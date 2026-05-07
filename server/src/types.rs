use eravm_prover_host::RawFriProof;

/// A proving job received from the server.
pub struct Job {
    pub batch_number: u32,
    pub protocol_version: u16,
    pub input: JobInput,
}

/// Job payload — either FRI input words (modes that prove) or a raw FRI proof
/// (`snark` mode, where the server only wraps an existing FRI proof).
pub enum JobInput {
    /// `input_words` for `GpuProver::prove`.
    Input(Vec<u32>),
    /// A raw FRI proof to wrap into a SNARK.
    FriProof(Box<RawFriProof>),
}

/// A completed proof ready to be submitted.
pub struct CompletedProof {
    pub batch_number: u32,
    pub proof_bytes: Vec<u8>,
}

/// JSON payload returned by `GET /airbender/fri_proofs` in `snark` mode.
///
/// Schema is server-defined for now — the FRI proof is bincode-encoded so
/// versioning is taken care of by `airbender_host::Proof` itself, and the
/// envelope only carries the batch metadata the network worker needs.
#[serde_with::serde_as]
#[derive(serde::Deserialize)]
pub struct FriProofPayload {
    pub l1_batch_number: u32,
    pub protocol_version: u16,
    /// Bincode-encoded `airbender_host::Proof` (FRI variant). Hex-wrapped to
    /// match the submission encoding on the other side of the pipeline.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub proof: Vec<u8>,
}

/// Mirrors `SubmitAirbenderProofRequest` from zksync-era.
/// The `proof` bytes are hex-encoded in JSON, matching the `#[serde_as(as = "Hex")]` annotation.
#[serde_with::serde_as]
#[derive(serde::Serialize)]
pub struct SubmitProofRequest<'a> {
    pub l1_batch_number: u32,
    pub prover_id: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub proof: &'a [u8],
}
