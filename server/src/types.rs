/// A proving job received from the server.
pub struct Job {
    pub batch_number: u32,
    pub protocol_version: u16,
    pub input_words: Vec<u32>,
}

/// A completed proof ready to be submitted.
pub struct CompletedProof {
    pub batch_number: u32,
    pub proof_bytes: Vec<u8>,
}

/// Mirrors `SubmitAirbenderProofRequest` from zksync-era.
/// The `proof` bytes are hex-encoded in JSON, matching the `#[serde_as(as = "Hex")]` annotation.
#[serde_with::serde_as]
#[derive(serde::Serialize)]
pub struct SubmitProofRequest<'a> {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub proof: &'a [u8],
}
