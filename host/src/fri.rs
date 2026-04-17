use airbender_host::{
    GpuProver, Program, Proof, Prover, ProverLevel, RealVerifier, Runner, TranspilerRunner,
    VerificationKey, VerificationRequest, Verifier,
};
use anyhow::{Context, Result};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;
use zksync_cli_utils::load_batch_words;
use zksync_tee_verifier::Verify;

/// The guest returns `[u32; 8]` — the proof public input hash.
/// We no longer check against a fixed expected output; any non-zero output
/// indicates successful execution + commitment computation.
/// The actual value is batch-specific and verified by L1 against stored commitments.
pub(crate) const FRI_PROOF_FILE_NAME: &str = "fri_proof.json";

pub(crate) type RawFriProof = airbender_host::raw::UnrolledProgramProof;

pub(crate) struct FriProofArtifact {
    pub(crate) proof: RawFriProof,
    pub(crate) proving_time: Duration,
    pub(crate) cycles: u64,
}

// ==============================================================================
// FRI Pipeline
// ==============================================================================
//
// This module keeps all Airbender-specific behavior in one place so the rest of
// the host can talk in terms of "run batch", "prove batch", and "load/save raw
// proof" without needing to know how the guest program, GPU prover, or VK cache
// are assembled.

pub(crate) struct FriPipeline {
    prover: GpuProver,
    verifier: RealVerifier,
    vk: VerificationKey,
}

impl FriPipeline {
    pub(crate) fn new(worker_threads: Option<usize>) -> Result<Self> {
        let program =
            Program::load(dist_dir()).context("while attempting to load guest program")?;
        let verifier = program
            .real_verifier(ProverLevel::RecursionUnified)
            .build()
            .context("while attempting to build real verifier")?;

        let cache_path = vk_cache_path(&program)
            .context("while attempting to resolve verification key cache path")?;
        let vk = load_or_generate_vk(&verifier, &cache_path).with_context(|| {
            format!(
                "while attempting to prepare verification key cache {}",
                cache_path.display()
            )
        })?;

        let mut prover = program
            .gpu_prover()
            .with_level(ProverLevel::RecursionUnified);
        if let Some(worker_threads) = worker_threads {
            prover = prover.with_worker_threads(worker_threads);
        }

        let prover = prover
            .build()
            .context("while attempting to build GPU prover")?;

        Ok(Self {
            prover,
            verifier,
            vk,
        })
    }

    pub(crate) fn prove_batch(
        &self,
        batch_number: u64,
        batch_path: &Path,
    ) -> Result<FriProofArtifact> {
        let v2 = load_v2_with_real_blobs(batch_path)
            .with_context(|| format!("failed to build V2 input for batch {batch_number}"))?;
        let prover_input = frame_v2_input(zksync_tee_verifier::types::TeeVerifierInput::V2(v2))?;

        let proving_started_at = Instant::now();
        let prove_result = self.prover.prove(&prover_input).with_context(|| {
            format!("while attempting to generate proof for batch {batch_number}")
        })?;
        let proving_time = proving_started_at.elapsed();
        let cycles = prove_result.cycles;
        let output = prove_result.receipt.output;

        info!(
            batch_number,
            cycles,
            proving_time_secs = proving_time.as_secs_f64(),
            ?output,
            "Finished FRI proof generation"
        );

        if output == [0u32; 8] {
            anyhow::bail!(
                "batch {batch_number} proof returned zero output — verification or commitment failed"
            );
        }

        self.verifier
            .verify(
                &prove_result.proof,
                &self.vk,
                VerificationRequest::real(&output),
            )
            .with_context(|| {
                format!("while attempting to verify proof for batch {batch_number}")
            })?;

        info!(batch_number, "Finished FRI proof verification");

        let proof = match prove_result.proof {
            Proof::Real(proof) => proof.into_inner(),
            Proof::Dev(_) => {
                anyhow::bail!("GPU prover returned a development proof unexpectedly")
            }
        };

        Ok(FriProofArtifact {
            proof,
            proving_time,
            cycles,
        })
    }
}

pub(crate) fn build_runner(jit: bool) -> Result<TranspilerRunner> {
    let program = Program::load(dist_dir()).context("while attempting to load guest program")?;
    let mut runner_builder = program.transpiler_runner().with_cycles(usize::MAX);

    if jit {
        runner_builder = runner_builder.with_jit();
    }

    runner_builder
        .build()
        .context("while attempting to build transpiler runner")
}

pub(crate) fn run_batch(
    runner: &TranspilerRunner,
    batch_number: u64,
    batch_path: &Path,
) -> Result<()> {
    // Load batch and compute real CommitmentInput (blob hashes from pubdata).
    let v2 = load_v2_with_real_blobs(batch_path)
        .with_context(|| format!("failed to build V2 input for batch {batch_number}"))?;

    // Run native verification with real blob data.
    let native_result = v2
        .clone()
        .verify()
        .context("native verification with real blob data failed")?;

    info!(
        batch_number,
        ?native_result.commitment,
        ?native_result.proof_public_input,
        "Native verification + commitment succeeded (with blob data)"
    );

    // Cross-check commitment sub-hashes against sequencer code.
    crosscheck_commitment(&native_result, batch_path)
        .with_context(|| format!("commitment cross-check failed for batch {batch_number}"))?;

    info!(batch_number, "Commitment cross-check passed");

    // Run transpiler with the same real CommitmentInput.
    let transpiler_input = frame_v2_input(zksync_tee_verifier::types::TeeVerifierInput::V2(v2))?;

    let execution = runner
        .run(&transpiler_input)
        .with_context(|| format!("while attempting to execute batch {batch_number}"))?;
    let output = execution.receipt.output;

    info!(
        batch_number,
        cycles = execution.cycles_executed,
        reached_end = execution.reached_end,
        ?output,
        "Finished transpiler run"
    );

    // Verify transpiler output matches native verification.
    anyhow::ensure!(
        output == native_result.proof_public_input,
        "batch {batch_number}: transpiler output {output:?} doesn't match native {0:?}",
        native_result.proof_public_input
    );

    info!(
        batch_number,
        "Transpiler output matches native verification"
    );

    Ok(())
}

/// Load a V1 batch and build a V2 input with a **test-only** synthetic
/// `CommitmentInput`: real blob linear hashes from pubdata, fabricated
/// versioned hashes / opening commitments, zero prev_meta/prev_aux. See
/// `zksync_tee_verifier::test_utils` module docs — the resulting
/// `proof_public_input` is **not** L1-settlement-equivalent, only
/// pipeline-equivalent between native, transpiler, and prover here.
fn load_v2_with_real_blobs(
    batch_path: &Path,
) -> Result<zksync_tee_verifier::types::V2TeeVerifierInput> {
    use zksync_tee_verifier::types::TeeVerifierInput;

    let v1_input = load_verifier_input(batch_path)?;
    let TeeVerifierInput::V1(v1) = v1_input else {
        anyhow::bail!("expected TeeVerifierInput::V1");
    };

    zksync_tee_verifier::test_utils::v1_to_v2_with_real_blobs(v1)
        .context("failed to compute real blob data")
}

/// Frame a TeeVerifierInput as words for the transpiler/prover.
fn frame_v2_input(v2: zksync_tee_verifier::types::TeeVerifierInput) -> Result<Vec<u32>> {
    let encoded = bincode::serde::encode_to_vec(&v2, bincode::config::standard())
        .context("failed to encode V2 TeeVerifierInput")?;

    let byte_len = encoded.len() as u32;
    let mut words = Vec::with_capacity(1 + encoded.len().div_ceil(4));
    words.push(byte_len);
    for chunk in encoded.chunks(4) {
        let mut padded = [0u8; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_be_bytes(padded));
    }
    Ok(words)
}

/// Load and deserialize a TeeVerifierInput from a batch file.
fn load_verifier_input(batch_path: &Path) -> Result<zksync_tee_verifier::types::TeeVerifierInput> {
    let framed_words = load_batch_words(
        &zksync_cli_utils::resolve_batch_inputs(
            batch_path.parent().unwrap(),
            Some(&[batch_path.to_path_buf()]),
            false,
        )?[0],
    )?;

    let payload = frame_words_to_bytes(&framed_words)?;
    let (input, decoded_len): (zksync_tee_verifier::types::TeeVerifierInput, usize) =
        bincode::serde::decode_from_slice(&payload, bincode::config::standard())
            .context("bincode decode failed")?;
    if decoded_len != payload.len() {
        anyhow::bail!("trailing bytes: decoded {decoded_len} of {}", payload.len());
    }
    Ok(input)
}

fn frame_words_to_bytes(words: &[u32]) -> Result<Vec<u8>> {
    let (&byte_len_word, payload_words) =
        words.split_first().context("frame has no length word")?;
    let byte_len = byte_len_word as usize;

    let mut bytes = Vec::with_capacity(byte_len);
    for word in payload_words {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.truncate(byte_len);
    Ok(bytes)
}

/// Cross-check commitment sub-hashes against independent computation.
fn crosscheck_commitment(
    result: &zksync_tee_verifier::VerificationResult,
    batch_path: &Path,
) -> Result<()> {
    use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
    use zksync_crypto_primitives::hasher::Hasher;
    use zksync_multivm::utils::get_used_bootloader_memory_bytes;
    use zksync_tee_verifier::commitment::expand_bootloader_heap;
    use zksync_tee_verifier::types::TOTAL_BLOBS_IN_COMMITMENT;
    use zksync_types::{
        commitment::{
            serialize_commitments, AuxCommitments, BlobHash, CommitmentCommonInput,
            CommitmentInput as SequencerCommitmentInput, L1BatchCommitment,
        },
        u256_to_h256,
        web3::keccak256,
        H256,
    };

    let input = load_verifier_input(batch_path)?;
    let zksync_tee_verifier::types::TeeVerifierInput::V1(input) = input else {
        anyhow::bail!("expected V1");
    };

    let protocol_version = input.system_env.version;
    let bootloader_code_hash = input.system_env.base_system_smart_contracts.bootloader.hash;
    let default_aa_code_hash = u256_to_h256(input.vm_run_data.default_account_code_hash);
    let evm_emulator_code_hash = input.vm_run_data.evm_emulator_code_hash.map(u256_to_h256);
    let initial_heap_content = &input.vm_run_data.initial_heap_content;

    // passThroughDataHash + metadataHash via sequencer code.
    let sequencer_input = SequencerCommitmentInput::PostBoojum {
        common: CommitmentCommonInput {
            l2_to_l1_logs: vec![],
            rollup_last_leaf_index: result.new_enumeration_index,
            rollup_root_hash: result.value_hash,
            bootloader_code_hash,
            default_aa_code_hash,
            evm_emulator_code_hash,
            protocol_version,
        },
        system_logs: vec![],
        state_diffs: vec![],
        aux_commitments: AuxCommitments {
            events_queue_commitment: H256::zero(),
            bootloader_initial_content_commitment: H256::zero(),
        },
        blob_hashes: vec![
            BlobHash {
                linear_hash: H256::zero(),
                commitment: H256::zero()
            };
            TOTAL_BLOBS_IN_COMMITMENT
        ],
        aggregation_root: H256::zero(),
    };
    let seq_hashes = L1BatchCommitment::new(sequencer_input, true)?.hash()?;

    anyhow::ensure!(
        result.pass_through_data_hash == seq_hashes.pass_through_data,
        "passThroughDataHash mismatch: guest {:?} vs sequencer {:?}",
        result.pass_through_data_hash,
        seq_hashes.pass_through_data
    );
    anyhow::ensure!(
        result.metadata_hash == seq_hashes.meta_parameters,
        "metadataHash mismatch: guest {:?} vs sequencer {:?}",
        result.metadata_hash,
        seq_hashes.meta_parameters
    );

    // system_logs_hash + state_diff_hash independently.
    let ind_logs_hash = H256(keccak256(&serialize_commitments(&result.system_logs)));
    anyhow::ensure!(
        result.system_logs_hash == ind_logs_hash,
        "system_logs_hash mismatch"
    );

    let ind_diff_hash = H256(keccak256(&serialize_commitments(&result.state_diffs)));
    anyhow::ensure!(
        result.state_diff_hash == ind_diff_hash,
        "state_diff_hash mismatch"
    );

    // bootloader_heap_hash independently.
    let memory_size = get_used_bootloader_memory_bytes(protocol_version.into());
    let ind_heap_hash =
        Blake2Hasher.hash_bytes(&expand_bootloader_heap(initial_heap_content, memory_size));
    anyhow::ensure!(
        result.bootloader_heap_hash == ind_heap_hash,
        "bootloader_heap_hash mismatch"
    );

    Ok(())
}

pub(crate) fn save_raw_proof(proof: &RawFriProof, path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("while attempting to derive the parent directory for the raw FRI proof file")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("while attempting to create {}", parent.display()))?;

    let file = std::fs::File::create(path)
        .with_context(|| format!("while attempting to create {}", path.display()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, proof)
        .with_context(|| format!("while attempting to serialize {}", path.display()))
}

pub(crate) fn load_raw_proof(path: &Path) -> Result<RawFriProof> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("while attempting to open {}", path.display()))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader)
        .with_context(|| format!("while attempting to deserialize {}", path.display()))
}

fn load_or_generate_vk(verifier: &RealVerifier, cache_path: &Path) -> Result<VerificationKey> {
    if cache_path.exists() {
        let bytes = std::fs::read(cache_path)
            .with_context(|| format!("while attempting to read {}", cache_path.display()))?;
        let (vk, decoded_len): (VerificationKey, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).with_context(
                || {
                    format!(
                        "while attempting to decode verification key cache {}",
                        cache_path.display()
                    )
                },
            )?;
        if decoded_len != bytes.len() {
            anyhow::bail!(
                "verification key cache {} has trailing bytes",
                cache_path.display()
            );
        }

        info!(path = %cache_path.display(), "Loaded verification key from cache");
        return Ok(vk);
    }

    let vk = verifier
        .generate_vk()
        .context("while attempting to generate verification key")?;
    let encoded = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .context("while attempting to bincode-encode verification key cache payload")?;
    std::fs::write(cache_path, encoded)
        .with_context(|| format!("while attempting to write {}", cache_path.display()))?;

    info!(path = %cache_path.display(), "Generated and cached verification key");
    Ok(vk)
}

fn vk_cache_path(program: &Program) -> Result<PathBuf> {
    let manifest_sha256 = program.manifest().bin.sha256.trim();
    if manifest_sha256.is_empty() {
        anyhow::bail!(
            "guest manifest has empty bin_sha256, cannot derive verification key cache path"
        );
    }

    Ok(PathBuf::from(format!("vk-{manifest_sha256}.bin")))
}

fn dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}
