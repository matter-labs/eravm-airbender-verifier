//! Integration test: starts the prover server binary, serves one real batch via a local HTTP
//! server, waits up to one hour for the proof to be submitted, then verifies it.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use tokio::sync::oneshot;

use airbender_host::{Program, Proof, ProverLevel, VerificationKey, VerificationRequest, Verifier};
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_cli_utils::{load_batch_words, BatchInputFile};

const EXPECTED_OUTPUT: u32 = 1;
const TEST_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Test HTTP server state and handlers
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TestServerState {
    verifier_input: Arc<AirbenderVerifierInput>,
    job_served: Arc<std::sync::atomic::AtomicBool>,
    proof_sender: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
}

/// `POST /airbender/proof_inputs` — serves the job once, then returns 204.
async fn handle_proof_inputs(State(state): State<TestServerState>) -> impl IntoResponse {
    if state
        .job_served
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return StatusCode::NO_CONTENT.into_response();
    }
    println!("[test-server] Serving job to prover");
    Json((*state.verifier_input).clone()).into_response()
}

/// `POST /airbender/submit_proofs` — stores the proof bytes and signals the test.
#[derive(serde::Deserialize)]
struct SubmitProofBody {
    l1_batch_number: u32,
    #[allow(dead_code)]
    prover_id: String,
    /// Hex-encoded proof bytes, matching `SubmitProofRequest` in the server crate.
    proof: String,
}

async fn handle_submit_proofs(
    State(state): State<TestServerState>,
    Json(body): Json<SubmitProofBody>,
) -> StatusCode {
    let proof_bytes = match hex::decode(&body.proof) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    println!(
        "[test-server] Received proof for batch {} ({} bytes)",
        body.l1_batch_number,
        proof_bytes.len()
    );
    if let Some(tx) = state.proof_sender.lock().expect("poisoned").take() {
        let _ = tx.send(proof_bytes);
    }
    StatusCode::OK
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Inverts the framed word format produced by the server's `input_to_words`:
/// `[byte_len as u32] ++ [bytes packed big-endian into u32 words, last zero-padded]`.
fn words_to_verifier_input(words: &[u32]) -> AirbenderVerifierInput {
    let byte_len = words[0] as usize;
    let bytes: Vec<u8> = words[1..].iter().flat_map(|w| w.to_be_bytes()).collect();
    let (input, _): (AirbenderVerifierInput, usize) =
        bincode::serde::decode_from_slice(&bytes[..byte_len], bincode::config::standard())
            .expect("failed to deserialize AirbenderVerifierInput from framed batch words");
    input
}

/// Loads the VK from `cache_path` if it exists; otherwise generates and caches it.
fn load_or_generate_vk(verifier: &impl Verifier, cache_path: &std::path::Path) -> VerificationKey {
    if cache_path.exists() {
        let bytes = std::fs::read(cache_path).expect("failed to read VK cache");
        let (vk, decoded_len): (VerificationKey, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("failed to decode VK cache");
        assert_eq!(decoded_len, bytes.len(), "VK cache has trailing bytes");
        println!(
            "[test] Loaded verification key from cache: {}",
            cache_path.display()
        );
        return vk;
    }

    println!("[test] Generating verification key (this may take a while)...");
    let vk = verifier.generate_vk().expect("failed to generate VK");
    let encoded = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .expect("failed to encode VK for caching");
    std::fs::write(cache_path, &encoded).expect("failed to write VK cache");
    println!(
        "[test] Verification key cached at: {}",
        cache_path.display()
    );
    vk
}

fn guest_dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}

fn batch_file_path(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/era_mainnet_batches/binary")
        .join(filename)
}

/// RAII guard that kills the child process on drop.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        println!("[test] Killing prover server process (pid {})", self.0.id());
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ---------------------------------------------------------------------------
// The integration test
// ---------------------------------------------------------------------------

/// Runs the full prover server → job server → proof verification pipeline for one batch.
///
/// Timeline:
/// 1. Load batch 506093 and deserialize it to `AirbenderVerifierInput`.
/// 2. Start a local HTTP server that serves the job once, then hangs returning 204.
/// 3. Start `eravm-prover-server` pointed at the local server.
/// 4. Wait up to 1 hour for the server to submit the proof.
/// 5. Verify the submitted proof with `RealVerifier`.
///
/// Ignored by default: requires a GPU, the built guest binary, and LFS batch 506093.bin.gz.
/// Run with `cargo test --test integration_test --release -- --ignored`.
#[ignore = "requires GPU, built guest binary, and LFS batch 506093.bin.gz"]
#[tokio::test(flavor = "multi_thread")]
async fn prover_server_proves_one_batch() {
    // --- 1. Load batch and build verifier input ---
    let dist_dir = guest_dist_dir();
    println!("[test] Guest dist dir: {}", dist_dir.display());

    let batch_path = batch_file_path("506093.bin.gz");
    println!("[test] Loading batch from: {}", batch_path.display());
    let batch_input = BatchInputFile {
        number: 506093,
        path: batch_path,
    };
    let words = load_batch_words(&batch_input).expect("failed to load batch words");
    println!("[test] Batch loaded: {} words", words.len());

    let verifier_input = words_to_verifier_input(&words);
    println!("[test] Verifier input deserialized successfully");

    // --- 2. Set up test HTTP server ---
    let (proof_tx, proof_rx) = oneshot::channel::<Vec<u8>>();
    let state = TestServerState {
        verifier_input: Arc::new(verifier_input),
        job_served: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        proof_sender: Arc::new(Mutex::new(Some(proof_tx))),
    };

    let app = Router::new()
        .route("/airbender/proof_inputs", post(handle_proof_inputs))
        .route("/airbender/submit_proofs", post(handle_submit_proofs))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind test HTTP server");
    let server_addr = listener
        .local_addr()
        .expect("failed to get test server address");
    println!("[test] Test HTTP server listening on http://{server_addr}");

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test HTTP server exited with error");
    });

    // --- 3. Start the prover server binary ---
    let prover_bin = env!("CARGO_BIN_EXE_eravm-prover-server");
    println!("[test] Spawning prover server: {prover_bin}");
    let child = Command::new(prover_bin)
        .env("PROVER_SERVER_URL", format!("http://{server_addr}"))
        .env(
            "PROVER_GUEST_DIST_DIR",
            dist_dir.to_str().expect("non-UTF8 guest dist dir"),
        )
        .env("PROVER_POLL_INTERVAL_MS", "1000")
        .env("PROVER_ID", "integration-test")
        .spawn()
        .expect("failed to spawn eravm-prover-server");
    println!("[test] Prover server spawned (pid {})", child.id());
    let _child_guard = ChildGuard(child);

    // --- 4. Wait up to 1 hour for the proof, printing a heartbeat every minute ---
    println!("[test] Waiting for proof (timeout: 1 hour)...");
    let started_at = Instant::now();

    let proof_bytes = tokio::time::timeout(TEST_TIMEOUT, async {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        interval.tick().await; // first tick fires immediately, skip it
        let mut proof_rx = std::pin::pin!(proof_rx);
        loop {
            tokio::select! {
                result = &mut proof_rx => {
                    return result.expect("proof channel closed without receiving a proof");
                }
                _ = interval.tick() => {
                    println!(
                        "[test] Still waiting for proof... elapsed: {:.0}s",
                        started_at.elapsed().as_secs_f64()
                    );
                }
            }
        }
    })
    .await
    .expect("timed out after 1 hour waiting for proof");

    println!(
        "[test] Proof received after {:.1}s ({} bytes)",
        started_at.elapsed().as_secs_f64(),
        proof_bytes.len()
    );

    // --- 5. Verify the proof ---
    println!("[test] Loading guest program for verification...");
    let program = Program::load(&dist_dir).expect("failed to load guest program");
    let verifier = program
        .real_verifier(ProverLevel::RecursionUnified)
        .build()
        .expect("failed to build RealVerifier");

    let manifest_sha256 = program.manifest().bin.sha256.trim().to_owned();
    assert!(
        !manifest_sha256.is_empty(),
        "guest manifest has empty sha256"
    );
    let vk_cache = PathBuf::from(format!("vk-{manifest_sha256}.bin"));
    let vk = load_or_generate_vk(&verifier, &vk_cache);

    println!("[test] Deserializing proof...");
    let (proof, _): (Proof, usize) =
        bincode::serde::decode_from_slice(&proof_bytes, bincode::config::standard())
            .expect("failed to deserialize proof bytes");

    println!("[test] Verifying proof...");
    verifier
        .verify(&proof, &vk, VerificationRequest::real(&EXPECTED_OUTPUT))
        .expect("proof verification failed");

    println!("[test] Proof verified successfully!");
}
