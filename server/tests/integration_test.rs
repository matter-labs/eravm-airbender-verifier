//! Integration tests: start the prover server binary, serve one real batch via a local HTTP
//! server, wait up to `TEST_TIMEOUT` for the proof(s) to be submitted, then verify them.
//!
//! Two scenarios are covered, gated by `#[ignore]` because they need a GPU, the built guest
//! binary, and the LFS batch corpus:
//!
//! * `prover_server_proves_one_batch` — default `fri-only` mode; verifies the FRI proof.
//! * `prover_server_proves_fri_snark` — `fri-snark` mode; checks that both the FRI and SNARK
//!   submissions land and the FRI proof verifies. Additionally requires `IT_SNARK_TRUSTED_SETUP`
//!   to point at a CPU CRS file (the server crate builds the SNARK wrapper without `snark_gpu`).

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use tokio::sync::oneshot;

use airbender_host::{
    Program, Proof, ProverLevel, SecurityLevel, VerificationKey, VerificationRequest, Verifier,
};
use eravm_prover_host::SnarkWrapperProof;
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_airbender_verifier::Verify;
use zksync_cli_utils::{load_batch, BatchInputFile};

const TEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
// SNARK wrapping (CPU in the server crate) is the long pole; bump the cap for fri-snark.
const FRI_SNARK_TEST_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Test HTTP server state and handlers
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TestServerState {
    verifier_input: Arc<AirbenderVerifierInput>,
    job_served: Arc<std::sync::atomic::AtomicBool>,
    fri_proof_sender: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
    snark_proof_sender: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
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

/// `POST /airbender/submit_proofs` — stores the FRI proof bytes and signals the test.
#[derive(serde::Deserialize)]
struct SubmitFriProofBody {
    l1_batch_number: u32,
    #[allow(dead_code)]
    prover_id: String,
    /// Hex-encoded proof bytes, matching `SubmitFriProofRequest` in the server crate.
    proof: String,
}

async fn handle_submit_proofs(
    State(state): State<TestServerState>,
    Json(body): Json<SubmitFriProofBody>,
) -> StatusCode {
    let proof_bytes = match hex::decode(&body.proof) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    println!(
        "[test-server] Received FRI proof for batch {} ({} bytes)",
        body.l1_batch_number,
        proof_bytes.len()
    );
    if let Some(tx) = state.fri_proof_sender.lock().expect("poisoned").take() {
        let _ = tx.send(proof_bytes);
    }
    StatusCode::OK
}

/// `POST /airbender/submit_snark_proofs` — stores the SNARK proof bytes and signals the test.
#[derive(serde::Deserialize)]
struct SubmitSnarkProofBody {
    l1_batch_number: u32,
    #[allow(dead_code)]
    prover_id: String,
    /// Hex-encoded JSON-serialized `SnarkWrapperProof`, matching `SubmitSnarkProofRequest`
    /// in the server crate.
    snark_proof: String,
}

async fn handle_submit_snark_proofs(
    State(state): State<TestServerState>,
    Json(body): Json<SubmitSnarkProofBody>,
) -> StatusCode {
    let proof_bytes = match hex::decode(&body.snark_proof) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    println!(
        "[test-server] Received SNARK proof for batch {} ({} bytes)",
        body.l1_batch_number,
        proof_bytes.len()
    );
    if let Some(tx) = state.snark_proof_sender.lock().expect("poisoned").take() {
        let _ = tx.send(proof_bytes);
    }
    StatusCode::OK
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    let vk = verifier
        .generate_vk(SecurityLevel::default())
        .expect("failed to generate VK");
    let encoded = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .expect("failed to encode VK for caching");
    std::fs::write(cache_path, &encoded).expect("failed to write VK cache");
    println!(
        "[test] Verification key cached at: {}",
        cache_path.display()
    );
    vk
}

/// Resolution order for paths the test consumes:
/// 1. `IT_<NAME>` env var (set by CI when running a prebuilt test binary on a
///    different machine than the one that compiled it — `CARGO_MANIFEST_DIR`
///    points to the build host).
/// 2. `CARGO_MANIFEST_DIR`-relative default (the local-dev path).
fn guest_dist_dir() -> PathBuf {
    std::env::var_os("IT_GUEST_DIST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app"))
}

fn batch_file_path(filename: &str) -> PathBuf {
    let dir = std::env::var_os("IT_BATCHES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/era_mainnet_batches/binary")
        });
    dir.join(filename)
}

fn prover_server_bin() -> PathBuf {
    std::env::var_os("IT_PROVER_SERVER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_eravm-prover-server")))
}

/// CRS used by the SNARK wrapper. The server crate builds without
/// `snark_gpu`, so this must be the CPU CRS (`setup.key`, not `setup_gpu.key`).
fn snark_trusted_setup_path() -> PathBuf {
    PathBuf::from(
        std::env::var_os("IT_SNARK_TRUSTED_SETUP")
            .expect("IT_SNARK_TRUSTED_SETUP must point to the CPU CRS file (e.g. setup.key)"),
    )
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

/// Loads batch 506093 from the LFS corpus and returns the verifier input plus
/// the natively-computed proof public input that a real proof must match.
fn load_batch_and_expected_public_input() -> (AirbenderVerifierInput, [u32; 8]) {
    let batch_path = batch_file_path("506093.bin.gz");
    println!("[test] Loading batch from: {}", batch_path.display());
    let batch_input = BatchInputFile {
        number: 506093,
        path: batch_path,
    };
    let v1 = load_batch(&batch_input)
        .expect("failed to load batch")
        .into_v1()
        .expect("expected AirbenderVerifierInput::V1 from disk");
    let expected_public_input = v1
        .clone()
        .verify()
        .expect("native verify failed")
        .proof_public_input;
    println!("[test] Native verify produced public input: {expected_public_input:?}");
    (AirbenderVerifierInput::V1(v1), expected_public_input)
}

/// Verifies a bincode-encoded `Proof` payload against the cached VK.
fn verify_fri_proof(
    proof_bytes: &[u8],
    expected_public_input: &[u32; 8],
    dist_dir: &std::path::Path,
) {
    println!("[test] Loading guest program for verification...");
    let program = Program::load(dist_dir).expect("failed to load guest program");
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
        bincode::serde::decode_from_slice(proof_bytes, bincode::config::standard())
            .expect("failed to deserialize proof bytes");

    println!("[test] Verifying proof...");
    verifier
        .verify(
            &proof,
            &vk,
            VerificationRequest::real(expected_public_input),
        )
        .expect("proof verification failed");

    println!("[test] FRI proof verified successfully!");
}

/// Awaits a `oneshot::Receiver` with a timeout, printing a heartbeat every
/// `HEARTBEAT_INTERVAL`. Used to wait for proof submissions without going
/// silent for many minutes.
async fn await_with_heartbeat(
    label: &str,
    receiver: oneshot::Receiver<Vec<u8>>,
    timeout: Duration,
) -> Vec<u8> {
    let started_at = Instant::now();
    tokio::time::timeout(timeout, async {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        interval.tick().await; // first tick fires immediately, skip it
        let mut receiver = std::pin::pin!(receiver);
        loop {
            tokio::select! {
                result = &mut receiver => {
                    return result.expect("proof channel closed without receiving a proof");
                }
                _ = interval.tick() => {
                    println!(
                        "[test] Still waiting for {label} proof... elapsed: {:.0}s",
                        started_at.elapsed().as_secs_f64()
                    );
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label} proof"))
}

// ---------------------------------------------------------------------------
// The integration tests
// ---------------------------------------------------------------------------

/// Runs the full prover server → job server → proof verification pipeline for one batch.
///
/// Timeline:
/// 1. Load batch 506093 and deserialize it to `AirbenderVerifierInput`.
/// 2. Start a local HTTP server that serves the job once, then hangs returning 204.
/// 3. Start `eravm-prover-server` pointed at the local server.
/// 4. Wait up to `TEST_TIMEOUT` for the server to submit the proof.
/// 5. Verify the submitted proof with `RealVerifier`.
///
/// Ignored by default: requires a GPU, the built guest binary, and LFS batch 506093.bin.gz.
/// Run with `cargo test --test integration_test --release -- --ignored`.
#[ignore = "requires GPU, built guest binary, and LFS batch 506093.bin.gz"]
#[tokio::test(flavor = "multi_thread")]
async fn prover_server_proves_one_batch() {
    let dist_dir = guest_dist_dir();
    println!("[test] Guest dist dir: {}", dist_dir.display());

    let (verifier_input, expected_public_input) = load_batch_and_expected_public_input();

    // --- 2. Set up test HTTP server ---
    let (fri_tx, fri_rx) = oneshot::channel::<Vec<u8>>();
    // Unused in fri-only mode but the state struct always carries it.
    let (snark_tx, _snark_rx) = oneshot::channel::<Vec<u8>>();
    let state = TestServerState {
        verifier_input: Arc::new(verifier_input),
        job_served: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        fri_proof_sender: Arc::new(Mutex::new(Some(fri_tx))),
        snark_proof_sender: Arc::new(Mutex::new(Some(snark_tx))),
    };

    let app = Router::new()
        .route("/airbender/proof_inputs", post(handle_proof_inputs))
        .route(
            "/airbender/submit_proofs",
            post(handle_submit_proofs).layer(DefaultBodyLimit::disable()),
        )
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
    let prover_bin = prover_server_bin();
    println!("[test] Spawning prover server: {}", prover_bin.display());
    let child = Command::new(&prover_bin)
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

    // --- 4. Wait up to TEST_TIMEOUT for the proof, printing a heartbeat every minute ---
    eprintln!(
        "[test] Waiting for FRI proof (timeout: {}s)...",
        TEST_TIMEOUT.as_secs()
    );
    let started_at = Instant::now();
    let proof_bytes = await_with_heartbeat("FRI", fri_rx, TEST_TIMEOUT).await;

    println!(
        "[test] Proof received after {:.1}s ({} bytes)",
        started_at.elapsed().as_secs_f64(),
        proof_bytes.len()
    );

    // --- 5. Verify the proof ---
    verify_fri_proof(&proof_bytes, &expected_public_input, &dist_dir);
}

/// Runs the prover server end-to-end in `fri-snark` mode. The prover proves
/// FRI, submits it to `/airbender/submit_proofs`, then wraps the same proof
/// into a SNARK and submits it to `/airbender/submit_snark_proofs`. The test
/// verifies that both submissions land and that the FRI proof verifies; the
/// SNARK proof is checked for payload shape (JSON-deserializes as
/// `SnarkWrapperProof`) because the server crate does not link a SNARK
/// verifier.
///
/// Additional setup vs the fri-only test:
/// * `IT_SNARK_TRUSTED_SETUP` must point at the CPU CRS file (`setup.key`).
/// * Timeout is bumped to `FRI_SNARK_TEST_TIMEOUT` since CPU SNARK wrapping
///   dominates wall-clock time.
#[ignore = "requires GPU, built guest binary, LFS batch 506093.bin.gz, and IT_SNARK_TRUSTED_SETUP"]
#[tokio::test(flavor = "multi_thread")]
async fn prover_server_proves_fri_snark() {
    let dist_dir = guest_dist_dir();
    println!("[test] Guest dist dir: {}", dist_dir.display());

    let trusted_setup = snark_trusted_setup_path();
    assert!(
        trusted_setup.exists(),
        "IT_SNARK_TRUSTED_SETUP points at non-existent file: {}",
        trusted_setup.display()
    );

    let (verifier_input, expected_public_input) = load_batch_and_expected_public_input();

    // --- 2. Set up test HTTP server with both FRI and SNARK submit endpoints ---
    let (fri_tx, fri_rx) = oneshot::channel::<Vec<u8>>();
    let (snark_tx, snark_rx) = oneshot::channel::<Vec<u8>>();
    let state = TestServerState {
        verifier_input: Arc::new(verifier_input),
        job_served: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        fri_proof_sender: Arc::new(Mutex::new(Some(fri_tx))),
        snark_proof_sender: Arc::new(Mutex::new(Some(snark_tx))),
    };

    let app = Router::new()
        .route("/airbender/proof_inputs", post(handle_proof_inputs))
        .route(
            "/airbender/submit_proofs",
            post(handle_submit_proofs).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/airbender/submit_snark_proofs",
            post(handle_submit_snark_proofs).layer(DefaultBodyLimit::disable()),
        )
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

    // --- 3. Start the prover server binary in fri-snark mode ---
    let prover_bin = prover_server_bin();
    println!(
        "[test] Spawning prover server in fri-snark mode: {}",
        prover_bin.display()
    );
    let child = Command::new(&prover_bin)
        .env("PROVER_SERVER_URL", format!("http://{server_addr}"))
        .env(
            "PROVER_GUEST_DIST_DIR",
            dist_dir.to_str().expect("non-UTF8 guest dist dir"),
        )
        .env("PROVER_MODE", "fri-snark")
        .env(
            "SNARK_TRUSTED_SETUP",
            trusted_setup
                .to_str()
                .expect("non-UTF8 SNARK trusted setup path"),
        )
        .env("PROVER_POLL_INTERVAL_MS", "1000")
        .env("PROVER_ID", "integration-test-fri-snark")
        .spawn()
        .expect("failed to spawn eravm-prover-server");
    println!("[test] Prover server spawned (pid {})", child.id());
    let _child_guard = ChildGuard(child);

    // --- 4. Wait for both proofs. FRI lands first; SNARK follows once
    //        wrapping completes. We use the longer fri-snark timeout for both
    //        because the SNARK wrapper holds the GPU/CPU after FRI returns,
    //        which can delay other progress on a busy host. ---
    eprintln!(
        "[test] Waiting for FRI then SNARK proofs (timeout: {}s)...",
        FRI_SNARK_TEST_TIMEOUT.as_secs()
    );
    let started_at = Instant::now();

    let fri_bytes = await_with_heartbeat("FRI", fri_rx, FRI_SNARK_TEST_TIMEOUT).await;
    println!(
        "[test] FRI proof received after {:.1}s ({} bytes)",
        started_at.elapsed().as_secs_f64(),
        fri_bytes.len()
    );

    let snark_bytes = await_with_heartbeat("SNARK", snark_rx, FRI_SNARK_TEST_TIMEOUT).await;
    println!(
        "[test] SNARK proof received after {:.1}s total ({} bytes)",
        started_at.elapsed().as_secs_f64(),
        snark_bytes.len()
    );

    // --- 5. Verify the FRI proof (cryptographic) and validate SNARK payload shape ---
    verify_fri_proof(&fri_bytes, &expected_public_input, &dist_dir);

    // The server JSON-encodes `SnarkWrapperProof` before hex-encoding into the
    // request body. Deserializing it back is the strongest payload-shape check
    // we can do here without linking a SNARK verifier into the test binary.
    let _snark_proof: SnarkWrapperProof = serde_json::from_slice(&snark_bytes)
        .expect("SNARK proof body did not deserialize as SnarkWrapperProof JSON");
    println!("[test] SNARK proof payload deserialized successfully!");
}
