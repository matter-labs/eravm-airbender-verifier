//! Integration test: starts the prover server binary, serves one real batch via a local HTTP
//! server, waits for the proof(s) to be submitted, then verifies them.
//!
//! Gated by `#[ignore]` because it needs a GPU, the built guest binary, and the LFS batch
//! corpus.
//!
//! `prover_server_proves_fri_then_snark` runs `fri-only` to produce the FRI proof against
//! `/airbender/submit_proofs`, kills that prover, then starts a fresh `snark-only` prover that
//! picks the captured FRI proof up via `/airbender/snark_inputs` and submits the SNARK proof to
//! `/airbender/submit_snark_proofs`. Two sequential processes — `fri-snark` would be cleaner but
//! the FRI prover's GPU allocator eats nearly the whole device, leaving no room for the SNARK
//! wrapper alongside it. The trusted setup is fetched into the system temp dir on first run
//! (matches the build's `snark_gpu` feature — GPU `setup_compact.key` when enabled, CPU
//! `setup_2^24.key` otherwise); override the path via `IT_SNARK_TRUSTED_SETUP` to reuse a local
//! copy.

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

use airbender_host::{Program, Proof, ProverLevel, SecurityLevel, VerificationRequest, Verifier};
use eravm_prover_host::{
    default_trusted_setup_download_url, default_trusted_setup_path,
    download_trusted_setup_if_not_present, load_vk_from_disk, SnarkWrapperProof,
};
use zksync_airbender_verifier::types::V1AirbenderVerifierInput;
use zksync_airbender_verifier::Verify;
use zksync_cli_utils::{load_batch, BatchInputFile};

const TEST_TIMEOUT: Duration = Duration::from_secs(20 * 60);
// SNARK wrapping is the long pole on top of FRI; give it room.
const FRI_SNARK_TEST_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
/// CUDA driver cleanup window after SIGKILL'ing the fri-only prover. Without
/// it, the snark-only prover's first `cudaMalloc` can race with the tail of
/// the dead context's reclaim and fail with `cudaErrorMemoryAllocation`.
const GPU_RECLAIM_DELAY: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Test HTTP server state and handlers
// ---------------------------------------------------------------------------

/// `(batch_number, bincode-encoded `Proof` bytes)` captured from a FRI submission.
type CapturedFriProof = Arc<Mutex<Option<(u32, Vec<u8>)>>>;

#[derive(Clone)]
struct TestServerState {
    /// Stored as the bare V1 payload so the test mock matches the upstream
    /// zksync-era wire format (a flat struct, no version enum wrapper).
    verifier_input: Arc<V1AirbenderVerifierInput>,
    /// One-shot latch for `/airbender/proof_inputs`: serve the job once, then 204.
    fri_input_served: Arc<std::sync::atomic::AtomicBool>,
    /// Latest FRI submission captured by `/airbender/submit_proofs`. Read by
    /// `/airbender/snark_inputs` so the snark-only prover can pick it up.
    fri_proof_capture: CapturedFriProof,
    fri_proof_sender: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
    /// One-shot latch for `/airbender/snark_inputs`: serve the captured FRI
    /// proof once, then 204. Only flips after `fri_proof_capture` is `Some`.
    snark_input_served: Arc<std::sync::atomic::AtomicBool>,
    snark_proof_sender: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
}

/// `POST /airbender/proof_inputs` — serves the job once, then returns 204.
async fn handle_proof_inputs(State(state): State<TestServerState>) -> impl IntoResponse {
    if state
        .fri_input_served
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return StatusCode::NO_CONTENT.into_response();
    }
    println!("[test-server] Serving job to prover");
    Json((*state.verifier_input).clone()).into_response()
}

/// `POST /airbender/snark_inputs` — once the FRI submission has been captured,
/// serves it (bincode-encoded `Proof`) to a snark-only prover exactly once;
/// before capture or after replay, returns 204.
async fn handle_snark_inputs(State(state): State<TestServerState>) -> impl IntoResponse {
    let Some((batch_number, proof_bytes)) =
        state.fri_proof_capture.lock().expect("poisoned").clone()
    else {
        return StatusCode::NO_CONTENT.into_response();
    };
    if state
        .snark_input_served
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return StatusCode::NO_CONTENT.into_response();
    }
    println!(
        "[test-server] Serving SNARK input for batch {batch_number} ({} bytes)",
        proof_bytes.len()
    );
    Json(serde_json::json!({
        "l1_batch_number": batch_number,
        "fri_proof": hex::encode(&proof_bytes),
    }))
    .into_response()
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
    // Capture for replay via `/airbender/snark_inputs`. Stored before signaling
    // the receiver so a snark-only prover that polls right after the test
    // unblocks always sees a populated capture.
    *state.fri_proof_capture.lock().expect("poisoned") =
        Some((body.l1_batch_number, proof_bytes.clone()));
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

/// Path to the committed FRI verification key. Both the spawned prover and
/// the in-test proof verifier load this file directly — the server is
/// configured to never derive a VK on the fly, so it must exist.
fn fri_vk_path() -> PathBuf {
    std::env::var_os("IT_FRI_VK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vks/fri_vk.bin"))
}

/// Path to the committed SNARK wrapper verification key. Required for the
/// `snark-only` phase of the test; not consumed in the FRI-only phase.
fn snark_vk_path() -> PathBuf {
    std::env::var_os("IT_SNARK_VK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vks/snark_vk.json"))
}

/// CRS used by the SNARK wrapper. The build's `snark_gpu` feature picks the
/// right URL (GPU `setup_compact.key` vs CPU `setup_2^24.key`).
///
/// If `IT_SNARK_TRUSTED_SETUP` is set, that path is used verbatim. Otherwise
/// the file is fetched into the system temp directory on first run — keeps
/// the test self-contained without depending on `target/` being writable
/// (some CI setups build and test as different users). The cache filename
/// includes the feature suffix so CPU and GPU runs don't clobber each other.
fn snark_trusted_setup_path() -> PathBuf {
    let path = std::env::var_os("IT_SNARK_TRUSTED_SETUP")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut name = std::ffi::OsString::from("eravm-airbender-");
            name.push(default_trusted_setup_path().as_os_str());
            std::env::temp_dir().join(name)
        });

    download_trusted_setup_if_not_present(&path, default_trusted_setup_download_url())
        .expect("failed to provision SNARK trusted setup for integration test");

    path
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
fn load_batch_and_expected_public_input() -> (V1AirbenderVerifierInput, [u32; 8]) {
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
    (v1, expected_public_input)
}

/// Verifies a bincode-encoded `Proof` payload against the committed FRI VK.
fn verify_fri_proof(
    proof_bytes: &[u8],
    expected_public_input: &[u32; 8],
    dist_dir: &std::path::Path,
    vk_path: &std::path::Path,
) {
    println!("[test] Loading guest program for verification...");
    let program = Program::load(dist_dir).expect("failed to load guest program");
    let verifier = program
        .real_verifier(ProverLevel::RecursionUnified)
        .build()
        .expect("failed to build RealVerifier");

    let vk = load_vk_from_disk(vk_path, SecurityLevel::default())
        .expect("failed to load committed FRI verification key");

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

/// Exercises `fri-only` followed by `snark-only` end-to-end against a single
/// test HTTP server:
/// 1. Start a prover in `fri-only` mode, wait for the FRI submission to land
///    on `/airbender/submit_proofs`, then kill it (the FRI prover claims
///    nearly the entire GPU at init, so the SNARK wrapper can't share).
/// 2. Start a fresh prover in `snark-only` mode. The server hands the just-
///    captured FRI proof back via `/airbender/snark_inputs`, the prover wraps
///    it, and submits the SNARK proof to `/airbender/submit_snark_proofs`.
///
/// The FRI proof is verified cryptographically. The SNARK proof is checked
/// for payload shape only (round-trips through `serde_json` as
/// `SnarkWrapperProof`) since the server crate does not link a SNARK verifier.
#[ignore = "requires GPU, built guest binary, and LFS batch 506093.bin.gz"]
#[tokio::test(flavor = "multi_thread")]
async fn prover_server_proves_fri_then_snark() {
    let dist_dir = guest_dist_dir();
    println!("[test] Guest dist dir: {}", dist_dir.display());

    let trusted_setup = snark_trusted_setup_path();
    println!("[test] SNARK trusted setup: {}", trusted_setup.display());

    let (verifier_input, expected_public_input) = load_batch_and_expected_public_input();

    // --- 2. Set up test HTTP server with all four prover endpoints. The same
    //        server instance is shared by both prover invocations. ---
    let (fri_tx, fri_rx) = oneshot::channel::<Vec<u8>>();
    let (snark_tx, snark_rx) = oneshot::channel::<Vec<u8>>();
    let state = TestServerState {
        verifier_input: Arc::new(verifier_input),
        fri_input_served: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        fri_proof_capture: Arc::new(Mutex::new(None)),
        fri_proof_sender: Arc::new(Mutex::new(Some(fri_tx))),
        snark_input_served: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        snark_proof_sender: Arc::new(Mutex::new(Some(snark_tx))),
    };

    let app = Router::new()
        .route("/airbender/proof_inputs", post(handle_proof_inputs))
        .route(
            "/airbender/submit_proofs",
            post(handle_submit_proofs).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/airbender/snark_inputs",
            post(handle_snark_inputs).layer(DefaultBodyLimit::disable()),
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

    let prover_bin = prover_server_bin();
    let server_url = format!("http://{server_addr}");
    let dist_dir_str = dist_dir
        .to_str()
        .expect("non-UTF8 guest dist dir")
        .to_owned();
    let trusted_setup_str = trusted_setup
        .to_str()
        .expect("non-UTF8 SNARK trusted setup path")
        .to_owned();
    let fri_vk = fri_vk_path();
    let snark_vk = snark_vk_path();
    assert!(
        fri_vk.exists(),
        "FRI verification key not found at {}. Run `cargo run -p eravm-prover-host -- gen-vks` first.",
        fri_vk.display()
    );
    assert!(
        snark_vk.exists(),
        "SNARK verification key not found at {}. Run `cargo run -p eravm-prover-host -- gen-vks` first.",
        snark_vk.display()
    );
    let fri_vk_str = fri_vk.to_str().expect("non-UTF8 FRI VK path").to_owned();
    let snark_vk_str = snark_vk
        .to_str()
        .expect("non-UTF8 SNARK VK path")
        .to_owned();
    println!("[test] FRI VK: {fri_vk_str}");
    println!("[test] SNARK VK: {snark_vk_str}");

    // --- 3a. Phase 1: spawn fri-only prover, wait for FRI proof, then kill it. ---
    println!(
        "[test] Phase 1: spawning fri-only prover: {}",
        prover_bin.display()
    );
    let fri_child = Command::new(&prover_bin)
        .env("PROVER_SERVER_URL", &server_url)
        .env("PROVER_GUEST_DIST_DIR", &dist_dir_str)
        .env("PROVER_MODE", "fri-only")
        .env("FRI_VK", &fri_vk_str)
        .env("PROVER_POLL_INTERVAL_MS", "1000")
        .env("PROVER_ID", "integration-test-fri")
        .spawn()
        .expect("failed to spawn fri-only eravm-prover-server");
    println!("[test] fri-only prover spawned (pid {})", fri_child.id());
    let fri_guard = ChildGuard(fri_child);

    eprintln!(
        "[test] Waiting for FRI proof (timeout: {}s)...",
        TEST_TIMEOUT.as_secs()
    );
    let started_at = Instant::now();
    let fri_bytes = await_with_heartbeat("FRI", fri_rx, TEST_TIMEOUT).await;
    println!(
        "[test] FRI proof received after {:.1}s ({} bytes)",
        started_at.elapsed().as_secs_f64(),
        fri_bytes.len()
    );

    // Kill the fri-only prover before starting the snark-only one so they
    // don't fight over the GPU.
    println!("[test] Phase 1 complete; stopping fri-only prover");
    drop(fri_guard);

    // SIGKILL is synchronous from the kernel's PoV, but the CUDA driver
    // doesn't always reap the dead context immediately — kicking off the
    // snark-only prover too soon makes its first `cudaMalloc` race with the
    // tail of the reclaim and fail with `cudaErrorMemoryAllocation`.
    println!(
        "[test] Sleeping {:?} to let the CUDA driver reclaim GPU state",
        GPU_RECLAIM_DELAY
    );
    tokio::time::sleep(GPU_RECLAIM_DELAY).await;

    // --- 3b. Phase 2: spawn snark-only prover. It will poll
    //        `/airbender/snark_inputs`, receive the captured FRI proof, wrap
    //        it, and submit the SNARK proof. ---
    println!(
        "[test] Phase 2: spawning snark-only prover: {}",
        prover_bin.display()
    );
    let snark_child = Command::new(&prover_bin)
        .env("PROVER_SERVER_URL", &server_url)
        .env("PROVER_GUEST_DIST_DIR", &dist_dir_str)
        .env("PROVER_MODE", "snark-only")
        .env("SNARK_TRUSTED_SETUP_FILE", &trusted_setup_str)
        .env("FRI_VK", &fri_vk_str)
        .env("SNARK_VK", &snark_vk_str)
        .env("PROVER_POLL_INTERVAL_MS", "1000")
        .env("PROVER_ID", "integration-test-snark")
        .spawn()
        .expect("failed to spawn snark-only eravm-prover-server");
    println!(
        "[test] snark-only prover spawned (pid {})",
        snark_child.id()
    );
    let _snark_guard = ChildGuard(snark_child);

    eprintln!(
        "[test] Waiting for SNARK proof (timeout: {}s)...",
        FRI_SNARK_TEST_TIMEOUT.as_secs()
    );
    let snark_started_at = Instant::now();
    let snark_bytes = await_with_heartbeat("SNARK", snark_rx, FRI_SNARK_TEST_TIMEOUT).await;
    println!(
        "[test] SNARK proof received after {:.1}s ({} bytes)",
        snark_started_at.elapsed().as_secs_f64(),
        snark_bytes.len()
    );

    // --- 4. Verify the FRI proof cryptographically and round-trip the SNARK payload. ---
    verify_fri_proof(&fri_bytes, &expected_public_input, &dist_dir, &fri_vk);

    // The server JSON-encodes `SnarkWrapperProof` before hex-encoding into the
    // request body. Deserializing it back is the strongest payload-shape check
    // we can do here without linking a SNARK verifier into the test binary.
    let _snark_proof: SnarkWrapperProof = serde_json::from_slice(&snark_bytes)
        .expect("SNARK proof body did not deserialize as SnarkWrapperProof JSON");
    println!("[test] SNARK proof payload deserialized successfully!");
}
