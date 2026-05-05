//! Simulator-mode integration test: starts the prover server binary built without
//! the `gpu` feature, serves one batch via a local HTTP server, and asserts that
//! the server submits empty proof bytes after running the guest in the RISC-V
//! simulator.

#![cfg(not(feature = "gpu"))]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use tokio::process::Command;
use tokio::sync::oneshot;

use zksync_airbender_verifier::test_utils::augment_with_synthetic_commitment;
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_cli_utils::{load_batch, BatchInputFile};

const TEST_TIMEOUT: Duration = Duration::from_secs(900); // 15 min — simulator is slower than GPU
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct TestServerState {
    verifier_input: Arc<AirbenderVerifierInput>,
    job_served: Arc<std::sync::atomic::AtomicBool>,
    proof_sender: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
}

async fn handle_proof_inputs(State(state): State<TestServerState>) -> impl IntoResponse {
    if state
        .job_served
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return StatusCode::NO_CONTENT.into_response();
    }
    eprintln!("[test-server] Serving job to simulator");
    Json((*state.verifier_input).clone()).into_response()
}

#[derive(serde::Deserialize)]
struct SubmitProofBody {
    l1_batch_number: u32,
    #[allow(dead_code)]
    prover_id: String,
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
    eprintln!(
        "[test-server] Received proof for batch {} ({} bytes)",
        body.l1_batch_number,
        proof_bytes.len()
    );
    if let Some(tx) = state.proof_sender.lock().expect("poisoned").take() {
        let _ = tx.send(proof_bytes);
    }
    StatusCode::OK
}

fn guest_dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}

fn batch_file_path(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/era_mainnet_batches/binary")
        .join(filename)
}

#[tokio::test(flavor = "multi_thread")]
async fn simulator_processes_one_batch_and_submits_empty_proof() {
    let dist_dir = guest_dist_dir();
    let batch_path = batch_file_path("506093.bin.gz");

    let batch_input = BatchInputFile {
        number: 506093,
        path: batch_path,
    };
    let raw = load_batch(&batch_input).expect("failed to load batch");
    let verifier_input =
        augment_with_synthetic_commitment(raw).expect("failed to synthesize commitment input");

    let (proof_tx, proof_rx) = oneshot::channel::<Vec<u8>>();
    let state = TestServerState {
        verifier_input: Arc::new(verifier_input),
        job_served: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        proof_sender: Arc::new(Mutex::new(Some(proof_tx))),
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
    eprintln!("[test] Test HTTP server listening on http://{server_addr}");

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test HTTP server exited with error");
    });

    let prover_bin = env!("CARGO_BIN_EXE_eravm-prover-server");
    eprintln!("[test] Spawning simulator prover server: {prover_bin}");
    let mut child = Command::new(prover_bin)
        .env("PROVER_SERVER_URL", format!("http://{server_addr}"))
        .env(
            "PROVER_GUEST_DIST_DIR",
            dist_dir.to_str().expect("non-UTF8 guest dist dir"),
        )
        .env("PROVER_POLL_INTERVAL_MS", "1000")
        .env("PROVER_ID", "simulator-integration-test")
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn eravm-prover-server");

    let started_at = Instant::now();

    let proof_bytes = tokio::time::timeout(TEST_TIMEOUT, async {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        interval.tick().await; // first tick fires immediately, skip it
        let mut proof_rx = std::pin::pin!(proof_rx);
        loop {
            tokio::select! {
                biased;
                result = &mut proof_rx => {
                    return result.expect("proof channel closed without receiving a proof");
                }
                exit_status = child.wait() => {
                    let status = exit_status.expect("failed to wait on prover-server child");
                    panic!(
                        "prover-server exited prematurely with {status} after {:.0}s",
                        started_at.elapsed().as_secs_f64()
                    );
                }
                _ = interval.tick() => {
                    eprintln!(
                        "[test] Still waiting for proof... elapsed: {:.0}s",
                        started_at.elapsed().as_secs_f64()
                    );
                }
            }
        }
    })
    .await
    .expect("timed out waiting for submit_proofs");

    assert!(
        proof_bytes.is_empty(),
        "simulator mode must submit empty proof bytes, got {} bytes",
        proof_bytes.len()
    );
    eprintln!("[test] Simulator submitted empty proof as expected");
}
