mod network;
mod types;
mod worker;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use network::{network_worker, NetworkWorkerConfig};
use worker::prover_worker;

use airbender_host::{Program, ProverLevel};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Prover server: polls for jobs and submits prove results"
)]
struct Cli {
    /// Base URL of the job server (e.g. http://localhost:8080)
    #[arg(long, env = "PROVER_SERVER_URL")]
    server_url: String,

    /// How long to wait between polls when no job is available (milliseconds)
    #[arg(long, env = "PROVER_POLL_INTERVAL_MS", default_value = "5000")]
    poll_interval_ms: u64,

    /// Number of worker threads for the GPU prover
    #[arg(long, env = "PROVER_WORKER_THREADS")]
    worker_threads: Option<usize>,

    /// Number of attempts to submit a prove result before giving up
    #[arg(long, env = "PROVER_SUBMIT_ATTEMPTS", default_value = "3")]
    submit_attempts: usize,

    /// Port to expose Prometheus metrics on (disabled if not set)
    #[arg(long, env = "PROVER_METRICS_PORT")]
    metrics_port: Option<u16>,

    /// Path to the compiled guest program directory
    #[arg(long, env = "PROVER_GUEST_DIST_DIR")]
    guest_dist_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    init_tracing()?;
    let cli = Cli::parse();

    if let Some(port) = cli.metrics_port {
        zksync_prover_metrics::start_metrics_server(port)
            .context("while starting metrics server")?;
        info!(port, "Metrics server started");
    }

    let dist_dir = cli.guest_dist_dir.unwrap_or_else(default_dist_dir);
    let program = Program::load(&dist_dir).context("while loading guest program")?;
    let mut prover_builder = program
        .gpu_prover()
        .with_level(ProverLevel::RecursionUnified);
    if let Some(threads) = cli.worker_threads {
        prover_builder = prover_builder.with_worker_threads(threads);
    }
    let prover = prover_builder
        .build()
        .context("while building GPU prover")?;

    let client = reqwest::blocking::Client::new();
    let poll_interval = Duration::from_millis(cli.poll_interval_ms);

    // Channel capacity 1: the network worker can buffer one job ahead while the prover is busy.
    let (job_tx, job_rx) = mpsc::sync_channel(1);
    // Channel capacity 1: the prover sends one result at a time.
    let (result_tx, result_rx) = mpsc::sync_channel(1);

    let shutdown = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let shutdown = Arc::clone(&shutdown);
        move || {
            info!("Shutdown signal received, stopping after current job...");
            shutdown.store(true, Ordering::Relaxed);
        }
    })
    .context("while setting Ctrl-C handler")?;

    info!(server_url = %cli.server_url, "Starting prover server");

    let prover_handle = std::thread::spawn(move || {
        prover_worker(prover, job_rx, result_tx);
    });

    network_worker(NetworkWorkerConfig {
        job_tx,
        result_rx,
        client,
        server_url: cli.server_url,
        poll_interval,
        submit_attempts: cli.submit_attempts,
        shutdown,
    });

    info!("Waiting for prover to finish current job...");
    prover_handle.join().expect("prover thread panicked");
    Ok(())
}

fn init_tracing() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        // `try_init` returns a `SetGlobalDefaultError` which does not implement
        // `std::error::Error`, so `.context()` is unavailable here.
        .map_err(|err| anyhow::anyhow!("failed to initialize tracing: {err}"))
}

/// Compile-time fallback path to the guest program.
/// Override at runtime with `--guest-dist-dir` or `PROVER_GUEST_DIST_DIR`.
fn default_dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}
