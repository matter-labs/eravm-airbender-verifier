mod network;
mod types;
mod worker;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use airbender_host::SecurityLevel;
use anyhow::{Context, Result};
use clap::Parser;
use eravm_prover_host::{FriPipeline, FriVerifier, SnarkOptions, SnarkPipeline};
use tracing::info;

use network::{network_worker, NetworkWorkerConfig};
use types::ProverMode;
use worker::{prover_worker, WorkerPipelines};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Prover server: polls for jobs and submits prove results"
)]
struct Cli {
    /// Base URL of the job server (e.g. http://localhost:8080)
    #[arg(long, env = "PROVER_SERVER_URL")]
    server_url: String,

    /// Pipeline this prover runs:
    /// `fri-only` (default) — proves FRI, submits FRI;
    /// `fri-snark` — proves FRI + SNARK, submits both;
    /// `snark-only` — wraps FRI proofs into SNARKs, submits SNARK.
    #[arg(long, env = "PROVER_MODE", value_enum, default_value_t = ProverMode::FriOnly)]
    mode: ProverMode,

    /// How long to wait between polls when no job is available (milliseconds)
    #[arg(long, env = "PROVER_POLL_INTERVAL_MS", default_value = "5000")]
    poll_interval_ms: u64,

    /// Number of worker threads for the GPU FRI prover
    #[arg(long, env = "PROVER_WORKER_THREADS")]
    worker_threads: Option<usize>,

    /// Identifier for this prover instance, included in proof submissions.
    /// Defaults to the HOSTNAME environment variable (i.e. the Kubernetes pod name).
    #[arg(long, env = "PROVER_ID", default_value_t = default_prover_id())]
    prover_id: String,

    /// Number of attempts to submit a prove result before giving up
    #[arg(long, env = "PROVER_SUBMIT_ATTEMPTS", default_value = "3")]
    submit_attempts: usize,

    /// Port to expose Prometheus metrics on (disabled if not set)
    #[arg(long, env = "PROVER_METRICS_PORT")]
    metrics_port: Option<u16>,

    /// Path to the compiled guest program directory
    #[arg(long, env = "PROVER_GUEST_DIST_DIR")]
    guest_dist_dir: Option<PathBuf>,

    /// Path to the bellman trusted setup (CRS) for the SNARK wrapper.
    /// Required when `--mode` is `fri-snark` or `snark-only`.
    #[arg(
        long,
        env = "SNARK_TRUSTED_SETUP",
        required_if_eq_any = [("mode", "fri-snark"), ("mode", "snark-only")],
    )]
    snark_trusted_setup: Option<PathBuf>,

    /// Use a zero-knowledge SNARK wrapping path. Off by default.
    #[arg(long, env = "SNARK_USE_ZK")]
    snark_use_zk: bool,

    /// Worker threads for the SNARK wrapper (defaults to wrapper's own default).
    #[arg(long, env = "SNARK_THREADS")]
    snark_threads: Option<usize>,

    /// Save SNARK intermediate artifacts (phase 1/2 proofs and VKs) to disk.
    /// Diagnostic flag — off by default in server mode.
    #[arg(long, env = "SNARK_SAVE_INTERMEDIATES")]
    snark_save_intermediates: bool,
}

fn main() -> Result<()> {
    init_tracing()?;
    let cli = Cli::parse();

    if let Some(port) = cli.metrics_port {
        zksync_prover_metrics::start_metrics_server(port)
            .context("while starting metrics server")?;
        info!(port, "Metrics server started");
    }

    let dist_dir = cli.guest_dist_dir.clone().unwrap_or_else(default_dist_dir);
    let security = SecurityLevel::default();

    let pipelines = build_pipelines(&cli, &dist_dir, security)?;

    let client = reqwest::blocking::Client::new();
    let poll_interval = Duration::from_millis(cli.poll_interval_ms);

    // Channel capacity 1: the network worker can buffer one job ahead while the prover is busy.
    let (job_tx, job_rx) = mpsc::sync_channel(1);
    // Channel capacity 2 to accommodate `fri-snark` mode emitting two results per job.
    let (result_tx, result_rx) = mpsc::sync_channel(2);

    let shutdown = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let shutdown = Arc::clone(&shutdown);
        move || {
            info!("Shutdown signal received, stopping after current job...");
            shutdown.store(true, Ordering::Relaxed);
        }
    })
    .context("while setting Ctrl-C handler")?;

    info!(
        server_url = %cli.server_url,
        mode = ?cli.mode,
        "Starting prover server"
    );

    let prover_handle = std::thread::spawn(move || {
        prover_worker(pipelines, job_rx, result_tx);
    });

    network_worker(NetworkWorkerConfig {
        mode: cli.mode,
        job_tx,
        result_rx,
        client,
        server_url: cli.server_url,
        prover_id: cli.prover_id,
        poll_interval,
        submit_attempts: cli.submit_attempts,
        shutdown,
    });

    info!("Waiting for prover to finish current job...");
    prover_handle.join().expect("prover thread panicked");
    Ok(())
}

fn build_pipelines(
    cli: &Cli,
    dist_dir: &std::path::Path,
    security: SecurityLevel,
) -> Result<WorkerPipelines> {
    let snark_options = SnarkOptions {
        worker_threads: cli.snark_threads,
        trusted_setup: cli.snark_trusted_setup.clone(),
        use_zk: cli.snark_use_zk,
        save_intermediates: cli.snark_save_intermediates,
    };

    let mut pipelines = WorkerPipelines {
        mode: cli.mode,
        fri: None,
        fri_verifier: None,
        snark: None,
    };

    match cli.mode {
        ProverMode::FriOnly => {
            pipelines.fri = Some(
                FriPipeline::new(dist_dir, cli.worker_threads, security)
                    .context("while building FRI pipeline")?,
            );
        }
        ProverMode::FriSnark => {
            pipelines.fri = Some(
                FriPipeline::new(dist_dir, cli.worker_threads, security)
                    .context("while building FRI pipeline")?,
            );
            pipelines.snark =
                Some(SnarkPipeline::new(&snark_options).context("while building SNARK pipeline")?);
        }
        ProverMode::SnarkOnly => {
            pipelines.fri_verifier = Some(
                FriVerifier::new(dist_dir, security)
                    .context("while building FRI verifier for snark-only mode")?,
            );
            pipelines.snark =
                Some(SnarkPipeline::new(&snark_options).context("while building SNARK pipeline")?);
        }
    }

    Ok(pipelines)
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

fn default_prover_id() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_owned())
}

/// Compile-time fallback path to the guest program.
/// Override at runtime with `--guest-dist-dir` or `PROVER_GUEST_DIST_DIR`.
fn default_dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}
