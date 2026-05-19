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

use network::NetworkWorker;
use types::ProverMode;
use worker::{ProverWorker, ProverWorkerBuilder};

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

    /// TCP connect timeout for HTTP calls to the job server (milliseconds)
    #[arg(long, env = "PROVER_HTTP_CONNECT_TIMEOUT_MS", default_value = "5000")]
    http_connect_timeout_ms: u64,

    /// Per-request timeout for polling job inputs (milliseconds)
    #[arg(long, env = "PROVER_POLL_TIMEOUT_MS", default_value = "30000")]
    poll_timeout_ms: u64,

    /// Per-request timeout for submitting proof results (milliseconds).
    /// SNARK submissions can be large, so this is generally larger than the poll timeout.
    #[arg(long, env = "PROVER_SUBMIT_TIMEOUT_MS", default_value = "120000")]
    submit_timeout_ms: u64,

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

    let prover_builder = build_prover(&cli, &dist_dir, security)?;

    let connect_timeout = Duration::from_millis(cli.http_connect_timeout_ms);
    let poll_client = reqwest::blocking::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(Duration::from_millis(cli.poll_timeout_ms))
        .build()
        .context("while building poll HTTP client")?;
    let submit_client = reqwest::blocking::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(Duration::from_millis(cli.submit_timeout_ms))
        .build()
        .context("while building submit HTTP client")?;
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

    let prover = prover_builder
        .build(job_rx, result_tx)
        .context("while building prover worker")?;
    let prover_handle = std::thread::spawn(move || prover.run());

    NetworkWorker {
        mode: cli.mode,
        job_tx,
        result_rx,
        poll_client,
        submit_client,
        server_url: cli.server_url,
        prover_id: cli.prover_id,
        poll_interval,
        submit_attempts: cli.submit_attempts,
        shutdown,
    }
    .run();

    info!("Waiting for prover to finish current job...");
    prover_handle.join().expect("prover thread panicked");
    Ok(())
}

fn build_prover(
    cli: &Cli,
    dist_dir: &std::path::Path,
    security: SecurityLevel,
) -> Result<ProverWorkerBuilder> {
    let snark_options = SnarkOptions {
        worker_threads: cli.snark_threads,
        trusted_setup: cli.snark_trusted_setup.clone(),
        use_zk: cli.snark_use_zk,
        // Server path uses `wrap_fri`, which never persists intermediates.
        save_intermediates: false,
    };

    let build_fri = || {
        FriPipeline::new(dist_dir, cli.worker_threads, security)
            .context("while building FRI pipeline")
    };
    let build_snark =
        || SnarkPipeline::new(&snark_options).context("while building SNARK pipeline");

    let builder = ProverWorker::builder();
    Ok(match cli.mode {
        ProverMode::FriOnly => builder.with_fri(build_fri()?),
        ProverMode::FriSnark => builder.with_fri(build_fri()?).with_snark(build_snark()?),
        ProverMode::SnarkOnly => {
            let verifier = FriVerifier::new(dist_dir, security)
                .context("while building FRI verifier for snark-only mode")?;
            builder
                .with_fri_verifier(verifier)
                .with_snark(build_snark()?)
        }
    })
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
