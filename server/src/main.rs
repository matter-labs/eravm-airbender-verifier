mod network;
mod types;
mod worker;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::info;

use network::{network_worker, NetworkWorkerConfig};
use worker::{prover_worker, Pipeline};

use airbender_host::{Program, ProverLevel};
use eravm_prover_host::{SnarkOptions, SnarkPipeline};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Prove FRI, submit FRI bytes (current default).
    Fri,
    /// Prove FRI then wrap to a SNARK, submit SNARK bytes.
    FriSnark,
    /// Wrap-only: fetch a FRI proof from the job server, submit a SNARK.
    Snark,
}

impl Mode {
    fn needs_gpu_prover(self) -> bool {
        matches!(self, Self::Fri | Self::FriSnark)
    }

    fn needs_snark_pipeline(self) -> bool {
        matches!(self, Self::FriSnark | Self::Snark)
    }
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Prover server: polls for jobs and submits prove results"
)]
struct Cli {
    /// Pipeline mode: which stages this server runs end-to-end.
    #[arg(long, env = "PROVER_MODE", value_enum, default_value_t = Mode::Fri)]
    mode: Mode,

    /// Base URL of the job server (e.g. http://localhost:8080)
    #[arg(long, env = "PROVER_SERVER_URL")]
    server_url: String,

    /// How long to wait between polls when no job is available (milliseconds)
    #[arg(long, env = "PROVER_POLL_INTERVAL_MS", default_value = "5000")]
    poll_interval_ms: u64,

    /// Number of worker threads for the GPU prover
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

    /// Path to a pre-built GPU prover setup cache. The file MUST exist —
    /// `airbender-host` does not auto-generate it; build it once with the
    /// upstream cache-dump tool. Saves several minutes of startup time per
    /// process. Defaults to `setup-cache-<bin_sha256>.bin` in the current
    /// directory, derived from the guest manifest digest. Used only in modes
    /// that prove FRI.
    #[arg(long, env = "PROVER_SETUP_CACHE_PATH")]
    setup_cache_path: Option<PathBuf>,

    /// Directory holding pre-generated SNARK wrapper VKs (`risc_wrapper_vk.json`,
    /// `compression_vk.json`, `snark_vk.json`). Loaded eagerly at startup so
    /// the SNARK pipeline never recomputes them between process restarts.
    /// Required for any mode that produces a SNARK.
    #[arg(long, env = "PROVER_SNARK_VK_DIR")]
    snark_vk_dir: Option<PathBuf>,

    /// Path to the trusted-setup file required by the SNARK wrapper. Required
    /// for any mode that produces a SNARK.
    #[arg(long, env = "PROVER_TRUSTED_SETUP")]
    snark_trusted_setup: Option<PathBuf>,

    /// Enable zero-knowledge mode in the SNARK wrapper.
    #[arg(long, env = "PROVER_SNARK_USE_ZK", default_value_t = false)]
    snark_use_zk: bool,
}

fn main() -> Result<()> {
    init_tracing()?;
    let cli = Cli::parse();

    if let Some(port) = cli.metrics_port {
        zksync_prover_metrics::start_metrics_server(port)
            .context("while starting metrics server")?;
        info!(port, "Metrics server started");
    }

    info!(mode = ?cli.mode, server_url = %cli.server_url, "Starting prover server");

    let pipeline = build_pipeline(&cli)?;

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

    let prover_handle = std::thread::spawn(move || {
        prover_worker(pipeline, job_rx, result_tx);
    });

    network_worker(NetworkWorkerConfig {
        job_tx,
        result_rx,
        client,
        server_url: cli.server_url,
        prover_id: cli.prover_id,
        poll_interval,
        submit_attempts: cli.submit_attempts,
        shutdown,
        mode: cli.mode,
    });

    info!("Waiting for prover to finish current job...");
    prover_handle.join().expect("prover thread panicked");
    Ok(())
}

fn build_pipeline(cli: &Cli) -> Result<Pipeline> {
    let prover = if cli.mode.needs_gpu_prover() {
        let dist_dir = cli.guest_dist_dir.clone().unwrap_or_else(default_dist_dir);
        let program = Program::load(&dist_dir).context("while loading guest program")?;
        let setup_cache_path = cli
            .setup_cache_path
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_setup_cache_path(&program))?;
        info!(path = %setup_cache_path.display(), "Using GPU prover setup cache");
        let mut prover_builder = program
            .gpu_prover()
            .with_level(ProverLevel::RecursionUnified)
            .with_setup_cache_path(&setup_cache_path);
        if let Some(threads) = cli.worker_threads {
            prover_builder = prover_builder.with_worker_threads(threads);
        }
        Some(
            prover_builder
                .build()
                .context("while building GPU prover")?,
        )
    } else {
        None
    };

    let snark = if cli.mode.needs_snark_pipeline() {
        let vk_cache_dir = cli.snark_vk_dir.clone().context(
            "--snark-vk-dir is required for modes that produce a SNARK; \
             generate the VKs once with `eravm-prover-host generate-vk` and pass the directory",
        )?;
        info!(path = %vk_cache_dir.display(), "Using SNARK wrapper VK cache directory");
        let snark_options = SnarkOptions {
            worker_threads: cli.worker_threads,
            trusted_setup: cli.snark_trusted_setup.clone(),
            use_zk: cli.snark_use_zk,
            // The server doesn't write per-batch SNARK artifacts to disk —
            // proofs are forwarded over the network.
            save_intermediates: false,
            vk_cache_dir: Some(vk_cache_dir),
        };
        Some(SnarkPipeline::new(&snark_options).context("while building SNARK pipeline")?)
    } else {
        None
    };

    Ok(match (prover, snark) {
        (Some(prover), None) => Pipeline::Fri { prover },
        (Some(prover), Some(snark)) => Pipeline::FriSnark { prover, snark },
        (None, Some(snark)) => Pipeline::Snark { snark },
        (None, None) => unreachable!("Cli::mode always selects at least one stage"),
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

/// Default setup-cache path keyed on the guest binary's manifest sha256, so a
/// rebuilt guest gets a fresh cache instead of silently reusing stale setups.
fn default_setup_cache_path(program: &Program) -> Result<PathBuf> {
    let manifest_sha256 = program.manifest().bin.sha256.trim();
    if manifest_sha256.is_empty() {
        anyhow::bail!(
            "guest manifest has empty bin.sha256, cannot derive default setup cache path; \
             pass --setup-cache-path explicitly"
        );
    }
    Ok(PathBuf::from(format!("setup-cache-{manifest_sha256}.bin")))
}
