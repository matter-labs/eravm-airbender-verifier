//! Measures the time saved by reading verification keys / setup from disk
//! vs. deriving them on the fly. Runs each scenario twice — once with an
//! empty cache (cold), once with a populated cache (warm) — and reports
//! the wall-clock difference.

use airbender_host::{Program, ProverLevel, SecurityLevel, VerificationKey};
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use eravm_prover_host::{SnarkOptions, SnarkPipeline};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;

const RISC_WRAPPER_VK_FILE_NAME: &str = "risc_wrapper_vk.json";
const COMPRESSION_VK_FILE_NAME: &str = "compression_vk.json";
const SNARK_VK_FILE_NAME: &str = "snark_vk.json";

#[derive(ValueEnum, Clone, Copy, Debug)]
enum SecurityLevelArg {
    #[value(name = "80")]
    Bits80,
    #[value(name = "100")]
    Bits100,
}

impl From<SecurityLevelArg> for SecurityLevel {
    fn from(s: SecurityLevelArg) -> Self {
        match s {
            SecurityLevelArg::Bits80 => SecurityLevel::Bits80,
            SecurityLevelArg::Bits100 => SecurityLevel::Bits100,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Fri,
    Snark,
}

#[derive(Debug, Parser)]
#[command(
    about = "Benchmark cold (on-the-fly) vs. warm (cached on disk) VK / setup initialization"
)]
struct Cli {
    /// Directory holding the SNARK wrapper VK cache (3 JSON files). The directory
    /// is wiped before the cold run so generation happens from scratch.
    #[arg(long)]
    snark_vk_dir: PathBuf,

    /// File path holding the cached FRI VerificationKey (bincode-encoded). The
    /// file is removed before the cold run.
    #[arg(long)]
    fri_vk_path: PathBuf,

    /// Trusted setup path forwarded to the SNARK wrapper.
    #[arg(long)]
    trusted_setup: Option<PathBuf>,

    /// Worker thread count forwarded to the SNARK wrapper.
    #[arg(long)]
    worker_threads: Option<usize>,

    /// Security level used for FRI VK generation.
    #[arg(long, default_value = "80")]
    security: SecurityLevelArg,

    /// Which scenarios to run. Defaults to both. Comma-separated.
    #[arg(long, value_delimiter = ',')]
    scenarios: Option<Vec<Scenario>>,
}

struct BenchResult {
    name: &'static str,
    cold: Duration,
    warm: Duration,
}

fn main() -> Result<()> {
    init_tracing().context("while attempting to initialize tracing")?;

    let cli = Cli::parse();
    let scenarios = cli
        .scenarios
        .clone()
        .unwrap_or_else(|| vec![Scenario::Fri, Scenario::Snark]);

    let mut results = Vec::new();
    if scenarios.contains(&Scenario::Fri) {
        results.push(bench_fri_vk(&cli.fri_vk_path, cli.security.into())?);
    }
    if scenarios.contains(&Scenario::Snark) {
        let opts = SnarkOptions {
            worker_threads: cli.worker_threads,
            trusted_setup: cli.trusted_setup.clone(),
            use_zk: false,
            save_intermediates: false,
            vk_cache_dir: Some(cli.snark_vk_dir.clone()),
        };
        results.push(bench_snark_vks(&cli.snark_vk_dir, &opts)?);
    }

    print_summary(&results);
    Ok(())
}

fn bench_fri_vk(cache_path: &Path, security: SecurityLevel) -> Result<BenchResult> {
    if cache_path.exists() {
        std::fs::remove_file(cache_path).with_context(|| {
            format!(
                "while attempting to remove existing FRI VK cache {}",
                cache_path.display()
            )
        })?;
    }
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "while attempting to create FRI VK cache parent {}",
                parent.display()
            )
        })?;
    }

    let program = Program::load(dist_dir()).context("while attempting to load guest program")?;
    let verifier = program
        .real_verifier(ProverLevel::RecursionUnified)
        .build()
        .context("while attempting to build real verifier")?;

    info!("FRI VK cold run: generating from scratch");
    let cold_start = Instant::now();
    let vk = verifier
        .generate_vk(security)
        .context("while attempting to generate FRI VK")?;
    let cold = cold_start.elapsed();
    info!(?cold, "FRI VK cold run finished");

    let encoded = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .context("while attempting to bincode-encode FRI VK")?;
    std::fs::write(cache_path, &encoded).with_context(|| {
        format!(
            "while attempting to write FRI VK cache {}",
            cache_path.display()
        )
    })?;
    drop(vk);

    info!("FRI VK warm run: loading from cache");
    let warm_start = Instant::now();
    let bytes = std::fs::read(cache_path).with_context(|| {
        format!(
            "while attempting to read FRI VK cache {}",
            cache_path.display()
        )
    })?;
    let (loaded, decoded_len): (VerificationKey, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .context("while attempting to decode cached FRI VK")?;
    anyhow::ensure!(
        decoded_len == bytes.len(),
        "trailing bytes in FRI VK cache {}",
        cache_path.display()
    );
    let warm = warm_start.elapsed();
    drop(loaded);
    info!(?warm, "FRI VK warm run finished");

    Ok(BenchResult {
        name: "FRI VK",
        cold,
        warm,
    })
}

fn bench_snark_vks(cache_dir: &Path, opts: &SnarkOptions) -> Result<BenchResult> {
    if cache_dir.exists() {
        std::fs::remove_dir_all(cache_dir).with_context(|| {
            format!(
                "while attempting to clear SNARK VK cache dir {}",
                cache_dir.display()
            )
        })?;
    }
    std::fs::create_dir_all(cache_dir).with_context(|| {
        format!(
            "while attempting to create SNARK VK cache dir {}",
            cache_dir.display()
        )
    })?;

    info!("SNARK VKs cold run: deriving all three phases from scratch");
    let cold_start = Instant::now();
    let pipeline =
        SnarkPipeline::new(opts).context("while attempting to build cold SnarkPipeline")?;
    let cold = cold_start.elapsed();
    drop(pipeline);
    info!(?cold, "SNARK VKs cold run finished");

    for file_name in [
        RISC_WRAPPER_VK_FILE_NAME,
        COMPRESSION_VK_FILE_NAME,
        SNARK_VK_FILE_NAME,
    ] {
        let path = cache_dir.join(file_name);
        anyhow::ensure!(
            path.exists(),
            "expected {} to be cached after cold run",
            path.display()
        );
    }

    info!("SNARK VKs warm run: loading all three phases from cache");
    let warm_start = Instant::now();
    let pipeline =
        SnarkPipeline::new(opts).context("while attempting to build warm SnarkPipeline")?;
    let warm = warm_start.elapsed();
    drop(pipeline);
    info!(?warm, "SNARK VKs warm run finished");

    Ok(BenchResult {
        name: "SNARK VKs",
        cold,
        warm,
    })
}

fn print_summary(results: &[BenchResult]) {
    println!();
    println!("========== Setup Cache Benchmark ==========");
    println!(
        "{:<12} {:>14} {:>14} {:>14} {:>10}",
        "Scenario", "Cold (s)", "Warm (s)", "Saved (s)", "Speedup"
    );
    for r in results {
        let saved = r.cold.saturating_sub(r.warm);
        let cold_s = r.cold.as_secs_f64();
        let warm_s = r.warm.as_secs_f64();
        let speedup = if warm_s > 0.0 {
            format!("{:>9.1}x", cold_s / warm_s)
        } else {
            "    n/a".to_string()
        };
        println!(
            "{:<12} {:>14.3} {:>14.3} {:>14.3} {:>10}",
            r.name,
            cold_s,
            warm_s,
            saved.as_secs_f64(),
            speedup
        );
    }
    println!("===========================================");
}

fn dist_dir() -> PathBuf {
    if let Ok(p) = std::env::var("ERAVM_PROVER_HOST_GUEST_DIR") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}

fn init_tracing() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|err| anyhow::anyhow!("while attempting to initialize tracing subscriber: {err}"))
}
