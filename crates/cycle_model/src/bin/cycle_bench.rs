//! Airbender cycle-cost calibration bench.
//!
//! For each batch it (1) runs the fast VM natively with the feature-counting
//! tracer to get a `FeatureVector` (the cheap, sequencer-computable model
//! inputs), and (2) runs the marker-instrumented guest through the transpiler
//! to get ground-truth cycles / phases / delegations. Rows are written to
//! `dataset.{json,csv}` for the Python fit.
//!
//! Usage (needs the LFS corpus and a guest built with `--features cycle-markers`):
//!
//! ```text
//! cargo airbender build --project guest --features cycle-markers   # → app.bin/app.text
//! ./scripts/fetch_lfs_batches.sh --all
//! # cheap pre-flight: confirm every batch loads at the pinned protocol version
//! cargo run --release -p zksync_cycle_model --bin cycle_bench -- --all-batches --check-only
//! # full measurement, parallel across cores
//! cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
//!     --all-batches --app-bin-dir guest/dist/app --jobs 16 --out artifacts/cycle_model
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use rayon::prelude::*;
use zksync_cli_utils::{load_batch, resolve_batch_inputs, BatchInputFile};
use zksync_cycle_model::{extract_features, run_guest, write_dataset, DatasetRow};
use zksync_types::ProtocolVersionId;

#[derive(Parser)]
#[command(about = "Airbender cycle-cost calibration: emit a (features, cycles) dataset")]
struct Args {
    /// Batch files (e.g. 506077.bin.gz). Mutually exclusive with --all-batches.
    #[arg(long, value_delimiter = ',', conflicts_with = "all_batches")]
    batch_files: Option<Vec<PathBuf>>,
    /// Process every batch in --batches-dir.
    #[arg(long, conflicts_with = "batch_files")]
    all_batches: bool,
    #[arg(long, default_value = "testdata/era_mainnet_batches/binary")]
    batches_dir: PathBuf,
    /// Directory holding the marker-enabled guest (app.bin + app.text).
    /// Required unless --check-only.
    #[arg(long)]
    app_bin_dir: Option<PathBuf>,
    #[arg(long, default_value = "artifacts/cycle_model")]
    out: PathBuf,
    /// Only verify each batch loads + is at the pinned protocol version; no
    /// guest run, no dataset. Fast pre-flight compatibility check.
    #[arg(long)]
    check_only: bool,
    /// Parallel workers for the measurement run. 0 = one per available core.
    /// Each worker holds a full transpiler VM in memory, so lower this if RAM-bound.
    #[arg(long, default_value_t = 0)]
    jobs: usize,
}

/// Full measurement for one batch: native features + guest cycle measurement.
fn process_batch(app_bin_dir: &Path, bf: &BatchInputFile) -> Result<DatasetRow> {
    // v31 is a single canonical `AirbenderVerifierInput` (no version envelope):
    // the same decoded input feeds both the guest run and native feature extraction.
    let input = load_batch(bf).with_context(|| format!("loading batch {}", bf.number))?;

    let features = extract_features(&input)
        .with_context(|| format!("extracting features for batch {}", bf.number))?;
    let guest = run_guest(app_bin_dir, &input)
        .with_context(|| format!("running guest for batch {}", bf.number))?;

    tracing::info!(batch = bf.number, raw_cycles = guest.raw_cycles, "measured");
    Ok(DatasetRow {
        batch_number: bf.number,
        features,
        raw_cycles: guest.raw_cycles,
        phase_cycles: guest.phase_cycles,
        delegations: guest.delegations,
    })
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let batches_dir = args
        .batches_dir
        .canonicalize()
        .with_context(|| format!("resolving batches dir {}", args.batches_dir.display()))?;
    let inputs = resolve_batch_inputs(&batches_dir, args.batch_files.as_deref(), args.all_batches)
        .context("resolving batch inputs")?;

    if args.check_only {
        return run_check(&inputs);
    }

    let app_bin_dir = args
        .app_bin_dir
        .context("--app-bin-dir is required for a measurement run (omit only with --check-only)")?;

    let jobs = if args.jobs == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        args.jobs
    };
    tracing::info!(batches = inputs.len(), jobs, "starting measurement run");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .context("building thread pool")?;

    // par_iter preserves input order in the collected Vec. Each batch is wrapped
    // in catch_unwind: the transpiler `panic!`s (e.g. "illegal instruction") on
    // some inputs, and an uncaught panic in a worker would abort the whole run
    // and lose every measurement. Catching turns it into a per-batch failure.
    let results: Vec<Result<DatasetRow>> = pool.install(|| {
        inputs
            .par_iter()
            .map(|bf| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    process_batch(&app_bin_dir, bf)
                }))
                .unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "transpiler panicked (illegal instruction / unsupported by this guest build)"
                    ))
                })
            })
            .collect()
    });

    let mut rows = Vec::with_capacity(results.len());
    let mut failures = 0usize;
    for (bf, res) in inputs.iter().zip(results) {
        match res {
            Ok(row) => rows.push(row),
            Err(e) => {
                failures += 1;
                tracing::error!(batch = bf.number, "failed: {e:#}");
            }
        }
    }

    write_dataset(&rows, &args.out)?;
    tracing::info!(
        measured = rows.len(),
        failures,
        out = ?args.out,
        "dataset written"
    );
    if failures > 0 {
        anyhow::bail!("{failures} batch(es) failed; see errors above");
    }
    Ok(())
}

/// Pre-flight: report each batch's protocol version and whether it matches the
/// verifier's pinned `latest()`. Non-zero exit if any batch is incompatible.
fn run_check(inputs: &[BatchInputFile]) -> Result<()> {
    let expected = ProtocolVersionId::latest();
    let mut incompatible = 0usize;
    for bf in inputs {
        // v31 has no version envelope: loading the batch is the whole check.
        match load_batch(bf).map(|input| input.system_env.version) {
            Ok(v) if v == expected => tracing::info!(batch = bf.number, version = ?v, "ok"),
            Ok(v) => {
                incompatible += 1;
                tracing::error!(batch = bf.number, version = ?v, expected = ?expected,
                    "INCOMPATIBLE protocol version");
            }
            Err(e) => {
                incompatible += 1;
                tracing::error!(batch = bf.number, "load failed: {e:#}");
            }
        }
    }
    tracing::info!(
        total = inputs.len(),
        incompatible,
        expected = ?expected,
        "compatibility check complete"
    );
    if incompatible > 0 {
        anyhow::bail!("{incompatible} batch(es) incompatible");
    }
    Ok(())
}
