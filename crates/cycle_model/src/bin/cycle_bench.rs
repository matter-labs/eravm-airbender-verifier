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
//! cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
//!     --all-batches --app-bin-dir guest/dist/app --out artifacts/cycle_model
//! ```

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use zksync_cli_utils::{load_batch, resolve_batch_inputs};
use zksync_cycle_model::{extract_features, run_guest, write_dataset, DatasetRow};

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
    #[arg(long)]
    app_bin_dir: PathBuf,
    #[arg(long, default_value = "artifacts/cycle_model")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let batches_dir = args
        .batches_dir
        .canonicalize()
        .with_context(|| format!("resolving batches dir {}", args.batches_dir.display()))?;
    let inputs = resolve_batch_inputs(&batches_dir, args.batch_files.as_deref(), args.all_batches)
        .context("resolving batch inputs")?;

    let mut rows = Vec::with_capacity(inputs.len());
    for bf in &inputs {
        tracing::info!(batch = bf.number, "processing");

        // The guest decodes the versioned envelope (as host does); the native
        // feature run needs the unwrapped V1 payload.
        let envelope = load_batch(bf).with_context(|| format!("loading batch {}", bf.number))?;
        let v1 = envelope
            .clone()
            .into_v1()
            .with_context(|| format!("batch {} is not a V1 verifier input", bf.number))?;

        let features = extract_features(&v1)
            .with_context(|| format!("extracting features for batch {}", bf.number))?;
        let guest = run_guest(&args.app_bin_dir, &envelope)
            .with_context(|| format!("running guest for batch {}", bf.number))?;

        tracing::info!(batch = bf.number, raw_cycles = guest.raw_cycles, "measured");
        rows.push(DatasetRow {
            batch_number: bf.number,
            features,
            raw_cycles: guest.raw_cycles,
            phase_cycles: guest.phase_cycles,
            delegations: guest.delegations,
        });
    }

    write_dataset(&rows, &args.out)?;
    tracing::info!(count = rows.len(), out = ?args.out, "dataset written");
    Ok(())
}
