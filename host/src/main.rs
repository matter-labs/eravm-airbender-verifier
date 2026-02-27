use airbender_host::Program;
use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use crate::cli::{Action, Cli};

mod batches;
mod cli;
mod commands;
mod statistics;

fn main() -> Result<()> {
    init_tracing().context("while attempting to initialize tracing")?;

    let request = Cli::parse()
        .into_request()
        .context("while attempting to parse CLI request")?;
    let program = Program::load(dist_dir()).context("while attempting to load guest program")?;

    info!(
        action = ?request.action,
        all_batches = request.all_batches,
        batch_count = request.batch_numbers.len(),
        "Starting batch processing"
    );

    match request.action {
        Action::Run => {
            commands::run::run_batches(&program, &request.batches_dir, &request.batch_numbers)
        }
        Action::Prove => commands::prove::prove_batches(
            &program,
            &request.batches_dir,
            &request.batch_numbers,
            request.worker_threads,
        ),
    }?;

    Ok(())
}

fn init_tracing() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|err| {
            anyhow::anyhow!("while attempting to initialize tracing subscriber: {err}")
        })?;

    Ok(())
}

fn dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}
