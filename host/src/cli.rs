use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use std::path::{Path, PathBuf};

use crate::batches::list_all_batch_numbers;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Action {
    Run,
    Prove,
}

#[derive(Debug, Parser)]
#[command(version, about = "Run or prove Era mainnet batches")]
pub struct Cli {
    #[arg(long, conflicts_with = "all_batches")]
    batch_number: Option<u64>,

    #[arg(long, conflicts_with = "batch_number")]
    all_batches: bool,

    #[arg(long, value_enum)]
    action: Action,

    #[arg(long)]
    batches_dir: String,

    #[arg(long)]
    worker_threads: Option<usize>,
}

#[derive(Debug)]
pub struct Request {
    pub action: Action,
    pub all_batches: bool,
    pub batches_dir: PathBuf,
    pub batch_numbers: Vec<u64>,
    pub worker_threads: Option<usize>,
}

impl Cli {
    pub fn into_request(self) -> Result<Request> {
        if self.all_batches && self.action != Action::Prove {
            bail!("--all-batches requires --action prove");
        }

        let batches_dir = canonicalize_batches_dir(&self.batches_dir)
            .context("while attempting to locate batches directory")?;
        let batch_numbers =
            resolve_batch_numbers(self.batch_number, self.all_batches, &batches_dir)
                .context("while attempting to resolve requested batches")?;

        Ok(Request {
            action: self.action,
            all_batches: self.all_batches,
            batches_dir,
            batch_numbers,
            worker_threads: self.worker_threads,
        })
    }
}

fn canonicalize_batches_dir(raw_path: &str) -> Result<PathBuf> {
    PathBuf::from(raw_path).canonicalize().with_context(|| {
        format!("while attempting to canonicalize batches directory path {raw_path}")
    })
}

fn resolve_batch_numbers(
    batch_number: Option<u64>,
    all_batches: bool,
    batches_dir: &Path,
) -> Result<Vec<u64>> {
    if all_batches {
        return list_all_batch_numbers(batches_dir)
            .context("while attempting to enumerate all batch files");
    }

    let batch_number = batch_number.context(
        "while attempting to select input batch, pass either --batch-number <number> or --all-batches",
    )?;

    Ok(vec![batch_number])
}
