use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use eravm_prover_host::{prove_batches_fri, run_batches, wrap_to_snark, SnarkOptions};
use std::path::PathBuf;
use zksync_cli_utils::{resolve_batch_inputs, BatchInputFile};

#[derive(Debug, Parser)]
#[command(version, about = "Run, prove, and wrap Era mainnet batches")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(RunArgs),
    ProveFri(ProveFriArgs),
    ProveSnark(ProveSnarkArgs),
}

#[derive(Debug, Args)]
struct BatchSelectionArgs {
    #[arg(long, value_delimiter = ',', conflicts_with = "all_batches")]
    batch_files: Option<Vec<PathBuf>>,

    #[arg(long, conflicts_with = "batch_files")]
    all_batches: bool,

    #[arg(long, default_value = "testdata/era_mainnet_batches/binary")]
    batches_dir: PathBuf,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    batch_selection: BatchSelectionArgs,

    #[arg(long)]
    jit: bool,
}

#[derive(Debug, Args)]
struct ProveFriArgs {
    #[command(flatten)]
    batch_selection: BatchSelectionArgs,

    #[arg(long)]
    output_dir: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,
}

#[derive(Debug, Args)]
struct ProveSnarkArgs {
    #[arg(long, value_delimiter = ',')]
    proof_files: Vec<PathBuf>,

    #[arg(long)]
    output_dir: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,

    #[arg(long)]
    trusted_setup: Option<PathBuf>,

    #[arg(long)]
    use_zk: bool,

    #[arg(long)]
    save_intermediates: bool,
}

impl BatchSelectionArgs {
    fn resolve(&self) -> Result<Vec<BatchInputFile>> {
        let batches_dir = self.batches_dir.canonicalize().with_context(|| {
            format!(
                "while attempting to canonicalize batches directory path {}",
                self.batches_dir.display()
            )
        })?;
        resolve_batch_inputs(&batches_dir, self.batch_files.as_deref(), self.all_batches)
            .context("while attempting to resolve requested batches")
    }
}

fn main() -> Result<()> {
    init_tracing().context("while attempting to initialize tracing")?;

    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => {
            let batch_inputs = args.batch_selection.resolve()?;
            run_batches(&batch_inputs, args.jit)
        }
        Command::ProveFri(args) => {
            let batch_inputs = args.batch_selection.resolve()?;
            prove_batches_fri(&batch_inputs, args.worker_threads, &args.output_dir)
        }
        Command::ProveSnark(args) => {
            let snark_options = SnarkOptions {
                worker_threads: args.worker_threads,
                trusted_setup: args.trusted_setup,
                use_zk: args.use_zk,
                save_intermediates: args.save_intermediates,
            };
            wrap_to_snark(&args.proof_files, &args.output_dir, &snark_options)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn prove_snark_parses_save_intermediates_flag() {
        let cli = Cli::try_parse_from([
            "eravm-prover-host",
            "prove-snark",
            "--proof-files",
            "./artifacts/proofs/batch-42/fri_proof.json",
            "--output-dir",
            "./artifacts/proofs",
            "--save-intermediates",
        ])
        .expect("prove-snark arguments should parse");

        match cli.command {
            Command::ProveSnark(args) => {
                assert!(args.save_intermediates);
                assert_eq!(
                    args.proof_files,
                    vec![PathBuf::from("./artifacts/proofs/batch-42/fri_proof.json")]
                );
                assert_eq!(args.output_dir, PathBuf::from("./artifacts/proofs"));
            }
            _ => panic!("expected prove-snark command"),
        }
    }
}
