use airbender_host::SecurityLevel;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use eravm_prover_host::{
    default_fri_vk_path, default_trusted_setup_download_url, default_trusted_setup_path,
    deserialize_from_file, download_trusted_setup_if_not_present, generate_fri_vk,
    generate_snark_vk, prove_batches_fri, run_batches, wrap_compression_to_snark,
    wrap_to_compression, wrap_to_snark, SnarkOptions, SnarkWrapperVK,
};
use std::path::PathBuf;
use zksync_cli_utils::{resolve_batch_inputs, BatchInputFile};

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityLevelArg {
    #[value(name = "80")]
    Bits80,
    #[value(name = "100")]
    Bits100,
}

impl From<SecurityLevelArg> for SecurityLevel {
    fn from(security: SecurityLevelArg) -> Self {
        match security {
            SecurityLevelArg::Bits80 => Self::Bits80,
            SecurityLevelArg::Bits100 => Self::Bits100,
        }
    }
}

impl From<SecurityLevel> for SecurityLevelArg {
    fn from(security: SecurityLevel) -> Self {
        match security {
            SecurityLevel::Bits80 => Self::Bits80,
            SecurityLevel::Bits100 => Self::Bits100,
        }
    }
}

impl Default for SecurityLevelArg {
    fn default() -> Self {
        SecurityLevel::default().into()
    }
}

impl std::fmt::Display for SecurityLevelArg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", SecurityLevel::from(*self))
    }
}

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
    /// Run wrapper phases 1+2 (risc wrapper + compression) only and save the
    /// resulting compression proof + VK to disk. Pair this with
    /// `prove-snark-from-compression` in a separate process to start phase 3
    /// on a GPU that no longer holds phase 1/2 buffers.
    ProveCompression(ProveCompressionArgs),
    /// Run wrapper phase 3 only against a pre-computed compression proof. The
    /// compression VK and SNARK VK must already be on disk. This is the
    /// second half of the split-process SNARK pipeline.
    ProveSnarkFromCompression(ProveSnarkFromCompressionArgs),
    /// Download the bellman SNARK trusted setup (CRS) so it is on disk before
    /// running `prove-snark`. Skips the download if the file already exists.
    DownloadTrustedSetup(DownloadTrustedSetupArgs),
    /// Generate the FRI and SNARK verification keys into a directory. The
    /// server only loads VKs from disk, so this is how committed VK files in
    /// `vks/` get refreshed when the guest binary or wrapper recursion
    /// changes. CI re-runs this and `git diff --exit-code`s the output.
    #[command(name = "gen-vks")]
    GenerateVks(GenerateVksArgs),
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

    #[arg(long, default_value_t = SecurityLevelArg::default())]
    security: SecurityLevelArg,

    /// Path to the committed FRI verification key. Reused if present;
    /// otherwise generated on the fly and written here.
    #[arg(long, default_value_os_t = default_fri_vk_path())]
    fri_vk: PathBuf,
}

#[derive(Debug, Args)]
struct GenerateVksArgs {
    /// Where to write the verification key files. Both `fri_vk.bin` and
    /// `snark_vk.json` are written under this directory.
    #[arg(long, default_value = "vks")]
    output_dir: PathBuf,

    #[arg(long, default_value_t = SecurityLevelArg::default())]
    security: SecurityLevelArg,

    /// SNARK trusted setup (CRS). Required to derive the SNARK wrapper VK.
    #[arg(long, env = "SNARK_TRUSTED_SETUP_FILE")]
    trusted_setup: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,
}

#[derive(Debug, Args)]
struct DownloadTrustedSetupArgs {
    /// Where to write the trusted setup file.
    #[arg(
        long,
        env = "SNARK_TRUSTED_SETUP_FILE",
        default_value_os_t = default_trusted_setup_path(),
    )]
    output: PathBuf,

    /// URL to download from. Defaults to the GCS bucket that matches the
    /// build's SNARK feature set (CPU vs `snark_gpu`).
    #[arg(long, default_value_t = default_trusted_setup_download_url().to_string())]
    url: String,
}

#[derive(Debug, Args)]
struct ProveSnarkArgs {
    #[arg(long, value_delimiter = ',')]
    proof_files: Vec<PathBuf>,

    #[arg(long)]
    output_dir: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,

    #[arg(long, env = "SNARK_TRUSTED_SETUP_FILE")]
    trusted_setup: Option<PathBuf>,

    /// Optional path to a pre-generated SNARK VK JSON. When set, the VK is
    /// loaded once at startup and reused for every wrap; otherwise it is
    /// derived from the setup chain.
    #[arg(long)]
    snark_vk: Option<PathBuf>,

    #[arg(long)]
    use_zk: bool,

    #[arg(long)]
    save_intermediates: bool,
}

#[derive(Debug, Args)]
struct ProveCompressionArgs {
    /// One or more raw FRI proof files (the JSON format written by
    /// `prove-fri`). Each input is run through phases 1+2 and produces a
    /// `compression_proof.json` + `compression_vk.json` pair in its own
    /// per-batch output directory.
    #[arg(long, value_delimiter = ',')]
    proof_files: Vec<PathBuf>,

    #[arg(long)]
    output_dir: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,

    /// Phase 1+2 do not strictly need the SNARK trusted setup, but the wrapper
    /// is constructed via the same config used for full SNARK runs, so a CRS
    /// path is accepted (and ignored) to keep the CLI symmetric with
    /// `prove-snark`.
    #[arg(long, env = "SNARK_TRUSTED_SETUP_FILE")]
    trusted_setup: Option<PathBuf>,

    /// Also write `risc_wrapper_proof.json` + `risc_wrapper_vk.json` alongside
    /// the compression artifacts. Off by default — only the compression
    /// outputs are needed to feed `prove-snark-from-compression`.
    #[arg(long)]
    save_intermediates: bool,
}

#[derive(Debug, Args)]
struct ProveSnarkFromCompressionArgs {
    /// Path to `compression_proof.json` produced by `prove-compression`.
    #[arg(long)]
    compression_proof: PathBuf,

    /// Path to `compression_vk.json` produced by `prove-compression`. The VK
    /// is deterministic given the recursion verifier, but we read it from
    /// disk rather than re-deriving it so this process never touches phase
    /// 1/2 GPU setup.
    #[arg(long)]
    compression_vk: PathBuf,

    #[arg(long)]
    output_dir: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,

    #[arg(long, env = "SNARK_TRUSTED_SETUP_FILE")]
    trusted_setup: Option<PathBuf>,

    /// Pre-generated SNARK VK JSON. Required: this process must skip the
    /// `wrapper.snark_vk()` derivation step, otherwise the wrapper rebuilds
    /// phase 1/2 GPU setup to derive the VK — which defeats the whole point
    /// of running phase 3 in a fresh process.
    #[arg(long)]
    snark_vk: PathBuf,

    #[arg(long)]
    use_zk: bool,
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
            prove_batches_fri(
                &batch_inputs,
                args.worker_threads,
                &args.output_dir,
                &args.fri_vk,
                args.security.into(),
            )
        }
        Command::DownloadTrustedSetup(args) => {
            download_trusted_setup_if_not_present(&args.output, &args.url)
                .context("while attempting to download the SNARK trusted setup")
        }
        Command::ProveSnark(args) => {
            let snark_options = SnarkOptions {
                worker_threads: args.worker_threads,
                trusted_setup: args.trusted_setup,
                use_zk: args.use_zk,
                save_intermediates: args.save_intermediates,
            };
            let snark_vk = load_snark_vk(args.snark_vk.as_deref())?;
            wrap_to_snark(
                &args.proof_files,
                &args.output_dir,
                &snark_options,
                snark_vk,
            )
        }
        Command::ProveCompression(args) => {
            let snark_options = SnarkOptions {
                worker_threads: args.worker_threads,
                trusted_setup: args.trusted_setup,
                use_zk: false,
                save_intermediates: args.save_intermediates,
            };
            wrap_to_compression(&args.proof_files, &args.output_dir, &snark_options)
        }
        Command::ProveSnarkFromCompression(args) => {
            let snark_options = SnarkOptions {
                worker_threads: args.worker_threads,
                trusted_setup: args.trusted_setup,
                use_zk: args.use_zk,
                save_intermediates: false,
            };
            let snark_vk = load_snark_vk(Some(&args.snark_vk))?
                .context("--snark-vk is required for prove-snark-from-compression")?;
            wrap_compression_to_snark(
                &args.compression_proof,
                &args.compression_vk,
                &args.output_dir,
                &snark_options,
                snark_vk,
            )
        }
        Command::GenerateVks(args) => {
            std::fs::create_dir_all(&args.output_dir).with_context(|| {
                format!(
                    "while attempting to create VK output directory {}",
                    args.output_dir.display()
                )
            })?;

            let fri_vk_path = args.output_dir.join("fri_vk.bin");
            generate_fri_vk(&fri_vk_path, args.security.into())
                .context("while generating the FRI verification key")?;

            let snark_vk_path = args.output_dir.join("snark_vk.json");
            let snark_options = SnarkOptions {
                worker_threads: args.worker_threads,
                trusted_setup: Some(args.trusted_setup),
                use_zk: false,
                save_intermediates: false,
            };
            generate_snark_vk(&snark_vk_path, &snark_options)
                .context("while generating the SNARK verification key")?;
            Ok(())
        }
    }
}

fn load_snark_vk(path: Option<&std::path::Path>) -> Result<Option<SnarkWrapperVK>> {
    let Some(path) = path else { return Ok(None) };
    let path_string = path.to_string_lossy().into_owned();
    let vk: SnarkWrapperVK = deserialize_from_file(&path_string)
        .with_context(|| format!("while loading SNARK VK from {}", path.display()))?;
    Ok(Some(vk))
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

    #[test]
    fn prove_compression_parses_minimal_args() {
        let cli = Cli::try_parse_from([
            "eravm-prover-host",
            "prove-compression",
            "--proof-files",
            "./artifacts/proofs/batch-42/fri_proof.json",
            "--output-dir",
            "./artifacts/compression",
        ])
        .expect("prove-compression arguments should parse");

        match cli.command {
            Command::ProveCompression(args) => {
                assert_eq!(
                    args.proof_files,
                    vec![PathBuf::from("./artifacts/proofs/batch-42/fri_proof.json")]
                );
                assert_eq!(args.output_dir, PathBuf::from("./artifacts/compression"));
                assert!(!args.save_intermediates);
            }
            _ => panic!("expected prove-compression command"),
        }
    }

    #[test]
    fn prove_snark_from_compression_requires_compression_and_snark_vks() {
        let cli = Cli::try_parse_from([
            "eravm-prover-host",
            "prove-snark-from-compression",
            "--compression-proof",
            "./artifacts/compression/batch-42/compression_proof.json",
            "--compression-vk",
            "./artifacts/compression/batch-42/compression_vk.json",
            "--output-dir",
            "./artifacts/snark",
            "--snark-vk",
            "./vks/snark_vk.json",
        ])
        .expect("prove-snark-from-compression arguments should parse");

        match cli.command {
            Command::ProveSnarkFromCompression(args) => {
                assert_eq!(
                    args.compression_proof,
                    PathBuf::from("./artifacts/compression/batch-42/compression_proof.json")
                );
                assert_eq!(
                    args.compression_vk,
                    PathBuf::from("./artifacts/compression/batch-42/compression_vk.json")
                );
                assert_eq!(args.snark_vk, PathBuf::from("./vks/snark_vk.json"));
                assert_eq!(args.output_dir, PathBuf::from("./artifacts/snark"));
                assert!(!args.use_zk);
            }
            _ => panic!("expected prove-snark-from-compression command"),
        }

        // Omitting --snark-vk must fail; the whole point of this subcommand is
        // to skip phase-1/2 GPU setup, which requires a pre-derived SNARK VK.
        Cli::try_parse_from([
            "eravm-prover-host",
            "prove-snark-from-compression",
            "--compression-proof",
            "./compression_proof.json",
            "--compression-vk",
            "./compression_vk.json",
            "--output-dir",
            "./snark",
        ])
        .expect_err("prove-snark-from-compression must require --snark-vk");
    }
}
