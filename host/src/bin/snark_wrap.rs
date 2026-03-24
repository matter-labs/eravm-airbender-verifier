use anyhow::{Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Bridge a final Airbender proof into the sibling zkos-wrapper SNARK pipeline"
)]
struct Cli {
    /// Path to the final Airbender proof JSON (`UnrolledProgramProof`).
    #[arg(long)]
    proof: PathBuf,

    /// Directory where the wrapper should write SNARK outputs.
    #[arg(short, long)]
    output_dir: PathBuf,

    /// Path to the trusted setup file used by the wrapper SNARK phase.
    #[arg(long)]
    trusted_setup: Option<PathBuf>,

    /// Path to a custom RISC-V binary for wrapper phase 1.
    /// If omitted, this bridge uses the local verifier guest binary.
    #[arg(long, requires = "text")]
    bin: Option<PathBuf>,

    /// Path to the custom RISC-V text section for wrapper phase 1.
    /// If omitted, this bridge uses the local verifier guest text section.
    #[arg(long, requires = "bin")]
    text: Option<PathBuf>,

    /// Number of worker threads passed through to the wrapper CLI.
    #[arg(long)]
    threads: Option<usize>,

    /// Enable zero-knowledge padding during the SNARK phase.
    #[arg(long)]
    use_zk: bool,

    /// Ask the wrapper CLI to preserve its intermediate proofs.
    #[arg(long)]
    save_intermediates: bool,

    /// Override the sibling wrapper manifest path if your checkout layout is different.
    #[arg(long, default_value_os_t = default_wrapper_manifest_path())]
    wrapper_manifest: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let proof_path =
        canonicalize_input_path(&cli.proof).with_context(|| {
            format!(
                "while attempting to resolve proof path {}",
                cli.proof.display()
            )
        })?;
    let wrapper_manifest = canonicalize_input_path(&cli.wrapper_manifest).with_context(|| {
        format!(
            "while attempting to resolve wrapper manifest path {}",
            cli.wrapper_manifest.display()
        )
    })?;
    let trusted_setup = cli
        .trusted_setup
        .as_ref()
        .map(|path| canonicalize_input_path(path))
        .transpose()
        .context("while attempting to resolve trusted setup path")?;
    let (bin, text) = resolve_guest_program_paths(cli.bin.as_deref(), cli.text.as_deref())
        .context("while attempting to resolve wrapper program commitment inputs")?;
    let output_dir = prepare_output_dir(&cli.output_dir)
        .with_context(|| format!("while attempting to prepare {}", cli.output_dir.display()))?;

    let mut command = build_wrapper_command(
        &wrapper_manifest,
        &proof_path,
        &output_dir,
        trusted_setup.as_deref(),
        Some(bin.as_ref()),
        Some(text.as_ref()),
        cli.threads,
        cli.use_zk,
        cli.save_intermediates,
    );

    let status = command.status().context(
        "while attempting to launch the sibling zkos-wrapper `prove-all` pipeline",
    )?;
    if !status.success() {
        anyhow::bail!("zkos-wrapper exited unsuccessfully with status {status}");
    }

    Ok(())
}

// ==============================================================================
// Wrapper Bridge
// ==============================================================================

// We intentionally delegate to the sibling `zkos-wrapper` CLI for now instead of linking its
// full dependency graph into this package. The current host API does not expose the final
// `UnrolledProgramProof` directly, and the wrapper still carries its own proving stack.
// TODO: Replace this bridge with an in-process integration once the proof payload is public and
// the dependency graphs are aligned.
#[allow(clippy::too_many_arguments)]
fn build_wrapper_command(
    wrapper_manifest: &Path,
    proof_path: &Path,
    output_dir: &Path,
    trusted_setup: Option<&Path>,
    bin: Option<&Path>,
    text: Option<&Path>,
    threads: Option<usize>,
    use_zk: bool,
    save_intermediates: bool,
) -> Command {
    let mut command = Command::new("cargo");
    command
        .arg("+nightly")
        .arg("run")
        .arg("--manifest-path")
        .arg(wrapper_manifest)
        .arg("--release")
        .arg("--bin")
        .arg("wrapper")
        .arg("--");

    if let Some(threads) = threads {
        command.arg("--threads").arg(threads.to_string());
    }

    command
        .arg("prove-all")
        .arg("--proof")
        .arg(proof_path)
        .arg("--output-dir")
        .arg(output_dir);

    if let Some(trusted_setup) = trusted_setup {
        command.arg("--trusted-setup").arg(trusted_setup);
    }
    if let Some(bin) = bin {
        command.arg("--bin").arg(bin);
    }
    if let Some(text) = text {
        command.arg("--text").arg(text);
    }
    if use_zk {
        command.arg("--use-zk");
    }
    if save_intermediates {
        command.arg("--save-intermediates");
    }

    if std::env::var_os("RUST_MIN_STACK").is_none() {
        command.env("RUST_MIN_STACK", "67108864");
    }

    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    command
}

fn prepare_output_dir(path: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("while attempting to create {}", path.display()))?;
    path.canonicalize()
        .with_context(|| format!("while attempting to canonicalize {}", path.display()))
}

fn canonicalize_input_path(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("while attempting to canonicalize {}", path.display()))
}

fn default_wrapper_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../zkos-wrapper/Cargo.toml")
}

fn default_guest_bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guest/dist/app/app.bin")
}

fn default_guest_text_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guest/dist/app/app.text")
}

fn resolve_guest_program_paths(
    bin: Option<&Path>,
    text: Option<&Path>,
) -> Result<(PathBuf, PathBuf)> {
    match (bin, text) {
        (Some(bin), Some(text)) => Ok((
            canonicalize_input_path(bin)
                .with_context(|| format!("while attempting to resolve custom binary path {}", bin.display()))?,
            canonicalize_input_path(text)
                .with_context(|| format!("while attempting to resolve custom text path {}", text.display()))?,
        )),
        (None, None) => Ok((
            canonicalize_input_path(&default_guest_bin_path()).context(
                "while attempting to resolve default verifier guest binary path",
            )?,
            canonicalize_input_path(&default_guest_text_path()).context(
                "while attempting to resolve default verifier guest text path",
            )?,
        )),
        _ => anyhow::bail!("`--bin` and `--text` must be provided together"),
    }
}
