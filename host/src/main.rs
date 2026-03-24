use airbender_host::{
    GpuProver, Program, Prover, ProverLevel, RealVerifier, Runner, VerificationKey,
    VerificationRequest, Verifier,
};
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use statistics::StatisticsCollector;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;
use zksync_cli_utils::{load_batch_words, resolve_batch_inputs};

mod statistics;

const EXPECTED_OUTPUT: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Action {
    Run,
    Prove,
}

#[derive(Debug, Parser)]
#[command(version, about = "Run or prove Era mainnet batches")]
struct Cli {
    #[arg(long, value_delimiter = ',', conflicts_with = "all_batches")]
    batch_files: Option<Vec<PathBuf>>,

    #[arg(long, conflicts_with = "batch_files")]
    all_batches: bool,

    #[arg(long, value_enum)]
    action: Action,

    #[arg(long, default_value = "testdata/era_mainnet_batches/binary")]
    batches_dir: PathBuf,

    #[arg(long)]
    proof_output_dir: Option<PathBuf>,

    #[arg(long)]
    worker_threads: Option<usize>,
}

fn main() -> Result<()> {
    init_tracing().context("while attempting to initialize tracing")?;

    let cli = Cli::parse();
    if cli.all_batches && cli.action != Action::Prove {
        anyhow::bail!("--all-batches requires --action prove");
    }
    if cli.proof_output_dir.is_some() && cli.action != Action::Prove {
        anyhow::bail!("--proof-output-dir requires --action prove");
    }

    let batches_dir = cli.batches_dir.canonicalize().with_context(|| {
        format!(
            "while attempting to canonicalize batches directory path {}",
            cli.batches_dir.display()
        )
    })?;
    let batch_inputs =
        resolve_batch_inputs(&batches_dir, cli.batch_files.as_deref(), cli.all_batches)
            .context("while attempting to resolve requested batches")?;
    let proof_output_dir = prepare_proof_output_dir(cli.proof_output_dir.as_deref())
        .context("while attempting to prepare proof output directory")?;

    info!(
        action = ?cli.action,
        all_batches = cli.all_batches,
        batch_count = batch_inputs.len(),
        "Starting batch processing"
    );

    match cli.action {
        Action::Run => {
            let program =
                Program::load(dist_dir()).context("while attempting to load guest program")?;
            let runner = program
                // .transpiler_runner()
                .simulator_runner()
                .with_cycles(usize::MAX)
                .build()
                .context("while attempting to build transpiler runner")?;

            for batch_input in batch_inputs {
                let input_words = load_batch_words(&batch_input).with_context(|| {
                    format!(
                        "while attempting to load batch {} from {}",
                        batch_input.number,
                        batch_input.path.display()
                    )
                })?;
                run_batch(&runner, batch_input.number, &input_words).with_context(|| {
                    format!(
                        "while attempting to run batch {} from {} in transpiler",
                        batch_input.number,
                        batch_input.path.display()
                    )
                })?;
            }
        }
        Action::Prove => {
            let program =
                Program::load(dist_dir()).context("while attempting to load guest program")?;
            let verifier = program
                .real_verifier(ProverLevel::RecursionUnified)
                .build()
                .context("while attempting to build real verifier")?;

            let cache_path = vk_cache_path(&program)
                .context("while attempting to resolve verification key cache path")?;
            let vk = load_or_generate_vk(&verifier, &cache_path).with_context(|| {
                format!(
                    "while attempting to prepare verification key cache {}",
                    cache_path.display()
                )
            })?;

            let mut prover = program
                .gpu_prover()
                .with_level(ProverLevel::RecursionUnified);

            if let Some(worker_threads) = cli.worker_threads {
                prover = prover.with_worker_threads(worker_threads);
            };

            let prover = prover
                .build()
                .context("while attempting to build GPU prover")?;

            let mut batches_proven = 0;
            let total_batches = batch_inputs.len();
            let mut statistics = StatisticsCollector::default();

            for batch_input in batch_inputs {
                let input_words = load_batch_words(&batch_input).with_context(|| {
                    format!(
                        "while attempting to load batch {} from {}",
                        batch_input.number,
                        batch_input.path.display()
                    )
                })?;
                let proof_output_path = proof_output_dir
                    .as_ref()
                    .map(|dir| dir.join(format!("{}.json", batch_input.number)));
                let proving_stats =
                    prove_batch(
                        &prover,
                        &verifier,
                        &vk,
                        batch_input.number,
                        &input_words,
                        proof_output_path.as_deref(),
                    )
                    .with_context(|| {
                        format!(
                            "while attempting to prove batch {} from {}",
                            batch_input.number,
                            batch_input.path.display()
                        )
                    })?;
                statistics.add_sample(proving_stats.proving_time, proving_stats.cycles);

                info!(
                    batch_number = batch_input.number,
                    batch_file = %batch_input.path.display(),
                    "Successfully proved batch"
                );
                batches_proven += 1;
                info!("Batches proven: {batches_proven}/{total_batches}");
                statistics.print_stats();
            }
        }
    }

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

fn run_batch(
    // runner: &airbender_host::TranspilerRunner,
    runner: &airbender_host::SimulatorRunner,
    batch_number: u64,
    input_words: &[u32],
) -> Result<()> {
    let execution = runner
        .run(input_words)
        .with_context(|| format!("while attempting to execute batch {batch_number}"))?;
    let output = execution.receipt.output[0];

    info!(
        batch_number,
        cycles = execution.cycles_executed,
        reached_end = execution.reached_end,
        output,
        "Finished transpiler run"
    );

    if output != EXPECTED_OUTPUT {
        anyhow::bail!(
            "batch {batch_number} returned unexpected output {output}, expected {EXPECTED_OUTPUT}"
        );
    }

    Ok(())
}

fn prove_batch(
    prover: &GpuProver,
    verifier: &RealVerifier,
    vk: &VerificationKey,
    batch_number: u64,
    input_words: &[u32],
    proof_output_path: Option<&Path>,
) -> Result<ProofBatchStats> {
    let proving_started_at = Instant::now();
    let prove_result = prover
        .prove(input_words)
        .with_context(|| format!("while attempting to generate proof for batch {batch_number}"))?;
    let proving_time = proving_started_at.elapsed();
    let cycles = prove_result.cycles;
    let output = prove_result.receipt.output[0];

    info!(
        batch_number,
        cycles,
        proving_time_secs = proving_time.as_secs_f64(),
        output,
        "Finished proof generation"
    );

    if output != EXPECTED_OUTPUT {
        anyhow::bail!(
            "batch {batch_number} proof output {output} does not match expected {EXPECTED_OUTPUT}"
        );
    }

    verifier
        .verify(
            &prove_result.proof,
            vk,
            VerificationRequest::real(&EXPECTED_OUTPUT),
        )
        .with_context(|| format!("while attempting to verify proof for batch {batch_number}"))?;

    info!(batch_number, "Finished proof verification");

    if let Some(output_path) = proof_output_path {
        write_unrolled_proof_json(&prove_result.proof, output_path).with_context(|| {
            format!(
                "while attempting to export wrapper-compatible proof for batch {batch_number} to {}",
                output_path.display()
            )
        })?;
        info!(
            batch_number,
            path = %output_path.display(),
            "Exported wrapper-compatible proof"
        );
    }

    Ok(ProofBatchStats {
        proving_time,
        cycles,
    })
}

struct ProofBatchStats {
    proving_time: Duration,
    cycles: u64,
}

fn load_or_generate_vk(verifier: &RealVerifier, cache_path: &Path) -> Result<VerificationKey> {
    if cache_path.exists() {
        let bytes = std::fs::read(cache_path)
            .with_context(|| format!("while attempting to read {}", cache_path.display()))?;
        let (vk, decoded_len): (VerificationKey, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).with_context(
                || {
                    format!(
                        "while attempting to decode verification key cache {}",
                        cache_path.display()
                    )
                },
            )?;
        if decoded_len != bytes.len() {
            anyhow::bail!(
                "verification key cache {} has trailing bytes",
                cache_path.display()
            );
        }

        info!(path = %cache_path.display(), "Loaded verification key from cache");
        return Ok(vk);
    }

    let vk = verifier
        .generate_vk()
        .context("while attempting to generate verification key")?;
    let encoded = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .context("while attempting to bincode-encode verification key cache payload")?;
    std::fs::write(cache_path, encoded)
        .with_context(|| format!("while attempting to write {}", cache_path.display()))?;

    info!(path = %cache_path.display(), "Generated and cached verification key");
    Ok(vk)
}

fn vk_cache_path(program: &Program) -> Result<PathBuf> {
    let manifest_sha256 = program.manifest().bin.sha256.trim();
    if manifest_sha256.is_empty() {
        anyhow::bail!(
            "guest manifest has empty bin_sha256, cannot derive verification key cache path"
        );
    }

    Ok(PathBuf::from(format!("vk-{manifest_sha256}.bin")))
}

fn dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}

// ==============================================================================
// Proof Export
// ==============================================================================

// The wrapper expects the raw `UnrolledProgramProof` JSON payload, while `airbender_host`
// deliberately keeps that payload inside its `Proof::Real` wrapper. We currently recover the
// inner JSON by round-tripping through serde so we can stay compatible without forking
// `airbender_host`.
fn write_unrolled_proof_json(proof: &airbender_host::Proof, output_path: &Path) -> Result<()> {
    let outer_proof_path = outer_proof_temp_path(output_path);
    let outer_proof_file = File::create(&outer_proof_path).with_context(|| {
        format!(
            "while attempting to create temporary outer proof file {}",
            outer_proof_path.display()
        )
    })?;
    serde_json::to_writer_pretty(BufWriter::new(outer_proof_file), proof).with_context(|| {
        format!(
            "while attempting to serialize host proof wrapper into {}",
            outer_proof_path.display()
        )
    })?;

    let outer_proof_file = File::open(&outer_proof_path).with_context(|| {
        format!(
            "while attempting to reopen temporary outer proof file {}",
            outer_proof_path.display()
        )
    })?;
    let extracted: SerializedHostProof =
        serde_json::from_reader(BufReader::new(outer_proof_file)).with_context(|| {
            format!(
                "while attempting to deserialize host proof wrapper from {}",
                outer_proof_path.display()
            )
        })?;

    std::fs::remove_file(&outer_proof_path).with_context(|| {
        format!(
            "while attempting to remove temporary outer proof file {}",
            outer_proof_path.display()
        )
    })?;

    let SerializedHostProof::Real(real_proof) = extracted else {
        anyhow::bail!("wrapper export expects a real proof, but received a dev proof");
    };

    let output_file = File::create(output_path)
        .with_context(|| format!("while attempting to create {}", output_path.display()))?;
    serde_json::to_writer_pretty(BufWriter::new(output_file), &real_proof.inner).with_context(
        || format!("while attempting to write {}", output_path.display()),
    )?;

    Ok(())
}

fn prepare_proof_output_dir(path: Option<&Path>) -> Result<Option<PathBuf>> {
    let Some(path) = path else {
        return Ok(None);
    };

    std::fs::create_dir_all(path)
        .with_context(|| format!("while attempting to create {}", path.display()))?;
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("while attempting to canonicalize {}", path.display()))?;

    Ok(Some(canonical_path))
}

fn outer_proof_temp_path(output_path: &Path) -> PathBuf {
    let file_name = output_path
        .file_name()
        .expect("proof output path must include a file name")
        .to_string_lossy();
    output_path.with_file_name(format!(".{file_name}.host-proof.tmp"))
}

#[derive(Debug, Deserialize)]
enum SerializedHostProof {
    Dev(()),
    Real(SerializedRealProof),
}

#[derive(Debug, Deserialize)]
struct SerializedRealProof {
    // Intentionally omitted: the wrapper export only needs the inner final proof payload.
    #[allow(dead_code)]
    level: Value,
    inner: Value,
}
