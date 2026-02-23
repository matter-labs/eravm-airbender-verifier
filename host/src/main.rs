use airbender_host::{
    GpuProver, Program, Prover, ProverLevel, RealVerifier, Runner, VerificationKey,
    VerificationRequest, Verifier,
};
use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use statistics::StatisticsCollector;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{info, warn};

mod statistics;

// use zksync_tee_verifier::types::TeeVerifierInput;

const BATCHES_DIR_RELATIVE: &str = "../../storage/era_mainnet_batches/binary";
const EXPECTED_OUTPUT: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Action {
    Run,
    Prove,
}

#[derive(Debug, Parser)]
#[command(version, about = "Run or prove Era mainnet batches")]
struct Cli {
    #[arg(long, conflicts_with = "all_batches")]
    batch_number: Option<u64>,

    #[arg(long, conflicts_with = "batch_number")]
    all_batches: bool,

    #[arg(long, value_enum)]
    action: Action,

    #[arg(long, default_value = "../../storage/era_mainnet_batches/binary")]
    batches_dir: String,

    #[arg(long)]
    worker_threads: Option<usize>,
}

fn main() -> Result<()> {
    init_tracing().context("while attempting to initialize tracing")?;

    let cli = Cli::parse();
    if cli.all_batches && cli.action != Action::Prove {
        bail!("--all-batches requires --action prove");
    }

    let program = Program::load(dist_dir()).context("while attempting to load guest program")?;
    // let batches_dir = batches_dir().context("while attempting to locate batches directory")?;
    let batches_dir = PathBuf::from(cli.batches_dir.clone())
        .canonicalize()
        .with_context(|| {
            format!(
                "while attempting to canonicalize batches directory path {}",
                cli.batches_dir
            )
        })?;
    let batch_numbers = resolve_batch_numbers(&cli, &batches_dir)
        .context("while attempting to resolve requested batches")?;

    info!(
        action = ?cli.action,
        all_batches = cli.all_batches,
        batch_count = batch_numbers.len(),
        "Starting batch processing"
    );

    match cli.action {
        Action::Run => {
            let runner = program
                // .transpiler_runner()
                .simulator_runner()
                .with_cycles(usize::MAX)
                .build()
                .context("while attempting to build transpiler runner")?;

            for batch_number in batch_numbers {
                let input_words = load_and_decode_batch(&batches_dir, batch_number)
                    .with_context(|| format!("while attempting to load batch {batch_number}"))?;
                run_batch(&runner, batch_number, &input_words).with_context(|| {
                    format!("while attempting to run batch {batch_number} in transpiler")
                })?;
            }
        }
        Action::Prove => {
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
            let total_batches = batch_numbers.len();
            let mut statistics = StatisticsCollector::default();

            for batch_number in batch_numbers {
                let input_words = load_and_decode_batch(&batches_dir, batch_number)
                    .with_context(|| format!("while attempting to load batch {batch_number}"))?;
                let proving_stats =
                    prove_batch(&prover, &verifier, &vk, batch_number, &input_words).with_context(
                        || format!("while attempting to prove batch {batch_number}"),
                    )?;
                statistics.add_sample(proving_stats.proving_time, proving_stats.cycles);

                info!(batch_number, "Successfully proved batch");
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

fn resolve_batch_numbers(cli: &Cli, batches_dir: &Path) -> Result<Vec<u64>> {
    if cli.all_batches {
        return list_all_batch_numbers(batches_dir)
            .context("while attempting to enumerate all batch files");
    }

    let batch_number = cli.batch_number.context(
        "while attempting to select input batch, pass either --batch-number <number> or --all-batches",
    )?;
    Ok(vec![batch_number])
}

fn list_all_batch_numbers(batches_dir: &Path) -> Result<Vec<u64>> {
    let entries = std::fs::read_dir(batches_dir)
        .with_context(|| format!("while attempting to read {}", batches_dir.display()))?;

    let mut batch_numbers = Vec::new();
    for entry in entries {
        let entry = entry.context("while attempting to read directory entry")?;
        let path = entry.path();

        let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if extension != "bin" {
            continue;
        }

        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            warn!(path = %path.display(), "Skipping non-UTF8 batch file name");
            continue;
        };

        match stem.parse::<u64>() {
            Ok(number) => batch_numbers.push(number),
            Err(_) => warn!(path = %path.display(), "Skipping .bin file with non-numeric name"),
        }
    }

    if batch_numbers.is_empty() {
        bail!("no batch files were found in {}", batches_dir.display());
    }

    batch_numbers.sort_unstable();
    Ok(batch_numbers)
}

fn load_and_decode_batch(batches_dir: &Path, batch_number: u64) -> Result<Vec<u32>> {
    let framed_words = load_batch_words(batches_dir, batch_number)
        .with_context(|| format!("while attempting to parse words for batch {batch_number}"))?;
    // let payload = frame_words_to_bytes(&framed_words).with_context(|| {
    //     format!("while attempting to decode framed payload for batch {batch_number}")
    // })?;

    // let (input, decoded_len): (TeeVerifierInput, usize) =
    //     bincode::serde::decode_from_slice(&payload, bincode::config::standard())
    //         .with_context(|| format!("while attempting to bincode-decode batch {batch_number}"))?;
    // if decoded_len != payload.len() {
    //     bail!(
    //         "batch {batch_number} bincode payload has trailing bytes (decoded {decoded_len} of {})",
    //         payload.len()
    //     );
    // }

    // let input_version = match input {
    //     TeeVerifierInput::V1(_) => "v1",
    //     TeeVerifierInput::V0 => "v0",
    //     _ => "unknown",
    // };
    // info!(
    //     batch_number,
    //     input_version,
    //     framed_words = framed_words.len(),
    //     payload_bytes = payload.len(),
    //     "Loaded and decoded batch input"
    // );

    Ok(framed_words)
}

fn load_batch_words(batches_dir: &Path, batch_number: u64) -> Result<Vec<u32>> {
    let batch_path = batch_file_path(batches_dir, batch_number);
    let raw = std::fs::read_to_string(&batch_path)
        .with_context(|| format!("while attempting to read {}", batch_path.display()))?;
    parse_hex_words(&raw).with_context(|| {
        format!(
            "while attempting to parse hex words in {}",
            batch_path.display()
        )
    })
}

fn parse_hex_words(raw: &str) -> Result<Vec<u32>> {
    let mut compact: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
    if let Some(stripped) = compact.strip_prefix("0x") {
        compact = stripped.to_string();
    }

    if compact.is_empty() {
        bail!("batch payload is empty");
    }

    if !compact.len().is_multiple_of(8) {
        bail!(
            "batch payload length must be a multiple of 8 hex characters (got {})",
            compact.len()
        );
    }

    let mut words = Vec::with_capacity(compact.len() / 8);
    for chunk in compact.as_bytes().chunks(8) {
        let chunk_str =
            std::str::from_utf8(chunk).context("while attempting to decode hex chunk as UTF-8")?;
        let word = u32::from_str_radix(chunk_str, 16)
            .with_context(|| format!("while attempting to parse hex word `{chunk_str}`"))?;
        words.push(word);
    }

    Ok(words)
}

fn frame_words_to_bytes(words: &[u32]) -> Result<Vec<u8>> {
    let (&byte_len_word, payload_words) = words
        .split_first()
        .context("while attempting to decode framed payload, frame has no length word")?;
    let byte_len = byte_len_word as usize;
    let expected_total_words = 1 + byte_len.div_ceil(4);
    if words.len() != expected_total_words {
        bail!(
            "framed payload has {} words but expected {expected_total_words} from byte length {byte_len}",
            words.len()
        );
    }

    let mut bytes = Vec::with_capacity(byte_len);
    for word in payload_words {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.truncate(byte_len);
    Ok(bytes)
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
        bail!(
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
) -> Result<ProofBatchStats> {
    let proving_started_at = Instant::now();
    let prove_result = prover
        .prove(input_words)
        .with_context(|| format!("while attempting to generate proof for batch {batch_number}"))?;
    let proving_time = proving_started_at.elapsed();
    let cycles = u64::try_from(prove_result.cycles)
        .context("while attempting to convert proof cycle count to u64")?;
    let output = prove_result.receipt.output[0];

    info!(
        batch_number,
        cycles,
        proving_time_secs = proving_time.as_secs_f64(),
        output,
        "Finished proof generation"
    );

    if output != EXPECTED_OUTPUT {
        bail!(
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
            bail!(
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
        bail!("guest manifest has empty bin_sha256, cannot derive verification key cache path");
    }

    Ok(PathBuf::from(format!("vk-{manifest_sha256}.bin")))
}

fn batch_file_path(batches_dir: &Path, batch_number: u64) -> PathBuf {
    batches_dir.join(format!("{batch_number}.bin"))
}

fn batches_dir() -> Result<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BATCHES_DIR_RELATIVE);
    path.canonicalize()
        .with_context(|| format!("while attempting to canonicalize {}", path.display()))
}

fn dist_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}
