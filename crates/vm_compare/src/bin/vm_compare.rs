use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use zksync_tee_verifier::types::TeeVerifierInput;
use zksync_vm_compare::{CompareOptions, ComparisonOutcome};

const DEFAULT_BATCHES_DIR: &str = "../../storage/era_mainnet_batches/binary";

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Compare legacy and fast VM execution on framed batch inputs"
)]
struct Cli {
    #[arg(long, conflicts_with = "all_batches")]
    batch_number: Option<u64>,

    #[arg(long, conflicts_with = "batch_number")]
    all_batches: bool,

    #[arg(long, default_value = DEFAULT_BATCHES_DIR)]
    batches_dir: String,

    #[arg(long, default_value_t = CompareOptions::default().max_capture_bytes)]
    max_capture_bytes: usize,

    #[arg(long)]
    no_fail_fast: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let batches_dir = PathBuf::from(&cli.batches_dir)
        .canonicalize()
        .with_context(|| format!("while attempting to canonicalize {}", cli.batches_dir))?;
    let batch_numbers = resolve_batch_numbers(&cli, &batches_dir)?;
    let options = CompareOptions {
        max_capture_bytes: cli.max_capture_bytes,
        fail_fast: !cli.no_fail_fast,
    };
    let mut had_divergence = false;

    for batch_number in batch_numbers {
        let input = load_verifier_input(&batches_dir, batch_number)
            .with_context(|| format!("while attempting to load batch {batch_number}"))?;
        let matched = compare_batch(batch_number, input, options)?;
        had_divergence |= !matched;
        if had_divergence && options.fail_fast {
            bail!("legacy and fast VM traces diverged");
        }
    }

    if had_divergence {
        bail!("legacy and fast VM traces diverged");
    }

    Ok(())
}

fn resolve_batch_numbers(cli: &Cli, batches_dir: &Path) -> Result<Vec<u64>> {
    if cli.all_batches {
        return list_all_batch_numbers(batches_dir);
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
        if path.extension().and_then(|ext| ext.to_str()) != Some("bin") {
            continue;
        }

        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if let Ok(number) = stem.parse::<u64>() {
            batch_numbers.push(number);
        }
    }

    if batch_numbers.is_empty() {
        bail!("no batch files were found in {}", batches_dir.display());
    }

    batch_numbers.sort_unstable();
    Ok(batch_numbers)
}

fn load_verifier_input(batches_dir: &Path, batch_number: u64) -> Result<TeeVerifierInput> {
    let framed_words = load_batch_words(batches_dir, batch_number)
        .with_context(|| format!("while attempting to parse words for batch {batch_number}"))?;
    let payload = frame_words_to_bytes(&framed_words).with_context(|| {
        format!("while attempting to decode framed payload for batch {batch_number}")
    })?;

    let (input, decoded_len): (TeeVerifierInput, usize) =
        bincode::serde::decode_from_slice(&payload, bincode::config::standard())
            .with_context(|| format!("while attempting to bincode-decode batch {batch_number}"))?;
    if decoded_len != payload.len() {
        bail!(
            "batch {batch_number} bincode payload has trailing bytes (decoded {decoded_len} of {})",
            payload.len()
        );
    }

    Ok(input)
}

fn load_batch_words(batches_dir: &Path, batch_number: u64) -> Result<Vec<u32>> {
    let batch_path = batches_dir.join(format!("{batch_number}.bin"));
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
        compact = stripped.to_owned();
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

fn compare_batch(
    batch_number: u64,
    input: TeeVerifierInput,
    options: CompareOptions,
) -> Result<bool> {
    let TeeVerifierInput::V1(input) = input else {
        bail!("batch {batch_number} must contain TeeVerifierInput::V1");
    };

    let report = zksync_vm_compare::compare(input, options).with_context(|| {
        format!("while attempting to compare V1 input for batch {batch_number}")
    })?;

    match &report.outcome {
        ComparisonOutcome::Match => {
            println!("batch {batch_number}: {report}");
            Ok(true)
        }
        ComparisonOutcome::Diverged(divergences) => {
            eprintln!("batch {batch_number}: {report}");
            for (index, divergence) in divergences.iter().enumerate() {
                eprintln!(
                    "divergence {} at L2 block {}, tx #{} ({:?}): {}",
                    index + 1,
                    divergence.location.l2_block_number,
                    divergence.location.tx_index_in_block,
                    divergence.location.tx_hash,
                    divergence.reason
                );
                if let Some(legacy) = &divergence.legacy {
                    eprintln!("legacy: {legacy:#?}");
                }
                if let Some(fast) = &divergence.fast {
                    eprintln!("fast: {fast:#?}");
                }
            }
            Ok(false)
        }
    }
}
