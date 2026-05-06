//! One-shot migrator: re-encode each test batch with a self-consistent
//! synthetic `CommitmentInput` baked into the payload. After running this,
//! consumers (host, guest, integration tests) load and verify directly —
//! no runtime synthesis step.
//!
//! Run once, locally, with all batches LFS-pulled:
//!
//!   ./scripts/fetch_lfs_batches.sh --all
//!   cargo run --release -p zksync_cli_utils --bin migrate-corpus
//!
//! Each `.bin.gz` is rewritten in place with the same container layout
//! (gzip + FNAME, hex-encoded, 4-byte BE length prefix, zero-padded to a
//! 4-byte multiple). The inner bincode payload decodes as
//! `TeeVerifierInput::V1(V1TeeVerifierInput { commitment_input: Some(_), .. })`.
//!
//! The synthetic `CommitmentInput` depends on VM-execution pubdata at
//! migration time. If the workspace's multivm crate ever changes pubdata
//! output, re-run this migration to refresh the baked linear hashes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::Compression;
use flate2::GzBuilder;
use zksync_cli_utils::{load_batch, BatchInputFile};
use zksync_tee_verifier::test_utils::augment_with_synthetic_commitment;
use zksync_tee_verifier::types::TeeVerifierInput;

fn main() -> Result<()> {
    let dir = PathBuf::from("testdata/era_mainnet_batches/binary");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("gz"))
        .collect();
    paths.sort();
    anyhow::ensure!(!paths.is_empty(), "no .gz batches under {}", dir.display());

    println!("migrating {} batches", paths.len());
    for path in &paths {
        let batch_input = batch_from_path(path)?;
        let v1 = load_batch(&batch_input)
            .with_context(|| format!("loading {}", path.display()))?
            .into_v1()
            .with_context(|| format!("{}: expected V1 payload", path.display()))?;
        let augmented = augment_with_synthetic_commitment(v1)
            .with_context(|| format!("synthesizing commitment for {}", path.display()))?;
        anyhow::ensure!(
            augmented.commitment_input.is_some(),
            "{}: augmentation didn't populate commitment_input",
            path.display()
        );

        let wrapped = TeeVerifierInput::V1(augmented);
        let raw_bytes = bincode::serde::encode_to_vec(&wrapped, bincode::config::standard())
            .with_context(|| format!("encoding {}", path.display()))?;
        let (decoded, decoded_len): (TeeVerifierInput, usize) =
            bincode::serde::decode_from_slice(&raw_bytes, bincode::config::standard())
                .context("enum round-trip decode failed")?;
        anyhow::ensure!(
            decoded == wrapped && decoded_len == raw_bytes.len(),
            "{}: enum round-trip mismatch",
            path.display()
        );

        let framed = frame_payload(&raw_bytes);
        let hex = bytes_to_lowercase_hex(&framed);
        let gz_filename = original_inner_filename(path)?;
        write_gzipped_text(path, &hex, &gz_filename)?;
        println!("  wrote {}", path.display());
    }

    println!(
        "done; {} batches now ship V1 + baked synthetic commitment_input.",
        paths.len()
    );
    Ok(())
}

fn batch_from_path(path: &Path) -> Result<BatchInputFile> {
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("non-utf8 filename")?;
    let number_str = stem
        .strip_suffix(".bin.gz")
        .with_context(|| format!("unexpected filename {stem}"))?;
    let number: u64 = number_str
        .parse()
        .with_context(|| format!("non-numeric batch number in {stem}"))?;
    Ok(BatchInputFile {
        number,
        path: path.to_path_buf(),
    })
}

/// Returns `[byte_len_be: u32] ++ bytes ++ zero_pad_to_multiple_of_4`.
fn frame_payload(bytes: &[u8]) -> Vec<u8> {
    let byte_len = u32::try_from(bytes.len()).expect("payload exceeds 4 GiB");
    let total = 4 + bytes.len();
    let padded_total = total.div_ceil(4) * 4;
    let mut framed = Vec::with_capacity(padded_total);
    framed.extend_from_slice(&byte_len.to_be_bytes());
    framed.extend_from_slice(bytes);
    framed.resize(padded_total, 0);
    framed
}

fn bytes_to_lowercase_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn original_inner_filename(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("non-utf8 filename")?;
    name.strip_suffix(".gz")
        .map(str::to_owned)
        .with_context(|| format!("expected .gz suffix on {name}"))
}

fn write_gzipped_text(path: &Path, text: &str, gz_filename: &str) -> Result<()> {
    let file = fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut encoder = GzBuilder::new()
        .filename(gz_filename)
        .write(file, Compression::default());
    encoder
        .write_all(text.as_bytes())
        .context("writing hex text")?;
    encoder.finish().context("finalizing gzip")?;
    Ok(())
}
