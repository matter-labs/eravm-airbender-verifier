use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use tracing::warn;

pub fn list_all_batch_numbers(batches_dir: &Path) -> Result<Vec<u64>> {
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

pub fn load_batch_words(batches_dir: &Path, batch_number: u64) -> Result<Vec<u32>> {
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

pub fn parse_hex_words(raw: &str) -> Result<Vec<u32>> {
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

fn batch_file_path(batches_dir: &Path, batch_number: u64) -> PathBuf {
    batches_dir.join(format!("{batch_number}.bin"))
}
