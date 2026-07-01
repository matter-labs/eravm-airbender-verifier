//! Convert a JSON `AirbenderVerifierInput` into the hex-text batch corpus format.
//!
//! The zksync-era prover service (`airbender_proof_data_handler`) serves verifier
//! inputs as JSON via `GET /proof-generation-data/{l1_batch_number}`, returning a
//! `Json(Option<AirbenderVerifierInput>)` — i.e. the batch object, or `null` when
//! no data is available. This tool reads that JSON on stdin and writes the
//! corresponding `<number>.bin` hex text on stdout, ready to be gzipped and staged
//! into the Git LFS corpus (see `scripts/regenerate_testdata.sh`).
//!
//! Usage:
//!   curl -s "$URL/airbender/proof_inputs_no_lock/84730" | json_to_batch > 84730.bin

use std::io::{Read, Write};

use anyhow::{Context, Result};
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_cli_utils::encode_batch;

fn main() -> Result<()> {
    let mut json = String::new();
    std::io::stdin()
        .read_to_string(&mut json)
        .context("while reading JSON verifier input from stdin")?;

    let trimmed = json.trim();
    anyhow::ensure!(
        !trimmed.is_empty() && trimmed != "null",
        "the endpoint returned no verifier input (empty body or `null`); \
         the batch may not be available yet"
    );

    let input: AirbenderVerifierInput = serde_json::from_str(trimmed)
        .context("while deserializing stdin as an AirbenderVerifierInput JSON object")?;

    let hex = encode_batch(&input)?;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(hex.as_bytes())
        .context("while writing hex batch text to stdout")?;
    handle
        .write_all(b"\n")
        .context("while writing trailing newline to stdout")?;
    Ok(())
}
