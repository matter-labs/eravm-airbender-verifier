//! Convert a batch into the verifier's on-disk fixture format (`.bin`/`.bin.gz`).
//!
//! The primary path turns a zksync-era airbender export — a `proof_inputs_*.json`
//! (a JSON-serialized `AirbenderVerifierInput`, as served by the node's
//! `/airbender/proof_inputs_no_lock/{batch}` endpoint) — into a repo fixture:
//!
//!   cargo run --release -p zksync_cycle_model --example encode_batch -- \
//!       proof_inputs_<N>.json <N>.bin.gz
//!
//! With `--from-bin` the input is an existing `.bin`/`.bin.gz` fixture instead of
//! JSON — useful to re-encode or sanity-check the round-trip on a known batch:
//!
//!   cargo run ... --example encode_batch -- --from-bin <N>.bin.gz /tmp/rt.bin.gz
//!
//! After writing, it reloads the output via `load_batch` and asserts it equals
//! the input, so a successful run is a proof the encode/decode round-trips.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use anyhow::{Context, Result};
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_cli_utils::{load_batch, save_batch, BatchInputFile};

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let from_bin = args.first().map(|a| a == "--from-bin").unwrap_or(false);
    if from_bin {
        args.remove(0);
    }
    if args.len() != 2 {
        anyhow::bail!(
            "usage: encode_batch [--from-bin] <input(.json|.bin[.gz])> <output.bin[.gz]>"
        );
    }
    let in_path = PathBuf::from(&args[0]);
    let out_path = PathBuf::from(&args[1]);

    let input: AirbenderVerifierInput = if from_bin {
        // load_batch resolves the format (.bin / .bin.gz) itself; number is
        // irrelevant here, only the path is used.
        load_batch(&BatchInputFile {
            number: 0,
            path: in_path.clone(),
        })
        .with_context(|| format!("loading fixture {}", in_path.display()))?
    } else {
        serde_json::from_reader(BufReader::new(
            File::open(&in_path).with_context(|| format!("opening {}", in_path.display()))?,
        ))
        .with_context(|| {
            format!(
                "parsing {} as AirbenderVerifierInput JSON",
                in_path.display()
            )
        })?
    };

    save_batch(&input, &out_path).with_context(|| format!("writing {}", out_path.display()))?;

    // Self-check: reload the fixture we just wrote and confirm it matches.
    let reloaded = load_batch(&BatchInputFile {
        number: 0,
        path: out_path.clone(),
    })
    .with_context(|| format!("re-loading {} for round-trip check", out_path.display()))?;
    anyhow::ensure!(
        reloaded == input,
        "round-trip mismatch: reloaded {} does not equal the input",
        out_path.display()
    );

    let written = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "wrote {} ({written} bytes) and verified load_batch round-trip",
        out_path.display()
    );
    Ok(())
}
