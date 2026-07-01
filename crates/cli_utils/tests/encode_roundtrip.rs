//! Round-trip test: every batch present in the corpus must survive
//! load -> `encode_batch` -> load unchanged. This pins `encode_batch` as the
//! exact inverse of `load_batch`, which is what `scripts/regenerate_testdata.sh`
//! relies on to produce byte-loadable `<number>.bin` files from the prover
//! service's JSON.
//!
//! The test round-trips whichever batches are materialized locally (Git LFS
//! leaves the corpus as pointer files by default). Fetch the batches you want to
//! exercise first, e.g.:
//!   ./scripts/fetch_lfs_batches.sh --all

use std::path::{Path, PathBuf};

use zksync_cli_utils::{encode_batch, load_batch, BatchInputFile};

/// Minimum size that distinguishes a materialized batch from a Git LFS pointer
/// (pointers are ~130 bytes).
const LFS_POINTER_MAX: u64 = 1000;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/era_mainnet_batches/binary")
}

/// Materialized `<number>.bin.gz` batches (skipping LFS pointer stubs).
fn present_batches() -> Vec<(u64, PathBuf)> {
    let dir = corpus_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".bin.gz") else {
            continue;
        };
        let Ok(number) = stem.parse::<u64>() else {
            continue;
        };
        let materialized = std::fs::metadata(&path)
            .map(|m| m.len() >= LFS_POINTER_MAX)
            .unwrap_or(false);
        if materialized {
            out.push((number, path));
        }
    }
    out.sort_by_key(|(number, _)| *number);
    out
}

#[test]
fn encode_batch_is_inverse_of_load_batch() {
    let batches = present_batches();

    if batches.is_empty() {
        // Under CI the corpus is fetched, so an empty set means a missing-LFS
        // misconfiguration; fail rather than report green. Locally we skip (the
        // default `cargo test` does not fetch LFS).
        assert!(
            std::env::var_os("CI").is_none(),
            "no materialized batches under CI — fetch the corpus (./scripts/fetch_lfs_batches.sh ...) before `cargo test`"
        );
        eprintln!("Skipping encode round-trip: no materialized batches (run ./scripts/fetch_lfs_batches.sh ...)");
        return;
    }

    for (number, path) in batches {
        let original = load_batch(&BatchInputFile { number, path })
            .unwrap_or_else(|err| panic!("failed to load batch {number}: {err:?}"));

        // Encode to on-disk hex text, write it as a `.bin`, and load it back.
        let hex = encode_batch(&original)
            .unwrap_or_else(|err| panic!("encode_batch failed for batch {number}: {err:?}"));
        let tmp = std::env::temp_dir().join(format!("{number}.encode_roundtrip.bin"));
        std::fs::write(&tmp, hex.as_bytes()).expect("failed to write temp batch");

        let reloaded = load_batch(&BatchInputFile {
            number,
            path: tmp.clone(),
        })
        .unwrap_or_else(|err| panic!("failed to reload encoded batch {number}: {err:?}"));
        let _ = std::fs::remove_file(&tmp);

        assert_eq!(
            original, reloaded,
            "batch {number}: encode_batch output did not reload to an identical AirbenderVerifierInput"
        );
        eprintln!("batch {number}: round-trip OK");
    }
}
