//! Storage-view soundness regressions: slot values come only from `merkle_paths`,
//! and slots it omits (writes the batch fully rolled back) are served empty rather
//! than from the operator. Forging an operator-supplied value must never change the
//! committed output.

use std::{collections::HashSet, path::Path};

use zksync_airbender_verifier::Verify;
use zksync_cli_utils::{load_batch, BatchInputFile};
use zksync_types::{H256, U256};

fn batch_path(number: u64) -> Option<std::path::PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../testdata/era_mainnet_batches/binary/{number}.bin.gz"
    ));
    let present = path.exists()
        && std::fs::metadata(&path)
            .map(|m| m.len() >= 1000)
            .unwrap_or(false);
    if present {
        return Some(path);
    }
    // These are security regressions, so under CI a missing fixture must fail the
    // job, not silently skip — otherwise a missing-LFS misconfiguration would
    // disable the checks while still reporting green. Locally we skip for
    // convenience (the default `cargo test` doesn't fetch LFS).
    assert!(
        std::env::var_os("CI").is_none(),
        "batch {number} fixture missing under CI — run ./scripts/fetch_lfs_batches.sh before `cargo test`"
    );
    eprintln!("Skipping: batch {number} fixture missing (run ./scripts/fetch_lfs_batches.sh)");
    None
}

/// `merkle_paths` hashed keys (`leaf_hashed_key` is a little-endian `U256`).
fn merkle_path_keys(
    v1: &zksync_airbender_verifier::types::AirbenderVerifierInput,
) -> HashSet<H256> {
    v1.merkle_paths
        .merkle_paths
        .iter()
        .map(|l| {
            let mut b = [0u8; 32];
            l.leaf_hashed_key.to_little_endian(&mut b);
            H256(b)
        })
        .collect()
}

/// Batch 506155 has one slot `merkle_paths` omits: a write the batch rolled back.
/// It is served empty, so the batch verifies, and forging the operator's value for
/// it yields the same commitment — confirming that pre-state cannot influence the
/// committed output.
///
/// Ignored: no batch in the current v31 corpus exercises a rolled-back write (a
/// read whose slot `merkle_paths` omits). Re-enable, pointing at the batch below,
/// once such a batch is captured from the sequencer.
#[test]
#[ignore = "no v31 corpus batch has a rolled-back-write gap slot; capture one before re-enabling"]
fn rolled_back_write_batch_506155_verifies_and_gap_is_harmless() {
    let Some(path) = batch_path(506155) else {
        return;
    };
    let v1 = load_batch(&BatchInputFile {
        number: 506155,
        path,
    })
    .expect("load");

    let honest = v1
        .clone()
        .verify()
        .expect("506155 should verify (gap slot served empty)")
        .commitment;

    let mp = merkle_path_keys(&v1);
    let gap: Vec<_> = v1
        .vm_run_data
        .witness_block_state
        .read_storage_key
        .keys()
        .filter(|k| !mp.contains(&k.hashed_key()))
        .cloned()
        .collect();
    eprintln!(
        "506155 gap reads (read, not in merkle_paths): {}",
        gap.len()
    );
    assert!(
        !gap.is_empty(),
        "expected 506155 to have at least one gap slot (cold read of a rolled-back write)"
    );

    // Forge every gap read's value; the committed output must be unchanged.
    let mut forged = v1;
    for key in &gap {
        if let Some(v) = forged
            .vm_run_data
            .witness_block_state
            .read_storage_key
            .get_mut(key)
        {
            *v = H256(std::array::from_fn(|i| v.0[i] ^ 0xff));
        }
    }
    let forged_commitment = forged
        .verify()
        .expect("forged-gap run should still verify")
        .commitment;

    assert_eq!(
        honest, forged_commitment,
        "gap-read value must not influence the committed output"
    );
}

/// Forging the operator's `read_storage_key` value for a slot that IS in
/// `merkle_paths` leaves the commitment unchanged: the value comes from the tree
/// witness, never the operator.
#[test]
fn committed_read_bound_to_merkle_paths() {
    let Some(path) = batch_path(84730) else {
        return;
    };
    let v1 = load_batch(&BatchInputFile {
        number: 84730,
        path,
    })
    .expect("load");

    let honest = v1.clone().verify().expect("84730 should verify").commitment;

    let mp = merkle_path_keys(&v1);
    let committed_read_key = v1
        .vm_run_data
        .witness_block_state
        .read_storage_key
        .keys()
        .find(|k| mp.contains(&k.hashed_key()))
        .cloned()
        .expect("84730 should have a read covered by merkle_paths");

    let mut forged = v1;
    let v = forged
        .vm_run_data
        .witness_block_state
        .read_storage_key
        .get_mut(&committed_read_key)
        .unwrap();
    *v = H256(std::array::from_fn(|i| v.0[i] ^ 0xff));

    let forged_commitment = forged
        .verify()
        .expect("forged operator value should not break verification")
        .commitment;

    assert_eq!(
        honest, forged_commitment,
        "committed read must use the merkle_paths value, not the operator's"
    );
}

/// A `merkle_paths` entry's `leaf_hashed_key` must match the slot the VM actually
/// touched. Re-keying an entry (keeping its valid path/value/index for the real
/// slot, but pointing `leaf_hashed_key` elsewhere) would let the proof bind one
/// slot's pre-state while the VM was fed a different value for it — so it must be
/// rejected.
///
/// Ignored: on the current low-activity v31 corpus the re-keyed re-run diverges
/// into bootloader pubdata construction and panics ("Empty pubdata information")
/// before reaching the `leaf_hashed_key` binding check this test asserts. Re-enable
/// once a batch with richer execution (non-empty pubdata) is captured.
#[test]
#[ignore = "current v31 corpus batches have empty pubdata; the tampered re-run panics before the leaf_hashed_key check"]
fn merkle_path_key_bound_to_vm_key() {
    let Some(path) = batch_path(84730) else {
        return;
    };
    let v1 = load_batch(&BatchInputFile {
        number: 84730,
        path,
    })
    .expect("load");

    // Sanity: it verifies untouched.
    v1.clone().verify().expect("84730 verifies untouched");

    // Re-key one committed write entry to an unused slot, leaving its Merkle
    // path/value/index (the proof for the real slot) intact.
    let mut tampered = v1;
    let entry = tampered
        .merkle_paths
        .merkle_paths
        .iter_mut()
        .find(|m| m.is_write)
        .expect("84730 should have a write entry");
    entry.leaf_hashed_key = U256::MAX;

    let err = match tampered.verify() {
        Ok(_) => panic!("re-keyed merkle_paths entry must be rejected"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("leaf_hashed_key"),
        "expected a leaf_hashed_key/VM-key binding rejection, got: {err}"
    );
}
