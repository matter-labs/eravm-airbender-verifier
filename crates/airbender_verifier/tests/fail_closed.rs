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

/// Batch number of the synthetic gap fixture (see `tools/gap-fixture` and
/// `testdata/.../README.md`): a v31 batch containing a `GapMaker.makeGaps` tx that
/// writes previously-empty storage slots and, in the same committed transaction,
/// writes them back to their original value. The net change is zero so
/// `merkle_paths` omits each slot, yet the VM accessed them — the "gap" this test
/// needs. (Set to the batch the fixture landed in; update when regenerated.)
const GAP_BATCH: u64 = 85348;

/// The gap fixture has (at least) one slot `merkle_paths` omits: a write the batch
/// rolled back. It is served empty, so the batch verifies, and forging the
/// operator's value for it yields the same commitment — confirming that pre-state
/// cannot influence the committed output.
///
/// Ignored until the fixture lands: the low-activity mainnet corpus has no
/// rolled-back write, and the original mainnet batch (506155) can't be re-fetched
/// in the v31 format. Produce `{GAP_BATCH}.bin.gz` with the zksync-era harness
/// documented in the corpus README (deploy `GapMaker`, call the revert-write
/// method, seal + export the `AirbenderVerifierInput`), commit it, then delete the
/// `#[ignore]`.
#[test]
#[ignore = "needs the synthetic gap fixture (GAP_BATCH); produce it per the corpus README, then un-ignore"]
fn rolled_back_write_gap_is_harmless() {
    let Some(path) = batch_path(GAP_BATCH) else {
        return;
    };
    let v1 = load_batch(&BatchInputFile {
        number: GAP_BATCH,
        path,
    })
    .expect("load");

    let honest = v1
        .clone()
        .verify()
        .expect("gap fixture should verify (gap slot served empty)")
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
        "gap fixture {GAP_BATCH} gap reads (read, not in merkle_paths): {}",
        gap.len()
    );
    assert!(
        !gap.is_empty(),
        "expected gap fixture {GAP_BATCH} to have at least one gap slot (cold read of a rolled-back write)"
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
/// Re-keying a given write entry can be rejected two ways, and which one depends on
/// the slot: re-keying a system slot (e.g. one the bootloader reads during block
/// setup) makes the re-run diverge or panic *before* the binding check, while
/// re-keying a slot whose served pre-state doesn't steer execution re-runs cleanly
/// and is caught by the `leaf_hashed_key`/VM-key binding check itself. Both are
/// fail-closed. Rather than depend on which entry the corpus happens to surface
/// first, re-key every write entry independently and assert two invariants: no
/// re-key is ever silently accepted, and at least one is rejected *specifically* by
/// the binding check — proving that check is load-bearing, not shadowed by the
/// earlier execution-divergence rejections.
#[test]
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

    let write_idxs: Vec<usize> = v1
        .merkle_paths
        .merkle_paths
        .iter()
        .enumerate()
        .filter(|(_, m)| m.is_write)
        .map(|(i, _)| i)
        .collect();
    assert!(!write_idxs.is_empty(), "84730 should have write entries");

    let mut accepted = 0usize;
    let mut binding_rejections = 0usize;

    for idx in write_idxs {
        let v = v1.clone();
        // Some slots make the re-keyed re-run *panic* (a re-keyed bootloader slot
        // fails block setup) rather than return an error; catch it — a panic is
        // still a fail-closed rejection, just not the binding-check one we count.
        // Expect a "thread panicked" line on stderr for such an entry; the test
        // still passes. `AssertUnwindSafe` because the captured input isn't
        // `UnwindSafe`; we never observe post-panic state, only re-run per entry.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let mut tampered = v;
            tampered.merkle_paths.merkle_paths[idx].leaf_hashed_key = U256::MAX;
            tampered.verify().map(|_| ()).map_err(|e| e.to_string())
        }));
        match outcome {
            Ok(Ok(())) => accepted += 1,
            Ok(Err(msg)) if msg.contains("leaf_hashed_key") => binding_rejections += 1,
            Ok(Err(_)) | Err(_) => {}
        }
    }

    assert_eq!(
        accepted, 0,
        "a re-keyed merkle_paths entry was silently accepted"
    );
    assert!(
        binding_rejections >= 1,
        "no re-keyed entry was rejected by the leaf_hashed_key/VM-key binding check"
    );
}
