//! Storage-view soundness regressions: slot pre-state comes only from `merkle_paths`
//! (proven against `old_root_hash`), never from operator-supplied values. A slot the
//! VM reads but `merkle_paths` omits is served empty, and a `merkle_paths` entry must
//! bind to the slot the VM actually touched. Each test tampers the ordinary `84730`
//! corpus and asserts the verifier ignores the forged operator value or fails closed
//! — no synthetic fixture required (see `omitted_merkle_path_read_cannot_inject_prestate`
//! for why an honest gap is unreachable on v31).

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

/// Storage-soundness regression: the operator cannot inject a slot's pre-state by
/// **omitting its `merkle_paths` proof**. Slot values come only from `merkle_paths`
/// (proven against `old_root_hash`); a slot the VM reads but that `merkle_paths`
/// omits is served empty (`None`) by the fallback in `execute`, never the
/// operator's `read_storage_key` value. So forging that value cannot smuggle a
/// pre-state into the committed output — the batch fails closed instead.
///
/// This began as an *honest* rolled-back-write fixture (mainnet batch 506155,
/// pre-v31): a write the batch fully rolled back left a slot the VM cold-read but
/// that `merkle_paths` legitimately omitted, served empty and harmless. That shape
/// is **unreachable on v31** — the fast-VM witness pipeline proves every accessed
/// slot (a committed net-zero write becomes a protective read; a reverted write
/// vanishes entirely), so `read_storage_key` always equals `merkle_paths` (verified
/// empirically by minting v31 batches whose transactions attempt the shape; none
/// produced a gap). We therefore test the underlying security property
/// adversarially — synthesize the gap by deleting a proven read's `merkle_paths`
/// entry and forging its operator value — which needs no fixture.
#[test]
fn omitted_merkle_path_read_cannot_inject_prestate() {
    let Some(path) = batch_path(84730) else {
        return;
    };
    let v1 = load_batch(&BatchInputFile {
        number: 84730,
        path,
    })
    .expect("load");
    v1.clone().verify().expect("84730 verifies untouched");

    // Take a proven read (is_write == false) and drop its `merkle_paths` entry, so
    // its slot is still read by the VM but no longer proven — an operator-forged
    // "gap". Then forge that slot's operator-supplied `read_storage_key` value.
    let read_entry = v1
        .merkle_paths
        .merkle_paths
        .iter()
        .find(|m| !m.is_write)
        .expect("84730 has a proven read")
        .clone();

    let mut tampered = v1;
    tampered
        .merkle_paths
        .merkle_paths
        .retain(|m| m.leaf_hashed_key != read_entry.leaf_hashed_key);

    let mut key_le = [0u8; 32];
    read_entry.leaf_hashed_key.to_little_endian(&mut key_le);
    let hashed = H256(key_le);
    let mut forged_any = false;
    for (k, v) in tampered
        .vm_run_data
        .witness_block_state
        .read_storage_key
        .iter_mut()
    {
        if k.hashed_key() == hashed {
            *v = H256(std::array::from_fn(|i| v.0[i] ^ 0xff));
            forged_any = true;
        }
    }
    assert!(
        forged_any,
        "the dropped read's slot should have an operator value to forge"
    );

    // The forged operator value must never be used: the slot is served empty, so the
    // re-run diverges from the proven execution and the batch is rejected.
    match tampered.verify() {
        Ok(_) => panic!(
            "omitting a read's merkle_paths proof must fail closed, not trust the operator value"
        ),
        Err(err) => eprintln!("omitted-proof gap rejected (fail-closed): {err}"),
    }
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
