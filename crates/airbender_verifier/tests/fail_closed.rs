//! Storage-view soundness regressions. Each tampers the `84730` corpus and asserts
//! the verifier ignores the forged operator value or fails closed. No synthetic
//! fixture required.

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

/// The operator cannot inject a slot's pre-state by omitting its `merkle_paths`
/// proof: an omitted read is served empty, not the operator's value, so the batch
/// fails closed.
///
/// This originally used an honest rolled-back-write gap (mainnet batch 506155,
/// pre-v31). We could not regenerate that batch on v31 — the batches we produced
/// don't reproduce the gap — so we synthesize it adversarially instead, by dropping
/// a proven read's `merkle_paths` entry and forging its operator value.
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

    // The forged value must never be used; the batch must be rejected.
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

/// A `merkle_paths` entry's `leaf_hashed_key` must match the slot the VM touched;
/// re-keying it elsewhere must be rejected. Re-key every write entry and assert two
/// invariants: none is ever silently accepted, and at least one is rejected by the
/// `leaf_hashed_key` binding check specifically (not only by execution divergence).
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
        // Some entries make the re-run panic rather than return an error; a panic is
        // still fail-closed, just not the binding-check rejection we count. Catch it
        // so the loop continues (expect a "thread panicked" line on stderr).
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
