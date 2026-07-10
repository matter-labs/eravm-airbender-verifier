//! Interpretation of the committed `merkle_paths` witness: classifying each
//! leaf's pre-state, building the pre-batch storage view, and turning the
//! witness into the `BlockOutputWithProofs` the tree fold verifies. Kept out of
//! `lib.rs` (and out of the vendored `merkle_tree` crate, which shouldn't carry
//! verifier policy) so the soundness-relevant leaf-shape rules live in one place.

use anyhow::Result;
use zksync_merkle_tree::{
    BlockOutputWithProofs, HashTree, TreeEntry, TreeInstruction, TreeLogEntry, TreeLogEntryWithProof,
    ValueHash, TREE_DEPTH,
};
use zksync_types::{StorageLog, H256, U256};

use crate::map_log_tree;
use crate::types::{StorageLogMetadata, WitnessInputMerklePaths, HASH_LEN};

/// The pre-state a single Merkle-witness leaf encodes, after rejecting shapes
/// the tree never emits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum WitnessLeaf {
    /// Empty leaf: value 0, no enumeration index (a read of a missing key, or a
    /// first write / insertion of a previously-empty slot).
    Empty { is_write: bool },
    /// Existing leaf at `index > 0` with pre-state `value`.
    Existing {
        is_write: bool,
        index: u64,
        value: H256,
    },
}

/// Classify a Merkle-witness leaf, rejecting malformed shapes the tree never
/// produces: a read flagged `first_write`, and a repeated write to enum index 0.
pub(crate) fn classify_witness_leaf(log: &StorageLogMetadata) -> anyhow::Result<WitnessLeaf> {
    let key = log.leaf_hashed_key;
    match (log.is_write, log.first_write, log.leaf_enumeration_index) {
        (false, true, _) => {
            anyhow::bail!("witness read entry for leaf {key:x} is marked first_write")
        }
        (false, _, 0) => Ok(WitnessLeaf::Empty { is_write: false }),
        (false, false, index) => Ok(WitnessLeaf::Existing {
            is_write: false,
            index,
            value: H256(log.value_read),
        }),
        (true, true, _) => Ok(WitnessLeaf::Empty { is_write: true }),
        (true, false, 0) => {
            anyhow::bail!("witness repeated write to leaf {key:x} has enumeration index 0")
        }
        (true, false, index) => Ok(WitnessLeaf::Existing {
            is_write: true,
            index,
            value: H256(log.value_read),
        }),
    }
}

/// Build the storage view from the committed `merkle_paths` witness: each entry's
/// classified pre-state (empty leaf -> `None`, existing leaf -> `Some((value,
/// index))`), keyed by its hashed key (a little-endian `U256`). Every entry is
/// proven against `old_root_hash` by the later `verify_proofs` fold, so this only
/// translates shapes — rejecting malformed leaves (via the classifier) and any
/// conflicting duplicate (`merkle_paths` is deduplicated to one entry per slot).
pub(crate) fn build_view_from_merkle_paths(
    merkle_paths: &[StorageLogMetadata],
) -> anyhow::Result<std::collections::BTreeMap<H256, Option<(H256, u64)>>> {
    use std::collections::btree_map::Entry;

    let mut view = std::collections::BTreeMap::new();
    for log in merkle_paths {
        let prestate = match classify_witness_leaf(log)? {
            WitnessLeaf::Empty { .. } => None,
            WitnessLeaf::Existing { index, value, .. } => Some((value, index)),
        };
        let mut key_bytes = [0u8; 32];
        log.leaf_hashed_key.to_little_endian(&mut key_bytes);
        match view.entry(H256(key_bytes)) {
            Entry::Vacant(slot) => {
                slot.insert(prestate);
            }
            Entry::Occupied(slot) => anyhow::ensure!(
                *slot.get() == prestate,
                "merkle_paths has a conflicting pre-state for slot {:?}: {:?} vs {prestate:?}",
                slot.key(),
                slot.get(),
            ),
        }
    }
    Ok(view)
}

/// Classify a witness leaf and map it to its `TreeLogEntry` base. Shared by
/// `get_bowp` (oracle) and `verify_paths_and_new_root` (streaming) so the two
/// can never disagree on classification.
fn tree_log_entry_from_witness(log: &StorageLogMetadata) -> anyhow::Result<TreeLogEntry> {
    Ok(match classify_witness_leaf(log)? {
        WitnessLeaf::Empty { is_write: false } => TreeLogEntry::ReadMissingKey,
        WitnessLeaf::Empty { is_write: true } => TreeLogEntry::Inserted,
        WitnessLeaf::Existing {
            is_write: false,
            index,
            value,
        } => TreeLogEntry::Read {
            leaf_index: index,
            value: value.0.into(),
        },
        WitnessLeaf::Existing {
            is_write: true,
            index,
            value,
        } => TreeLogEntry::Updated {
            leaf_index: index,
            previous_value: value.0.into(),
        },
    })
}

/// Builds `BlockOutputWithProofs` from the merkle witness, paired with each
/// entry's `leaf_hashed_key` in order.
///
/// The keys are returned separately because `BlockOutputWithProofs` doesn't
/// carry them, yet `generate_tree_instructions` must bind each proof to the VM's
/// storage-log key. `verify_proofs` checks the Merkle path against the VM key
/// (via the `TreeInstruction`), while the storage view is seeded by
/// `leaf_hashed_key`; if those two keys are allowed to differ, a proof for one
/// slot's pre-state could be paired with a VM that read a *different* value for
/// that slot. Binding them keeps the proven slot and the executed slot the same.
///
/// Superseded in production by `verify_paths_and_new_root` (the streaming
/// pass); kept as part of the differential-test oracle (this +
/// `generate_tree_instructions` + `verify_proofs` + `root_hash()`) — see
/// `streaming_tests` below.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn get_bowp(
    witness_input_merkle_paths: WitnessInputMerklePaths,
) -> Result<(BlockOutputWithProofs, Vec<U256>)> {
    let entries: Vec<(TreeLogEntryWithProof, U256)> = witness_input_merkle_paths
        .into_merkle_paths()
        .map(|log| -> anyhow::Result<(TreeLogEntryWithProof, U256)> {
            let root_hash = log.root_hash.into();
            let leaf_hashed_key = log.leaf_hashed_key;
            // Same classifier as the storage-view derivation, so the two can
            // never disagree on which witness shapes are valid. `value_written`
            // is intentionally unused: the verifier derives the written value
            // from VM execution, not from the witness.
            let base = tree_log_entry_from_witness(&log)?;
            let merkle_path = log.merkle_paths.into_iter().map(|x| x.into()).collect();
            Ok((
                TreeLogEntryWithProof {
                    base,
                    merkle_path,
                    root_hash,
                },
                leaf_hashed_key,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let (logs, leaf_keys): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
    Ok((
        BlockOutputWithProofs {
            logs,
            leaf_count: 0,
        },
        leaf_keys,
    ))
}

/// Reconstruct entry `i`'s full Merkle path from the delta-compressed witness
/// form: the shared prefix is taken from `first` (the first/longest stored
/// path). Mirrors `WitnessInputMerklePaths::into_merkle_paths`, one entry at a
/// time (entry 0 passes `first` as `compact` and is returned unchanged).
///
/// Expands one path lazily so the streaming pass holds only one full path at a
/// time, instead of eagerly materializing all of them via `into_merkle_paths`.
fn expand_full_path(
    first: &[[u8; HASH_LEN]],
    compact: &[[u8; HASH_LEN]],
) -> anyhow::Result<Vec<ValueHash>> {
    anyhow::ensure!(
        compact.len() <= first.len(),
        "Merkle paths malformed: a later path ({}) is longer than the first ({})",
        compact.len(),
        first.len(),
    );
    let prefix_len = first.len() - compact.len();
    let mut full = Vec::with_capacity(first.len());
    full.extend(first[..prefix_len].iter().map(|h| ValueHash::from(*h)));
    full.extend(compact.iter().map(|h| ValueHash::from(*h)));
    Ok(full)
}

/// Streaming replacement for `get_bowp` + `generate_tree_instructions` +
/// `BlockOutputWithProofs::verify_proofs` + `root_hash()`. Classifies each
/// witness leaf, binds it to the VM storage-log key, maps it to a
/// `TreeInstruction`, then expands its Merkle path and folds it via the
/// `merkle_tree` crate's own `dyn HashTree::fold_merkle_path` (now `pub`, reused
/// as-is rather than reimplemented) against the running root — holding only one
/// expanded path at a time. Returns `(new_root_hash, new_enumeration_index)`.
///
/// Behavior MUST match the three-step path exactly (accept/reject and returned
/// values); see the differential oracle test. Divergences from the fused steps:
/// the count check is hoisted UP FRONT (a bare `zip` would silently truncate),
/// and `N == 0` maps to the same error the oracle's `root_hash()` `None` yields.
///
/// Wired into `execute()` in `lib.rs`; the three-step path (`get_bowp` +
/// `generate_tree_instructions` + `verify_proofs` + `root_hash()`) remains as
/// the differential-test oracle (see `streaming_tests` below).
pub(crate) fn verify_paths_and_new_root(
    witness: WitnessInputMerklePaths,
    vm_logs: Vec<StorageLog>,
    hasher: &dyn HashTree,
    old_root_hash: ValueHash,
    mut enumeration_index: u64,
) -> anyhow::Result<(ValueHash, u64)> {
    let metas = witness.merkle_paths;
    // Count check up front: `generate_tree_instructions` performs it before any
    // fold, and a bare `zip` below would silently truncate to the shorter side.
    anyhow::ensure!(
        metas.len() == vm_logs.len(),
        "VM deduplicated storage logs count mismatch with merkle proofs: vm_logs={}, merkle_logs={}",
        vm_logs.len(),
        metas.len(),
    );
    // With no logs the oracle's `root_hash()` is `None`, which the production
    // caller turns into this exact error via `.context(...)`.
    anyhow::ensure!(
        !metas.is_empty(),
        "root_hash unavailable after verify_proofs",
    );
    let first_path = metas[0].merkle_paths.clone();

    let mut root_hash = old_root_hash;
    for (meta, vm_log) in metas.iter().zip(vm_logs.iter()) {
        // (1) classify the witness leaf (shared classifier with `get_bowp`).
        let base = tree_log_entry_from_witness(meta)?;
        // (2) bind the proof to the slot the VM actually touched.
        let key = meta.leaf_hashed_key;
        let vm_key = vm_log.key.hashed_key_u256();
        anyhow::ensure!(
            key == vm_key,
            "merkle_paths leaf_hashed_key {key:?} does not match \
             VM storage-log key {vm_key:?}",
        );
        // (3) map to a `TreeInstruction` (advances `enumeration_index` on insert).
        let instruction = map_log_tree(key, vm_log, &base, &mut enumeration_index)?;
        // (4) expand this path lazily and fold-verify it (as `verify_proofs`).
        let full = expand_full_path(&first_path, &meta.merkle_paths)?;
        anyhow::ensure!(full.len() <= TREE_DEPTH);
        let op_root = ValueHash::from(meta.root_hash);
        if matches!(instruction, TreeInstruction::Read(_)) {
            anyhow::ensure!(
                op_root == root_hash,
                "Condition failed: `op.root_hash == root_hash` ({op_root:?} vs {root_hash:?})",
            );
            anyhow::ensure!(base.is_read());
        } else {
            anyhow::ensure!(!base.is_read());
        }
        let prev_entry = match base {
            TreeLogEntry::Inserted | TreeLogEntry::ReadMissingKey => {
                TreeEntry::empty(instruction.key())
            }
            TreeLogEntry::Updated {
                leaf_index,
                previous_value: value,
            }
            | TreeLogEntry::Read { leaf_index, value } => {
                TreeEntry::new(instruction.key(), leaf_index, value)
            }
        };
        let prev_hash = hasher.fold_merkle_path(&full, prev_entry);
        anyhow::ensure!(
            prev_hash == root_hash,
            "Condition failed: `prev_hash == root_hash` ({prev_hash:?} vs {root_hash:?})",
        );
        if let TreeInstruction::Write(new_entry) = instruction {
            let next_hash = hasher.fold_merkle_path(&full, new_entry);
            anyhow::ensure!(
                next_hash == op_root,
                "Condition failed: `next_hash == op.root_hash` ({next_hash:?} vs {op_root:?})",
            );
        }
        root_hash = op_root;
    }
    Ok((root_hash, enumeration_index))
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::types::HASH_LEN;

    fn meta(paths: Vec<[u8; HASH_LEN]>) -> StorageLogMetadata {
        StorageLogMetadata {
            root_hash: [0; HASH_LEN],
            is_write: false,
            first_write: false,
            merkle_paths: paths,
            leaf_hashed_key: U256::zero(),
            leaf_enumeration_index: 1,
            value_written: [0; HASH_LEN],
            value_read: [0; HASH_LEN],
        }
    }

    #[test]
    fn expand_full_path_matches_into_merkle_paths() {
        // first (longest, uncompacted) path of 4 hashes, then two paths that
        // share a prefix with it. `WitnessInputMerklePaths` has a private
        // field, so we build it via `push_merkle_path` (as the crate's own
        // `witness_merkle_paths_roundtrip` test does) and let it compute the
        // delta-compacted form itself, exactly as production code does.
        let first_full = vec![[1u8; HASH_LEN], [2; HASH_LEN], [3; HASH_LEN], [4; HASH_LEN]];
        let second_full = vec![[1u8; HASH_LEN], [2; HASH_LEN], [3; HASH_LEN], [9; HASH_LEN]]; // shares first[0..3]
        let third_full = vec![[1u8; HASH_LEN], [2; HASH_LEN], [8; HASH_LEN], [7; HASH_LEN]]; // shares first[0..2]

        let mut witness = WitnessInputMerklePaths::new(4);
        witness.reserve(3);
        witness.push_merkle_path(meta(first_full));
        witness.push_merkle_path(meta(second_full));
        witness.push_merkle_path(meta(third_full));

        // Sanity check: the middle/last entries were actually delta-compacted
        // (otherwise this test would trivially pass without exercising
        // `expand_full_path`'s prefix-splicing logic).
        assert_eq!(witness.merkle_paths[1].merkle_paths.len(), 1);
        assert_eq!(witness.merkle_paths[2].merkle_paths.len(), 2);

        let oracle: Vec<Vec<ValueHash>> = witness
            .clone()
            .into_merkle_paths()
            .map(|m| m.merkle_paths.into_iter().map(Into::into).collect())
            .collect();

        let firsts = &witness.merkle_paths[0].merkle_paths;
        let got: Vec<Vec<ValueHash>> = witness
            .merkle_paths
            .iter()
            .map(|m| expand_full_path(firsts, &m.merkle_paths).unwrap())
            .collect();

        assert_eq!(got, oracle);
    }

    #[test]
    fn expand_full_path_rejects_compact_longer_than_first() {
        let first = vec![[1u8; HASH_LEN], [2; HASH_LEN]];
        let too_long = vec![[3u8; HASH_LEN], [4; HASH_LEN], [5; HASH_LEN]];

        let err = expand_full_path(&first, &too_long).unwrap_err();
        assert!(
            err.to_string().contains("malformed"),
            "unexpected error message: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // Differential oracle test for `verify_paths_and_new_root`.
    //
    // The oracle is the exact current three-step production path
    // (`get_bowp` + `generate_tree_instructions` + `BlockOutputWithProofs::
    // verify_proofs` + `root_hash()`); `verify_paths_and_new_root` fuses those
    // into a single streaming pass. On every input the two MUST agree on the
    // returned `(new_root, new_enumeration_index)` and on accept/reject.
    // ---------------------------------------------------------------------
    use anyhow::Context;
    use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
    use zksync_merkle_tree::HashTree;
    use zksync_types::{AccountTreeId, StorageKey, StorageLog, H160, H256};

    use crate::generate_tree_instructions;

    /// Oracle: the exact current three-step path, threaded like the production
    /// caller in `lib.rs` (enum index advances by the number of `Inserted`
    /// leaves; `root_hash()` is `None` when there are no logs).
    fn reference(
        witness: WitnessInputMerklePaths,
        vm_logs: Vec<StorageLog>,
        old_root: ValueHash,
        idx: u64,
    ) -> anyhow::Result<(ValueHash, u64)> {
        let (bowp, leaf_keys) = get_bowp(witness)?;
        let instructions = generate_tree_instructions(idx, &bowp, &leaf_keys, vm_logs)?;
        bowp.verify_proofs(&Blake2Hasher, old_root, &instructions)?;
        let num_insertions = bowp
            .logs
            .iter()
            .filter(|log| matches!(log.base, TreeLogEntry::Inserted))
            .count() as u64;
        let new_root = bowp
            .root_hash()
            .context("root_hash unavailable after verify_proofs")?;
        Ok((new_root, idx + num_insertions))
    }

    /// Run both paths on identical inputs and assert they agree exactly.
    fn assert_equivalent(
        witness: WitnessInputMerklePaths,
        vm_logs: Vec<StorageLog>,
        old_root: ValueHash,
        idx: u64,
    ) {
        let expect = reference(witness.clone(), vm_logs.clone(), old_root, idx);
        let got = verify_paths_and_new_root(witness, vm_logs, &Blake2Hasher, old_root, idx);
        match (expect, got) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "streaming result diverged from oracle"),
            (Err(_), Err(_)) => {}
            (a, b) => panic!("accept/reject diverged: oracle={a:?} streaming={b:?}"),
        }
    }

    fn empty_root() -> ValueHash {
        HashTree::empty_tree_hash(&Blake2Hasher)
    }

    /// A `(leaf_hashed_key, read StorageLog)` pair whose hashed key is
    /// self-consistent (the log's own `hashed_key_u256()`), so key-binding
    /// passes unless deliberately broken.
    fn read_pair(addr: u8, slot: u8, value: H256) -> (U256, StorageLog) {
        let key = StorageKey::new(
            AccountTreeId::new(H160::repeat_byte(addr)),
            H256::repeat_byte(slot),
        );
        (key.hashed_key_u256(), StorageLog::new_read_log(key, value))
    }

    #[allow(clippy::too_many_arguments)]
    fn entry(
        is_write: bool,
        first_write: bool,
        enum_index: u64,
        leaf_hashed_key: U256,
        root: ValueHash,
        value_read: H256,
        paths: Vec<[u8; HASH_LEN]>,
    ) -> StorageLogMetadata {
        StorageLogMetadata {
            root_hash: root.to_fixed_bytes(),
            is_write,
            first_write,
            merkle_paths: paths,
            leaf_hashed_key,
            leaf_enumeration_index: enum_index,
            value_written: [0; HASH_LEN],
            value_read: value_read.to_fixed_bytes(),
        }
    }

    /// Build a witness directly from metadata entries, bypassing
    /// `push_merkle_path`'s delta-compaction. The entries are taken as the
    /// already-stored (compact) form, exactly as the streaming pass and
    /// `into_merkle_paths` consume them. Bypassing lets the malformed-first-path
    /// case construct a state `push_merkle_path` would refuse to build.
    fn witness_of(metas: Vec<StorageLogMetadata>) -> WitnessInputMerklePaths {
        let mut witness = WitnessInputMerklePaths::new(0);
        witness.merkle_paths = metas;
        witness
    }

    // --- Real ACCEPT case: single missing-key read on the empty tree. --------

    #[test]
    fn streaming_matches_oracle_on_missing_key_read() {
        let (key, log) = read_pair(0x11, 0x22, H256::zero());
        // is_write=false, first_write=false, enum_index=0 -> ReadMissingKey.
        // Empty path + empty entry folds to the empty-tree root, and
        // old_root == op.root_hash == empty_tree_hash, so both paths ACCEPT.
        let meta = entry(false, false, 0, key, empty_root(), H256::zero(), vec![]);
        let witness = witness_of(vec![meta]);

        // Prove it is a genuine ACCEPT (not merely a matching reject).
        let got = verify_paths_and_new_root(
            witness.clone(),
            vec![log],
            &Blake2Hasher,
            empty_root(),
            5,
        )
        .expect("missing-key read on empty tree must verify");
        assert_eq!(got, (empty_root(), 5), "root unchanged, enum index unchanged");

        assert_equivalent(witness, vec![log], empty_root(), 5);
    }

    // --- Logic-agreement rejects (both paths Err). ---------------------------

    #[test]
    fn streaming_matches_oracle_on_count_mismatch() {
        let (key, _log) = read_pair(1, 2, H256::zero());
        let meta = entry(false, false, 1, key, empty_root(), H256::zero(), vec![]);
        // One merkle path, zero VM logs.
        assert_equivalent(witness_of(vec![meta]), vec![], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_key_binding_mismatch() {
        // Valid read classification, but leaf_hashed_key != VM key.
        let (_vmkey, log) = read_pair(1, 2, H256::from_low_u64_be(9));
        let meta = entry(
            false,
            false,
            1,
            U256::from(0xdead_beef_u64),
            empty_root(),
            H256::from_low_u64_be(9),
            vec![],
        );
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_read_marked_first_write() {
        // classify rejects: a read flagged first_write.
        let (key, log) = read_pair(3, 4, H256::zero());
        let meta = entry(false, true, 0, key, empty_root(), H256::zero(), vec![]);
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_repeated_write_index_zero() {
        // classify rejects: a repeated write with enumeration index 0.
        let key = StorageKey::new(AccountTreeId::new(H160::repeat_byte(5)), H256::repeat_byte(6));
        let log = StorageLog::new_write_log(key, H256::from_low_u64_be(1));
        let meta = entry(true, false, 0, key.hashed_key_u256(), empty_root(), H256::zero(), vec![]);
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_read_value_mismatch() {
        // map_log_tree rejects: witnessed pre-state value != VM-read value.
        let (vmkey, log) = read_pair(7, 8, H256::from_low_u64_be(3));
        let meta = entry(
            false,
            false,
            1,
            vmkey,
            empty_root(),
            H256::from_low_u64_be(7), // witnessed value_read != VM value (3)
            vec![],
        );
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_corrupted_root_hash() {
        // fold rejects: a read op whose root_hash does not equal the running root.
        let (vmkey, log) = read_pair(9, 10, H256::zero());
        let meta = entry(
            false,
            false,
            0,
            vmkey,
            H256::repeat_byte(0xAB), // corrupted op root
            H256::zero(),
            vec![],
        );
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_wrong_prestate_root() {
        // fold rejects at the prev_hash check: an existing-leaf read whose
        // pre-state (index 1, non-zero value) cannot fold to the empty root.
        let value = H256::from_low_u64_be(77);
        let (vmkey, log) = read_pair(11, 12, value);
        let meta = entry(false, false, 1, vmkey, empty_root(), value, vec![]);
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    // --- Malformed first path: streaming-only (oracle panics). ---------------

    #[test]
    fn streaming_rejects_malformed_first_path() {
        // A later path longer than the first. `into_merkle_paths` (used by the
        // oracle) PANICS on this, so we test the streaming pass alone.
        let (k0, log0) = read_pair(13, 0, H256::zero());
        let (k1, log1) = read_pair(13, 1, H256::zero());
        let m0 = entry(false, false, 0, k0, empty_root(), H256::zero(), vec![]);
        let m1 = entry(false, false, 0, k1, empty_root(), H256::zero(), vec![[1u8; HASH_LEN]]);
        let witness = witness_of(vec![m0, m1]);

        let res = verify_paths_and_new_root(
            witness,
            vec![log0, log1],
            &Blake2Hasher,
            empty_root(),
            0,
        );
        assert!(res.is_err(), "streaming must reject a malformed longer-than-first path");
    }
}
