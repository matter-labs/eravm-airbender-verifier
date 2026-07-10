//! Interpretation of the committed `merkle_paths` witness: classifying each
//! leaf's pre-state, building the pre-batch storage view, and turning the
//! witness into the `BlockOutputWithProofs` the tree fold verifies. Kept out of
//! `lib.rs` (and out of the vendored `merkle_tree` crate, which shouldn't carry
//! verifier policy) so the soundness-relevant leaf-shape rules live in one place.

use anyhow::Result;
use zksync_merkle_tree::{BlockOutputWithProofs, TreeLogEntry, TreeLogEntryWithProof, ValueHash};
use zksync_types::{H256, U256};

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
/// Not yet wired into `get_bowp`/`verify_paths_and_new_root`: it exists so the
/// upcoming streaming pass can expand paths lazily, one at a time, instead of
/// eagerly materializing all of them via `into_merkle_paths`.
#[allow(dead_code)]
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
}
