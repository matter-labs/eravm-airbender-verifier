//! Interpretation of the committed `merkle_paths` witness: classifying each
//! leaf's pre-state, building the pre-batch storage view, and turning the
//! witness into the `BlockOutputWithProofs` the tree fold verifies. Kept out of
//! `lib.rs` (and out of the vendored `merkle_tree` crate, which shouldn't carry
//! verifier policy) so the soundness-relevant leaf-shape rules live in one place.

use anyhow::Result;
use zksync_merkle_tree::{BlockOutputWithProofs, TreeLogEntry, TreeLogEntryWithProof};
use zksync_types::{H256, U256};

use crate::types::{StorageLogMetadata, WitnessInputMerklePaths};

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
