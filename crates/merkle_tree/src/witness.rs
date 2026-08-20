use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_types::U256;

use crate::{
    hasher::{empty_subtree_prefix_len, HashTree},
    types::TREE_DEPTH,
};

const HASH_LEN: usize = 32;

/// Metadata emitted by the Merkle tree after processing a single storage log.
#[allow(missing_docs)]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageLogMetadata {
    #[serde_as(as = "Bytes")]
    pub root_hash: [u8; HASH_LEN],
    pub is_write: bool,
    pub first_write: bool,
    #[serde_as(as = "Vec<Bytes>")]
    pub merkle_paths: Vec<[u8; HASH_LEN]>,
    pub leaf_hashed_key: U256,
    pub leaf_enumeration_index: u64,
    // **NB.** For compatibility reasons, `#[serde_as(as = "Bytes")]` attributes are not added below.
    pub value_written: [u8; HASH_LEN],
    pub value_read: [u8; HASH_LEN],
}

impl StorageLogMetadata {
    /// Returns `leaf_hashed_key` as a fixed-size little-endian byte array.
    pub fn leaf_hashed_key_array(&self) -> [u8; HASH_LEN] {
        let mut result = [0_u8; HASH_LEN];
        self.leaf_hashed_key.to_little_endian(&mut result);
        result
    }

    /// Converts Merkle paths into a fixed-size array.
    ///
    /// Call this on entries produced by
    /// [`WitnessInputMerklePaths::into_merkle_paths()`], which restores the full
    /// `TREE_DEPTH` form; the *stored* form of an entry is truncated to its own
    /// populated depth and will not match `PATH_LEN`.
    ///
    /// # Panics
    ///
    /// Panics if the stored Merkle path length differs from `PATH_LEN`.
    pub fn into_merkle_paths_array<const PATH_LEN: usize>(self) -> Box<[[u8; HASH_LEN]; PATH_LEN]> {
        let actual_len = self.merkle_paths.len();
        self.merkle_paths.try_into().unwrap_or_else(|_| {
            panic!(
                "Unexpected length of Merkle paths in `StorageLogMetadata`: expected {PATH_LEN}, got {actual_len}"
            );
        })
    }
}

/// Witness data produced by the Merkle tree after processing a single block.
///
/// # Stored path form
///
/// Each entry stores its path truncated to its own populated depth, omitting the
/// leading `empty_subtree_hash` run the fold regenerates for any path shorter than
/// [`TREE_DEPTH`]. [`Self::into_merkle_paths()`] restores the full form.
///
/// This replaces a scheme that padded to `TREE_DEPTH` and delta-compacted against
/// the **first** stored path, charging every entry `max(depth(first), depth(i))` —
/// so one leaf planted next to entry 0's key inflated the whole witness. The
/// per-path form has no cross-entry coupling and is never larger.
///
/// `into_merkle_paths` decodes both forms: for distinct keys the old encoder's
/// stripped prefix *was* this constant run, since at index
/// `TREE_DEPTH - max(depth(first), depth(i))` exactly one side is a real subtree
/// hash. The exception is an entry stored as an *empty* vec (path byte-identical to
/// entry 0's), which here means depth 0 instead; the verifier resolves that at fold
/// time — see `merkle_witness::stored_path_for`.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessInputMerklePaths {
    pub merkle_paths: Vec<StorageLogMetadata>,
    pub(crate) next_enumeration_index: u64,
}

impl WitnessInputMerklePaths {
    /// Creates a new witness with the specified leaf index and no paths.
    pub fn new(next_enumeration_index: u64) -> Self {
        Self {
            merkle_paths: vec![],
            next_enumeration_index,
        }
    }

    /// Returns the next leaf index at the beginning of the block.
    pub fn next_enumeration_index(&self) -> u64 {
        self.next_enumeration_index
    }

    /// Reserves additional capacity for Merkle paths.
    pub fn reserve(&mut self, additional_capacity: usize) {
        self.merkle_paths.reserve(additional_capacity);
    }

    /// Pushes a path, stored truncated to its own populated depth.
    ///
    /// Accepts either the tree's own truncated path or a `TREE_DEPTH`-padded one —
    /// the empty-subtree run is stripped either way, so the stored form is
    /// canonical and the call idempotent. Never inspects other entries, so no
    /// entry can inflate another's stored length.
    pub fn push_merkle_path(&mut self, mut path: StorageLogMetadata) {
        let empty_prefix = empty_subtree_prefix_len(&path.merkle_paths);
        if empty_prefix > 0 {
            path.merkle_paths.drain(..empty_prefix);
            path.merkle_paths.shrink_to_fit();
        }
        self.merkle_paths.push(path);
    }

    /// Drops the redundant leading empty-subtree hashes from every stored path;
    /// returns the number of hashes reclaimed.
    ///
    /// Fold-invariant (see [`empty_subtree_prefix_len`]), so it cannot change any
    /// accept/reject decision — a pure memory reclaim. This is what normalises a
    /// witness received in the legacy `max(first_depth, own_depth)` form, whose
    /// surplus prefix is exactly such a run. Idempotent.
    pub fn trim_empty_prefixes(&mut self) -> usize {
        let mut reclaimed = 0;
        for log in &mut self.merkle_paths {
            let empty_prefix = empty_subtree_prefix_len(&log.merkle_paths);
            if empty_prefix > 0 {
                log.merkle_paths.drain(..empty_prefix);
                log.merkle_paths.shrink_to_fit();
                reclaimed += empty_prefix;
            }
        }
        reclaimed
    }

    /// Expands every stored path to its full [`TREE_DEPTH`] form.
    ///
    /// Prefixes each with the canonical empty-subtree hashes for the levels it
    /// omits — the constants a fold would substitute — which also decodes the
    /// legacy delta form (see the type docs). Over-long paths pass through
    /// unchanged for the caller's length check to reject.
    pub fn into_merkle_paths(self) -> impl ExactSizeIterator<Item = StorageLogMetadata> {
        self.merkle_paths.into_iter().map(|mut log| {
            let missing = TREE_DEPTH.saturating_sub(log.merkle_paths.len());
            if missing > 0 {
                log.merkle_paths.splice(
                    0..0,
                    (0..missing).map(|depth| Blake2Hasher.empty_subtree_hash(depth).0),
                );
            }
            log
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(depth: usize) -> [u8; HASH_LEN] {
        Blake2Hasher.empty_subtree_hash(depth).0
    }

    /// A `TREE_DEPTH`-padded path whose populated (non-empty) depth is `d`, i.e.
    /// exactly what the tree + the old `domain.rs` padding produced.
    fn padded(d: usize, tag: u8) -> Vec<[u8; HASH_LEN]> {
        let mut path: Vec<_> = (0..TREE_DEPTH - d).map(empty).collect();
        // Sibling hashes of non-empty subtrees; `| 0x80` keeps them clear of the
        // empty constants (a match would be a blake2s collision).
        let mut byte = tag;
        path.extend(
            std::iter::repeat_with(|| {
                byte = byte.wrapping_add(37);
                [byte | 0x80; HASH_LEN]
            })
            .take(d),
        );
        path
    }

    fn meta(merkle_paths: Vec<[u8; HASH_LEN]>) -> StorageLogMetadata {
        StorageLogMetadata {
            root_hash: [0; HASH_LEN],
            is_write: false,
            first_write: false,
            merkle_paths,
            leaf_hashed_key: U256::zero(),
            leaf_enumeration_index: 0,
            value_written: [0; HASH_LEN],
            value_read: [0; HASH_LEN],
        }
    }

    /// Depths chosen so the first entry is *deeper* than the second — the shape
    /// the old delta format charged every later entry for.
    const DEPTHS: [usize; 4] = [24, 9, 40, 11];
    /// One distinct sibling-byte seed per entry, so no two paths collide.
    const TAGS: [u8; 4] = [17, 34, 51, 68];

    fn padded_paths() -> Vec<Vec<[u8; HASH_LEN]>> {
        DEPTHS
            .iter()
            .zip(TAGS)
            .map(|(&d, tag)| padded(d, tag))
            .collect()
    }

    #[test]
    fn stored_form_is_each_paths_own_depth() {
        let mut witness = WitnessInputMerklePaths::new(1);
        for path in padded_paths() {
            witness.push_merkle_path(meta(path));
        }

        let stored: Vec<_> = witness
            .merkle_paths
            .iter()
            .map(|m| m.merkle_paths.len())
            .collect();
        assert_eq!(stored, DEPTHS);
        // The old delta scheme would have stored `[TREE_DEPTH, 24, 40, 24]` here:
        // entry 0 uncompacted and every later entry floored at entry 0's depth.
        let legacy_total: usize =
            TREE_DEPTH + DEPTHS[1..].iter().map(|&d| d.max(DEPTHS[0])).sum::<usize>();
        assert!(stored.iter().sum::<usize>() < legacy_total);
    }

    #[test]
    fn into_merkle_paths_restores_the_padded_form() {
        let paths = padded_paths();
        let mut witness = WitnessInputMerklePaths::new(1);
        for path in paths.clone() {
            witness.push_merkle_path(meta(path));
        }

        let restored: Vec<_> = witness
            .into_merkle_paths()
            .map(|m| m.merkle_paths)
            .collect();
        assert_eq!(restored, paths);
    }

    /// The load-bearing compatibility property: a witness serialised in the
    /// legacy delta-compacted form decodes to exactly the same full paths, so a
    /// reader can be upgraded before (or without) the producer.
    #[test]
    fn into_merkle_paths_decodes_the_legacy_delta_form() {
        let paths = padded_paths();
        // Rebuild what the old `push_merkle_path` would have stored: entry 0 full,
        // entry i>0 truncated to its shared-prefix boundary with entry 0, which is
        // always `max(depth_0, depth_i)` hashes.
        let mut legacy = WitnessInputMerklePaths::new(1);
        legacy.merkle_paths.push(meta(paths[0].clone()));
        for (path, &depth) in paths.iter().zip(&DEPTHS).skip(1) {
            let stored_len = depth.max(DEPTHS[0]);
            legacy
                .merkle_paths
                .push(meta(path[TREE_DEPTH - stored_len..].to_vec()));
        }

        let restored: Vec<_> = legacy.into_merkle_paths().map(|m| m.merkle_paths).collect();
        assert_eq!(restored, paths);
    }

    #[test]
    fn trim_empty_prefixes_normalises_the_legacy_form_and_is_idempotent() {
        let paths = padded_paths();
        // The real legacy shape: entry 0 padded to TREE_DEPTH, every later entry
        // cut to `max(depth_0, depth_i)` — i.e. *partially* stripped, so the
        // surplus sits at depths `TREE_DEPTH - stored_len ..`, not at depth 0.
        let mut legacy = WitnessInputMerklePaths::new(1);
        legacy.merkle_paths.push(meta(paths[0].clone()));
        let mut surplus = TREE_DEPTH - DEPTHS[0];
        for (path, &depth) in paths.iter().zip(&DEPTHS).skip(1) {
            let stored_len = depth.max(DEPTHS[0]);
            surplus += stored_len - depth;
            legacy
                .merkle_paths
                .push(meta(path[TREE_DEPTH - stored_len..].to_vec()));
        }

        let reclaimed = legacy.trim_empty_prefixes();
        assert_eq!(reclaimed, surplus);
        // The point of the trim is to give the memory BACK, not just to shorten
        // `len`: `drain` alone leaves the original allocation intact. Assert the
        // capacity actually shrank, or a dropped `shrink_to_fit` would silently
        // turn this into a no-op with every test still green.
        for log in &legacy.merkle_paths {
            assert_eq!(
                log.merkle_paths.capacity(),
                log.merkle_paths.len(),
                "trim must release the surplus allocation, not just shorten len"
            );
        }
        let stored: Vec<_> = legacy
            .merkle_paths
            .iter()
            .map(|m| m.merkle_paths.len())
            .collect();
        assert_eq!(stored, DEPTHS);
        // Idempotent, and it did not lose information: the full form still comes back.
        let mut again = legacy.clone();
        assert_eq!(again.trim_empty_prefixes(), 0);
        assert_eq!(
            legacy
                .into_merkle_paths()
                .map(|m| m.merkle_paths)
                .collect::<Vec<_>>(),
            paths
        );
    }

    /// An over-long path is passed through untouched for the caller's length
    /// bound to reject, rather than panicking or silently truncating.
    #[test]
    fn over_long_paths_are_passed_through() {
        let long = vec![[0xAB; HASH_LEN]; TREE_DEPTH + 5];
        let mut witness = WitnessInputMerklePaths::new(1);
        witness.merkle_paths.push(meta(long.clone()));
        let restored: Vec<_> = witness
            .into_merkle_paths()
            .map(|m| m.merkle_paths)
            .collect();
        assert_eq!(restored, vec![long]);
    }
}
