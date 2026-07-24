//! Hashing operations on the Merkle tree.

use std::{fmt, iter, sync::LazyLock};

use zksync_crypto_primitives::hasher::{blake2::Blake2Hasher, Hasher};

pub(crate) use self::nodes::{InternalNodeCache, MerklePath};
pub use self::proofs::TreeRangeDigest;
use crate::{
    metrics::HashingStats,
    types::{TreeEntry, ValueHash, TREE_DEPTH},
};

mod nodes;
mod proofs;

/// Tree hashing functionality.
pub trait HashTree: Send + Sync {
    /// Returns the unique name of the hasher. This is used in Merkle tree tags to ensure
    /// that the tree remains consistent.
    fn name(&self) -> &'static str;

    /// Hashes a leaf node.
    fn hash_leaf(&self, value_hash: &ValueHash, leaf_index: u64) -> ValueHash;
    /// Compresses hashes in an intermediate node of a binary Merkle tree.
    fn hash_branch(&self, lhs: &ValueHash, rhs: &ValueHash) -> ValueHash;

    /// Returns the hash of an empty subtree with the given depth. Implementations
    /// are encouraged to cache the returned values.
    fn empty_subtree_hash(&self, depth: usize) -> ValueHash;

    /// Returns the hash of the empty tree. The default implementation uses [`Self::empty_subtree_hash()`].
    fn empty_tree_hash(&self) -> ValueHash {
        self.empty_subtree_hash(TREE_DEPTH)
    }
}

impl<H: HashTree + ?Sized> HashTree for &H {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    fn hash_leaf(&self, value_hash: &ValueHash, leaf_index: u64) -> ValueHash {
        (**self).hash_leaf(value_hash, leaf_index)
    }

    fn hash_branch(&self, lhs: &ValueHash, rhs: &ValueHash) -> ValueHash {
        (**self).hash_branch(lhs, rhs)
    }

    fn empty_subtree_hash(&self, depth: usize) -> ValueHash {
        (**self).empty_subtree_hash(depth)
    }
}

impl dyn HashTree + '_ {
    /// Extends the provided `path` to length `TREE_DEPTH`.
    fn extend_merkle_path<'a>(
        &'a self,
        path: &'a [ValueHash],
    ) -> impl Iterator<Item = ValueHash> + 'a {
        let empty_hash_count = TREE_DEPTH - path.len();
        let empty_hashes = (0..empty_hash_count).map(|depth| self.empty_subtree_hash(depth));
        empty_hashes.chain(path.iter().copied())
    }

    /// Folds a Merkle path (as returned in [`TreeEntryWithProof`](crate::TreeEntryWithProof) /
    /// [`TreeLogEntryWithProof`](crate::TreeLogEntryWithProof)) together with the leaf `entry`
    /// into the resulting root hash. `path` may be shorter than [`TREE_DEPTH`]; it is extended
    /// with empty-subtree hashes as necessary.
    pub fn fold_merkle_path(&self, path: &[ValueHash], entry: TreeEntry) -> ValueHash {
        let mut hash = self.hash_leaf(&entry.value, entry.leaf_index);
        let full_path = self.extend_merkle_path(path);
        for (depth, adjacent_hash) in full_path.enumerate() {
            hash = if entry.key.bit(depth) {
                self.hash_branch(&adjacent_hash, &hash)
            } else {
                self.hash_branch(&hash, &adjacent_hash)
            };
        }
        hash
    }

    pub(crate) fn with_stats<'a>(&'a self, stats: &'a HashingStats) -> HasherWithStats<'a> {
        HasherWithStats {
            shared_metrics: Some(stats),
            ..HasherWithStats::new(self)
        }
    }
}

/// Fused blake2s Merkle-path fold, byte-for-byte identical to
/// `Blake2Hasher::fold_merkle_path` but far cheaper per level.
///
/// The generic fold re-inits a hasher and marshals both 32-byte operands into a
/// fresh block every level. Instead we drive airbender-crypto's
/// [`Blake2sPathHasher`](airbender_crypto::Blake2sPathHasher), which wraps the
/// blake2s delegation's fused two-to-one `compress_node` primitive: the running
/// hash stays in the evaluator across levels, so each level marshals only the
/// 32-byte sibling and issues one delegated compression. The delegated hash and
/// its inputs are unchanged, so the root is identical — this only removes the
/// on-budget marshalling glue.
///
/// The seed is `blake2s(leaf_index_be(8) || value(32))`, matching
/// `Blake2Hasher::hash_leaf`; each fold takes `sibling_on_left = key.bit(depth)`,
/// matching the `sibling || node` vs `node || sibling` branch of the generic
/// fold. Correctness is pinned by the differential tests below and the
/// streaming/oracle tests, which fold every witness both ways and compare
/// byte-for-byte.
///
/// # Panics
///
/// Panics if `path.len() > TREE_DEPTH` (a malformed proof); callers bound the
/// expanded path to `TREE_DEPTH` before folding.
pub fn blake2_fold_merkle_path(path: &[ValueHash], entry: TreeEntry) -> ValueHash {
    use airbender_crypto::blake2s::Blake2sPathHasher;

    assert!(
        path.len() <= TREE_DEPTH,
        "Merkle path longer than TREE_DEPTH"
    );

    // Leaf hash: blake2s( leaf_index.to_be_bytes() (8) || value (32) ), exactly
    // as `Blake2Hasher::hash_leaf`.
    let mut leaf_input = [0u8; 40];
    leaf_input[..8].copy_from_slice(&entry.leaf_index.to_be_bytes());
    leaf_input[8..].copy_from_slice(entry.value.as_bytes());
    let mut hasher = Blake2sPathHasher::from_single_block(&leaf_input);

    // `extend_merkle_path` fills the missing (top) levels with empty-subtree
    // hashes, so level `depth < empty_count` uses `empty_subtree_hash(depth)` and
    // the rest walk `path` in order — identical adjacency to the generic fold.
    let empty_count = TREE_DEPTH - path.len();
    for depth in 0..TREE_DEPTH {
        let sibling = if depth < empty_count {
            HashTree::empty_subtree_hash(&Blake2Hasher, depth)
        } else {
            path[depth - empty_count]
        };
        // `key.bit(depth)` set => the current node is the right child, i.e. the
        // sibling is on the left => `blake2s(sibling || running)`.
        hasher.fold(sibling.as_fixed_bytes(), entry.key.bit(depth));
    }

    ValueHash::from(hasher.finalize())
}

impl fmt::Debug for dyn HashTree + '_ {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HashTree").finish_non_exhaustive()
    }
}

/// No-op hasher that returns `H256::zero()` for all operations.
impl HashTree for () {
    fn name(&self) -> &'static str {
        "no_op256"
    }

    fn hash_leaf(&self, _value_hash: &ValueHash, _leaf_index: u64) -> ValueHash {
        ValueHash::zero()
    }

    fn hash_branch(&self, _lhs: &ValueHash, _rhs: &ValueHash) -> ValueHash {
        ValueHash::zero()
    }

    fn empty_subtree_hash(&self, _depth: usize) -> ValueHash {
        ValueHash::zero()
    }
}

impl HashTree for Blake2Hasher {
    fn name(&self) -> &'static str {
        "blake2s256"
    }

    fn hash_leaf(&self, value_hash: &ValueHash, leaf_index: u64) -> ValueHash {
        let mut bytes = [0_u8; 40];
        bytes[..8].copy_from_slice(&leaf_index.to_be_bytes());
        bytes[8..].copy_from_slice(value_hash.as_ref());
        self.hash_bytes(&bytes)
    }

    /// Compresses the hashes of 2 children in a branch node.
    fn hash_branch(&self, lhs: &ValueHash, rhs: &ValueHash) -> ValueHash {
        self.compress(lhs, rhs)
    }

    /// Returns the hash of an empty subtree with the given depth.
    fn empty_subtree_hash(&self, depth: usize) -> ValueHash {
        static EMPTY_TREE_HASHES: LazyLock<Vec<ValueHash>> =
            LazyLock::new(compute_empty_tree_hashes);
        EMPTY_TREE_HASHES[depth]
    }
}

fn compute_empty_tree_hashes() -> Vec<ValueHash> {
    let empty_leaf_hash = Blake2Hasher.hash_bytes(&[0_u8; 40]);
    iter::successors(Some(empty_leaf_hash), |hash| {
        Some(Blake2Hasher.hash_branch(hash, hash))
    })
    .take(TREE_DEPTH + 1)
    .collect()
}

/// Hasher that keeps track of hashing metrics.
///
/// On drop, the metrics are merged into `shared_stats` (if present). Such roundabout handling
/// is motivated by efficiency; if atomics were to be used to track metrics (e.g.,
/// via a wrapping `HashTree` implementation), this would tank performance because of contention.
#[derive(Debug)]
pub(crate) struct HasherWithStats<'a> {
    inner: &'a dyn HashTree,
    shared_metrics: Option<&'a HashingStats>,
    local_hashed_bytes: u64,
}

impl<'a> HasherWithStats<'a> {
    pub fn new(inner: &'a dyn HashTree) -> Self {
        Self {
            inner,
            shared_metrics: None,
            local_hashed_bytes: 0,
        }
    }
}

impl<'a> AsRef<dyn HashTree + 'a> for HasherWithStats<'a> {
    fn as_ref(&self) -> &(dyn HashTree + 'a) {
        self.inner
    }
}

impl Drop for HasherWithStats<'_> {
    fn drop(&mut self) {
        if let Some(shared_stats) = self.shared_metrics {
            shared_stats.add_hashed_bytes(self.local_hashed_bytes);
        }
    }
}

impl HasherWithStats<'_> {
    fn hash_leaf(&mut self, value_hash: &ValueHash, leaf_index: u64) -> ValueHash {
        const HASHED_BYTES: u64 = 8 + ValueHash::len_bytes() as u64;

        self.local_hashed_bytes += HASHED_BYTES;
        self.inner.hash_leaf(value_hash, leaf_index)
    }

    fn hash_branch(&mut self, lhs: &ValueHash, rhs: &ValueHash) -> ValueHash {
        const HASHED_BYTES: u64 = 2 * ValueHash::len_bytes() as u64;

        self.local_hashed_bytes += HASHED_BYTES;
        self.inner.hash_branch(lhs, rhs)
    }

    fn hash_optional_branch(
        &mut self,
        subtree_depth: usize,
        lhs: Option<ValueHash>,
        rhs: Option<ValueHash>,
    ) -> Option<ValueHash> {
        match (lhs, rhs) {
            (None, None) => None,
            (Some(lhs), None) => {
                let empty_hash = self.empty_subtree_hash(subtree_depth);
                Some(self.hash_branch(&lhs, &empty_hash))
            }
            (None, Some(rhs)) => {
                let empty_hash = self.empty_subtree_hash(subtree_depth);
                Some(self.hash_branch(&empty_hash, &rhs))
            }
            (Some(lhs), Some(rhs)) => Some(self.hash_branch(&lhs, &rhs)),
        }
    }

    pub fn empty_subtree_hash(&self, depth: usize) -> ValueHash {
        self.inner.empty_subtree_hash(depth)
    }
}

#[cfg(test)]
mod fused_fold_tests {
    use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
    use zksync_types::{H256, U256};

    use super::{blake2_fold_merkle_path, HashTree};
    use crate::types::{TreeEntry, ValueHash, TREE_DEPTH};

    /// The fused `compress_node` fold must produce byte-identical roots to the
    /// generic `Blake2Hasher::fold_merkle_path` for every (key, value, index,
    /// path-length) shape, including full paths, short (empty-topped) paths, and
    /// empty leaves.
    fn assert_same(key: U256, value: ValueHash, leaf_index: u64, path: &[ValueHash]) {
        let entry = TreeEntry {
            key,
            value,
            leaf_index,
        };
        let generic = (&Blake2Hasher as &dyn HashTree).fold_merkle_path(path, entry);
        let fused = blake2_fold_merkle_path(path, entry);
        assert_eq!(generic, fused, "fused fold diverged from generic fold");
    }

    fn path_of(len: usize, seed: u8) -> Vec<ValueHash> {
        (0..len)
            .map(|i| {
                H256::repeat_byte(
                    seed.wrapping_add(i.to_le_bytes()[0])
                        .wrapping_mul(7)
                        .wrapping_add(1),
                )
            })
            .collect()
    }

    #[test]
    fn matches_generic_full_path() {
        assert_same(
            U256::from_big_endian(&[0xA5; 32]),
            H256::repeat_byte(0x3C),
            42,
            &path_of(TREE_DEPTH, 1),
        );
    }

    #[test]
    fn matches_generic_short_and_empty_paths() {
        for len in [0usize, 1, 5, 200, TREE_DEPTH - 1, TREE_DEPTH] {
            // varied keys to exercise every direction bit
            assert_same(U256::zero(), H256::zero(), 0, &path_of(len, 9)); // empty leaf
            assert_same(
                U256::MAX,
                H256::repeat_byte(0xFF),
                u64::MAX,
                &path_of(len, 17),
            );
            assert_same(
                U256::from(0xdead_beef_u64),
                H256::repeat_byte(0x11),
                7,
                &path_of(len, 33),
            );
        }
    }
}
