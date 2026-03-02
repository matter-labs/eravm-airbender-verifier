use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use zksync_types::U256;

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

    /// Converts Merkle paths into a fixed-size array, panicking on length mismatch.
    pub fn into_merkle_paths_array<const PATH_LEN: usize>(self) -> Box<[[u8; HASH_LEN]; PATH_LEN]> {
        let actual_len = self.merkle_paths.len();
        self.merkle_paths.try_into().unwrap_or_else(|_| {
            panic!(
                "Unexpected length of Merkle paths in `StorageLogMetadata`: expected {}, got {}",
                PATH_LEN, actual_len
            );
        })
    }
}

/// Witness data produced by the Merkle tree after processing a single block.
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

    /// Pushes an additional Merkle path in compact form.
    pub fn push_merkle_path(&mut self, mut path: StorageLogMetadata) {
        let Some(first_path) = self.merkle_paths.first() else {
            self.merkle_paths.push(path);
            return;
        };
        assert_eq!(first_path.merkle_paths.len(), path.merkle_paths.len());

        let mut hash_pairs = path.merkle_paths.iter().zip(&first_path.merkle_paths);
        let first_unique_idx =
            hash_pairs.position(|(hash, first_path_hash)| hash != first_path_hash);
        let first_unique_idx = first_unique_idx.unwrap_or(path.merkle_paths.len());
        path.merkle_paths = path.merkle_paths.split_off(first_unique_idx);
        self.merkle_paths.push(path);
    }

    /// Expands compact Merkle paths and returns an iterator over all logs.
    pub fn into_merkle_paths(self) -> impl ExactSizeIterator<Item = StorageLogMetadata> {
        let mut merkle_paths = self.merkle_paths;
        if let [first, rest @ ..] = merkle_paths.as_mut_slice() {
            for path in rest {
                assert!(
                    path.merkle_paths.len() <= first.merkle_paths.len(),
                    "Merkle paths in `WitnessInputMerklePaths` are malformed; the first path is not \
                     the longest one"
                );
                let spliced_len = first.merkle_paths.len() - path.merkle_paths.len();
                let spliced_hashes = &first.merkle_paths[0..spliced_len];
                path.merkle_paths
                    .splice(0..0, spliced_hashes.iter().cloned());
                debug_assert_eq!(path.merkle_paths.len(), first.merkle_paths.len());
            }
        }
        merkle_paths.into_iter()
    }
}
