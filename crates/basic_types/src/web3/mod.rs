//! Selected Web3 types copied from the `web3` crate.
//!
//! The majority of the code is copied verbatim from the `web3` crate 0.19.0,
//! https://github.com/tomusdrw/rust-web3, licensed under the MIT open-source license.
//!
//! TODO(eravm-airbender-verifier): Reintroduce additional web3 types only when
//! a concrete in-tree consumer requires them.

use std::fmt;

use ethabi::ethereum_types::Address;
use serde::{
    de::{Error, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{H160, H256, U256, U64};

pub mod contract;

pub type Index = U64;

// `Signature`, `keccak256`: from `web3::signing`

/// A struct that represents the components of a secp256k1 signature.
#[derive(Debug)]
pub struct Signature {
    /// V component in Electrum format with chain-id replay protection.
    pub v: u64,
    /// R component of the signature.
    pub r: H256,
    /// S component of the signature.
    pub s: H256,
}

#[cfg(target_arch = "riscv32")]
mod keccak_delegate {
    use seq_macro::seq;

    pub const KECCAK_SPECIAL5_STATE_AND_SCRATCH_U64_WORDS: usize = 31;

    #[macro_export]
    macro_rules! keccak_special5_load_initial_control {
        () => {
            core::arch::asm!(
                "add x10, x0, x0",
                out("x10") _,
                options(nostack, preserves_flags)
            )
        };
    }

    #[cfg(target_arch = "riscv32")]
    #[macro_export]
    macro_rules! keccak_special5_invoke {
        ($state: expr) => {
            core::arch::asm!(
                "csrrw x0, 0x7CB, x0",
                in("x11") $state,
                out("x10") _,
                options(nostack, preserves_flags)
            )
        };
    }

    pub(crate) fn keccak_f1600(state: &mut AlignedState) {
        unsafe {
            // start by setting initial control

            let state_ptr = state.0.as_mut_ptr();
            // start by setting initial control
            keccak_special5_load_initial_control!();

            // then run 24 rounds
            seq!(round in 0..24 {
                // iota-theta-rho-chi-nopi: 5 iota_columnxor + 2 columnmix + 5 theta + 5 rho + 5*2 chi
                // control flow is guarded by circuit itself
                seq!(i in 0..27 {
                    keccak_special5_invoke!(state_ptr);
                });
            });

            // then add +1 for the final iota
            keccak_special5_invoke!(state_ptr);
        }
    }

    #[cfg(not(target_endian = "little"))]
    compile_error!("invalid arch - only intended for LE machines");

    pub trait MiniDigest: Sized {
        type HashOutput;

        fn new() -> Self;
        fn digest(input: impl AsRef<[u8]>) -> Self::HashOutput;
        fn update(&mut self, input: impl AsRef<[u8]>);
        fn finalize(self) -> Self::HashOutput;
        fn finalize_reset(&mut self) -> Self::HashOutput;
    }

    // NB: repr(align(256)) ensures that the lowest u16 of the pointer can fully address
    //     all the words without carry, s.t. we can very cheaply offset the ptr in-circuit
    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    #[repr(align(256))]
    pub(crate) struct AlignedState([u64; KECCAK_SPECIAL5_STATE_AND_SCRATCH_U64_WORDS]);

    // NOTE: Sha3 and Keccak differ only in padding, so we can make it generic for free,
    // whether we will need it in practice or not. We also do not use a separate buffer for input,
    // and instead XOR input directly into the state

    const BUFFER_SIZE_U64_WORDS: usize = 17;
    const BUFFER_SIZE_U32_WORDS: usize = BUFFER_SIZE_U64_WORDS * 2;
    const BUFFER_SIZE_BYTES: usize = 17 * core::mem::size_of::<u64>();

    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    pub struct Keccak256Core<const SHA3: bool = false> {
        state: AlignedState,
        filled_bytes: usize,
    }

    #[allow(dead_code)]
    pub type Keccak256 = Keccak256Core<false>;
    #[allow(dead_code)]
    pub type Sha3_256 = Keccak256Core<true>;

    impl<const SHA3: bool> Keccak256Core<SHA3> {
        #[inline(always)]
        unsafe fn absorb_unaligned(&mut self, input: &mut &[u8]) {
            let unalignment = self.filled_bytes % core::mem::size_of::<u32>();
            if unalignment == 0 {
                return;
            }
            let to_absorb: usize =
                core::cmp::min(core::mem::size_of::<u32>() - unalignment, input.len());
            let (slice_to_absorb, rest) = input.split_at_unchecked(to_absorb);
            *input = rest;

            let mut buffer = [0u8; core::mem::size_of::<u32>()];
            let dst = buffer
                .get_unchecked_mut(unalignment..)
                .get_unchecked_mut(..to_absorb);
            core::hint::assert_unchecked(slice_to_absorb.len() == dst.len());
            dst.copy_from_slice(slice_to_absorb);

            let u32_word_idx = self.filled_bytes / core::mem::size_of::<u32>();
            let dst_word = self.state.0.as_mut_ptr().cast::<u32>().add(u32_word_idx);
            dst_word.write(dst_word.read() ^ u32::from_le_bytes(buffer));

            self.filled_bytes += to_absorb;
        }

        #[inline(always)]
        unsafe fn absorb_aligned(&mut self, input: &mut &[u8]) {
            if input.is_empty() {
                return;
            }
            debug_assert_eq!(self.filled_bytes % core::mem::size_of::<u32>(), 0);
            debug_assert_ne!(self.filled_bytes, BUFFER_SIZE_BYTES);
            debug_assert_eq!(
                (BUFFER_SIZE_BYTES - self.filled_bytes) % core::mem::size_of::<u32>(),
                0
            );

            let (u32_chunks, rest) = input.as_chunks::<4>();
            *input = rest;
            let max_words_to_absorb =
                (BUFFER_SIZE_BYTES - self.filled_bytes) / core::mem::size_of::<u32>();

            let words_to_absorb = core::cmp::min(max_words_to_absorb, u32_chunks.len());
            let u32_word_idx = self.filled_bytes / core::mem::size_of::<u32>();

            let mut dst = self.state.0.as_mut_ptr().cast::<u32>().add(u32_word_idx);

            let (fill_to_end_maybe, more) = u32_chunks.split_at_unchecked(words_to_absorb);
            let mut it = fill_to_end_maybe.into_iter();
            for _ in 0..words_to_absorb {
                dst.write(dst.read() ^ u32::from_le_bytes(*it.next().unwrap_unchecked()));
                dst = dst.add(1);
            }
            self.filled_bytes += words_to_absorb * core::mem::size_of::<u32>();
            if self.filled_bytes == BUFFER_SIZE_BYTES {
                self.filled_bytes = 0;
                keccak_f1600(&mut self.state);
            }

            // then as many full fills as possible
            let (full_buffer_fills, partial_fills) = more.as_chunks::<BUFFER_SIZE_U32_WORDS>();
            for src in full_buffer_fills.into_iter() {
                debug_assert_eq!(self.filled_bytes, 0);
                let dst = self
                    .state
                    .0
                    .as_mut_ptr()
                    .cast::<[u32; BUFFER_SIZE_U32_WORDS]>()
                    .as_mut()
                    .unwrap_unchecked();
                core::hint::assert_unchecked(src.len() == dst.len());
                for (src, dst) in src.into_iter().zip(dst.iter_mut()) {
                    *dst ^= u32::from_le_bytes(*src);
                }
                keccak_f1600(&mut self.state);
            }

            // and partial fill again
            let words_to_absorb = partial_fills.len();
            if words_to_absorb > 0 {
                debug_assert_eq!(self.filled_bytes, 0);
            }
            debug_assert!(words_to_absorb < BUFFER_SIZE_U32_WORDS);
            let mut it = partial_fills.into_iter();
            let mut dst = self.state.0.as_mut_ptr().cast::<u32>();
            for _ in 0..words_to_absorb {
                dst.write(dst.read() ^ u32::from_le_bytes(*it.next().unwrap_unchecked()));
                dst = dst.add(1);
            }
            self.filled_bytes += words_to_absorb * core::mem::size_of::<u32>();
            // can not trigger a permutation
        }

        #[inline(always)]
        unsafe fn absorb_tail(&mut self, input: &[u8]) {
            if input.is_empty() {
                return;
            }
            debug_assert!(input.len() < core::mem::size_of::<u32>());
            debug_assert_eq!(self.filled_bytes % core::mem::size_of::<u32>(), 0);
            let to_absorb = input.len();
            let mut buffer = [0u8; core::mem::size_of::<u32>()];
            buffer.get_unchecked_mut(..to_absorb).copy_from_slice(input);
            let u32_word_idx = self.filled_bytes / core::mem::size_of::<u32>();
            let dst = self.state.0.as_mut_ptr().cast::<u32>().add(u32_word_idx);
            dst.write(dst.read() ^ u32::from_le_bytes(buffer));
            self.filled_bytes += to_absorb;
        }
    }

    impl<const SHA3: bool> MiniDigest for Keccak256Core<SHA3> {
        type HashOutput = [u8; 32];

        #[inline(always)]
        fn new() -> Self {
            Self {
                state: AlignedState([0; KECCAK_SPECIAL5_STATE_AND_SCRATCH_U64_WORDS]),
                filled_bytes: 0,
            }
        }

        // #[inline(always)]
        #[inline(never)]
        fn update(&mut self, input: impl AsRef<[u8]>) {
            let mut input = input.as_ref();

            if input.len() == 0 {
                return;
            }

            // NOTE: reading unaligned u64/u32 to XOR bytes with the state is the same as copying it into aligned
            // buffer first and then XORing anyway, so we will do it on the fly

            unsafe {
                self.absorb_unaligned(&mut input);
                if self.filled_bytes == BUFFER_SIZE_BYTES {
                    self.filled_bytes = 0;
                    keccak_f1600(&mut self.state);
                }
                // absorb aligned will permut internellay if needed
                self.absorb_aligned(&mut input);

                // final absorb unaligned can not trigger permutation
                self.absorb_tail(input);

                debug_assert_ne!(self.filled_bytes, BUFFER_SIZE_BYTES);
            };
        }

        #[inline(always)]
        fn finalize(mut self) -> Self::HashOutput {
            keccak_pad::<SHA3>(&mut self.state.0, self.filled_bytes);
            keccak_f1600(&mut self.state);
            unsafe { self.state.0.as_ptr().cast::<[u8; 32]>().read() }
        }

        #[inline(always)]
        fn finalize_reset(&mut self) -> Self::HashOutput {
            keccak_pad::<SHA3>(&mut self.state.0, self.filled_bytes);
            keccak_f1600(&mut self.state);
            let output = unsafe { self.state.0.as_ptr().cast::<[u8; 32]>().read() };
            for dst in self.state.0.iter_mut() {
                *dst = 0;
            }
            self.filled_bytes = 0;

            output
        }

        #[inline(always)]
        fn digest(input: impl AsRef<[u8]>) -> Self::HashOutput {
            let mut hasher = Self::new();
            hasher.update(input);
            hasher.finalize()
        }
    }

    #[allow(dead_code)]
    #[inline(always)]
    fn keccak_pad<const SHA3: bool>(
        state: &mut [u64; KECCAK_SPECIAL5_STATE_AND_SCRATCH_U64_WORDS],
        len_filled_bytes: usize,
    ) {
        let pos_padding_start_u64 = len_filled_bytes / 8;
        let padding_start = {
            let len_leftover_bytes = len_filled_bytes % 8;
            (if SHA3 { 0x06 } else { 0x01 }) << (len_leftover_bytes * 8)
        };
        state[pos_padding_start_u64] ^= padding_start;
        state[16] ^= 0x80000000_00000000; // last bit is always there
    }
}

/// Compute the Keccak-256 hash of input bytes.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    #[cfg(target_arch = "riscv32")]
    {
        use keccak_delegate::{Keccak256, MiniDigest};

        let sha256 = Keccak256::digest(bytes);
        sha256
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        use tiny_keccak::{Hasher, Keccak};

        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(bytes);
        hasher.finalize(&mut output);
        output
    }
}

/// Hashes concatenation of the two provided hashes using `keccak256`.
pub fn keccak256_concat(hash1: H256, hash2: H256) -> H256 {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(hash1.as_bytes());
    bytes[32..].copy_from_slice(hash2.as_bytes());

    H256(keccak256(&bytes))
}

// `Bytes`: from `web3::types::bytes`

/// Raw bytes wrapper.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Bytes(pub Vec<u8>);

impl<T: Into<Vec<u8>>> From<T> for Bytes {
    fn from(data: T) -> Self {
        Bytes(data.into())
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let mut serialized = "0x".to_owned();
            serialized.push_str(&hex::encode(&self.0));
            serializer.serialize_str(serialized.as_ref())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'a> Deserialize<'a> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'a>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_identifier(BytesVisitor)
        } else {
            Vec::<u8>::deserialize(deserializer).map(Bytes)
        }
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let serialized = format!("0x{}", hex::encode(&self.0));
        f.debug_tuple("Bytes").field(&serialized).finish()
    }
}

struct BytesVisitor;

impl<'a> Visitor<'a> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a 0x-prefixed hex-encoded vector of bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if let Some(value) = value.strip_prefix("0x") {
            let bytes =
                hex::decode(value).map_err(|e| Error::custom(format!("Invalid hex: {e}")))?;
            Ok(Bytes(bytes))
        } else {
            Err(Error::invalid_value(Unexpected::Str(value), &"0x prefix"))
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_str(value.as_ref())
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Bytes(value))
    }
}

// `AccessList`, `AccessListItem`: from `web3::types::transaction`

/// Access list.
pub type AccessList = Vec<AccessListItem>;

/// Access list item.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    /// Accessed address.
    pub address: Address,
    /// Accessed storage keys.
    pub storage_keys: Vec<H256>,
}

// `Log`: from `web3::types::log`

/// A log produced by a transaction.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Log {
    /// H160.
    pub address: H160,
    /// Topics.
    pub topics: Vec<H256>,
    /// Data.
    pub data: Bytes,
    /// Block Hash.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<H256>,
    /// Block Number.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<U64>,
    /// Transaction Hash.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<H256>,
    /// Transaction Index.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<Index>,
    /// Log Index in Block.
    #[serde(rename = "logIndex")]
    pub log_index: Option<U256>,
    /// Log Index in Transaction.
    #[serde(rename = "transactionLogIndex")]
    pub transaction_log_index: Option<U256>,
    /// Log Type.
    #[serde(rename = "logType")]
    pub log_type: Option<String>,
    /// Removed.
    pub removed: Option<bool>,
    /// L2 block timestamp.
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: Option<U64>,
}

impl Log {
    /// Returns true if the log has been removed.
    pub fn is_removed(&self) -> bool {
        if let Some(val_removed) = self.removed {
            return val_removed;
        }
        if let Some(val_log_type) = &self.log_type {
            if val_log_type == "removed" {
                return true;
            }
        }
        false
    }
}

impl From<Log> for ethabi::RawLog {
    fn from(log: Log) -> Self {
        ethabi::RawLog {
            topics: log.topics,
            data: log.data.0,
        }
    }
}
