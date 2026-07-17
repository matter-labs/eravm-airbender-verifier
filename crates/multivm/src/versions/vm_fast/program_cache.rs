//! Bounded cache of decoded [`Program`]s used by the fast VM's `World::decommit`
//! (see `world.rs`).
//!
//! `decommit` previously inserted every distinct decommitted bytecode into an
//! unbounded `HashMap` and never evicted. A transaction that far-calls many
//! distinct cold contracts could therefore pin gigabytes of decoded programs
//! (each program holds `instructions` + `code_page`, roughly 2.5x the bytecode
//! size) in the guest heap and exhaust it — an unrecoverable OOM for a priority
//! transaction that cannot be skipped.
//!
//! Re-decoding a program from its bytecode is deterministic, so evicting a cached
//! program and rebuilding it on a later access is observably equivalent: the cache
//! is a pure host-side optimization and never affects the commitment. This lets us
//! bound it with a simple byte-capped cache without any protocol change.
//!
//! Design notes:
//! - System-contract programs (default-AA / EVM-emulator) handed to
//!   [`ProgramCache::new`] are *pinned* — always hot, consensus-critical, few in
//!   number — so they are never evicted and never counted against the cap.
//! - Pinned and evictable programs share one `HashMap` so a cache hit is a single
//!   lookup, matching the pre-existing unbounded-`HashMap` hit cost (`decommit`
//!   runs on every far call, i.e. thousands of times per batch).
//! - Eviction is **FIFO** (oldest inserted first), deliberately not strict LRU: a
//!   per-hit recency update would cost more than it saves here — a legitimate
//!   batch's working set fits under the cap and never evicts, while a flooding
//!   attacker decommits each cold contract once, so recency carries no information
//!   FIFO lacks.

use std::collections::{HashMap, VecDeque};

use zksync_types::U256;
use zksync_vm2::Program;

/// Byte budget for the evictable portion of the cache, counted in *bytecode*
/// (code-page) bytes. A decoded program's real footprint is larger — the
/// `instructions` array roughly doubles it — so the actual resident memory is on
/// the order of 2.5x this value.
///
/// Sized well above the distinct-bytecode working set of any legitimate batch so
/// honest workloads never evict (and never pay a re-decode), while still bounding
/// an adversary that decommits many distinct cold contracts.
pub(super) const PROGRAM_CACHE_CAP_BYTES: usize = 64 << 20; // 64 MiB of bytecode

/// A pinned + byte-bounded (FIFO) cache of decoded programs keyed by bytecode hash.
pub(super) struct ProgramCache<T, W> {
    /// All cached programs, pinned and evictable alike (see [`CacheEntry::evictable_bytes`]).
    entries: HashMap<U256, CacheEntry<T, W>>,
    /// Insertion order of *evictable* keys; the front is the oldest (next to evict).
    fifo: VecDeque<U256>,
    /// Running sum of evictable entries' byte sizes.
    evictable_bytes: usize,
    cap_bytes: usize,
}

struct CacheEntry<T, W> {
    program: Program<T, W>,
    /// `Some(bytes)` for an evictable entry (its code-page byte size, the eviction
    /// accounting unit); `None` for a pinned entry.
    evictable_bytes: Option<usize>,
}

impl<T, W> ProgramCache<T, W> {
    /// Builds a cache whose `pinned` programs are never evicted.
    pub(super) fn new(pinned: HashMap<U256, Program<T, W>>, cap_bytes: usize) -> Self {
        let entries = pinned
            .into_iter()
            .map(|(hash, program)| {
                (
                    hash,
                    CacheEntry {
                        program,
                        evictable_bytes: None,
                    },
                )
            })
            .collect();
        Self {
            entries,
            fifo: VecDeque::new(),
            evictable_bytes: 0,
            cap_bytes,
        }
    }

    /// Returns a clone of the cached program for `hash`, or `None` if it is not
    /// cached. A single map lookup — this runs on every far call.
    pub(super) fn get(&self, hash: U256) -> Option<Program<T, W>> {
        self.entries.get(&hash).map(|entry| entry.program.clone())
    }

    /// Caches `program` under `hash` as an evictable entry, evicting oldest entries
    /// until the evictable footprint is back within `cap_bytes`.
    ///
    /// No-op if `hash` is already present (pinned or cached); callers only `insert`
    /// on a miss, and the guard keeps `fifo`/`evictable_bytes` consistent regardless.
    pub(super) fn insert(&mut self, hash: U256, program: Program<T, W>) {
        if self.entries.contains_key(&hash) {
            return;
        }
        let bytes = program_bytes(&program);
        self.entries.insert(
            hash,
            CacheEntry {
                program,
                evictable_bytes: Some(bytes),
            },
        );
        self.fifo.push_back(hash);
        self.evictable_bytes += bytes;
        self.evict_to_cap();
    }

    /// Evict oldest-inserted evictable entries until within the byte cap.
    fn evict_to_cap(&mut self) {
        while self.evictable_bytes > self.cap_bytes {
            let Some(hash) = self.fifo.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&hash) {
                // `fifo` only ever holds evictable keys.
                self.evictable_bytes -= entry.evictable_bytes.unwrap_or(0);
            }
        }
    }
}

/// Bytecode (code-page) bytes of a decoded program — the eviction accounting unit.
fn program_bytes<T, W>(program: &Program<T, W>) -> usize {
    program.code_page().len() * 32
}

impl<T, W> std::fmt::Debug for ProgramCache<T, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgramCache")
            .field("entries", &self.entries.len())
            .field("evictable_bytes", &self.evictable_bytes)
            .field("cap_bytes", &self.cap_bytes)
            .finish()
    }
}
