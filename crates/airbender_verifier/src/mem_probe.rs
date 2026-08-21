//! Heap-probe hooks for the memory benchmarking tools, compiled only under the
//! `mem-markers` feature (off by default — see `docs/benchmarking.md`).
//!
//! The verifier must fit a bounded guest heap, so what matters is *peak
//! simultaneously-live* bytes and which phase of `execute()` creates that peak.
//! This module holds the counters; an external `#[global_allocator]` in the
//! benchmarking example updates them, and `checkpoint()` prints a labeled sample.
//! Keeping the counters here rather than in the example is what lets `execute()`
//! itself report at phase boundaries — the only way to attribute peak to a phase.
//!
//! Purely observational: no allocation behavior changes and nothing here is
//! reachable in a default build. Unlike `cycle-markers`, this leaves the proved
//! guest untouched in every configuration, because every tool that drives it runs
//! natively on the host.
use core::sync::atomic::{AtomicUsize, Ordering};

/// Bytes currently live, as counted by the driving global allocator.
pub static LIVE: AtomicUsize = AtomicUsize::new(0);
/// High-water mark of `LIVE`, or of whatever footprint metric the driver stores.
pub static PEAK: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub fn on_alloc(n: usize) {
    let now = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

#[inline]
pub fn on_dealloc(n: usize) {
    LIVE.fetch_sub(n, Ordering::Relaxed);
}

/// Print the current live heap and running high-water mark at `label`.
///
/// Writes to stderr so a run's CSV on stdout stays clean.
pub fn checkpoint(label: &str) {
    let live = LIVE.load(Ordering::Relaxed);
    let peak = PEAK.load(Ordering::Relaxed);
    eprintln!(
        "[mem] {label:<34} live={:>7.1} MiB   peak={:>7.1} MiB",
        live as f64 / (1024.0 * 1024.0),
        peak as f64 / (1024.0 * 1024.0),
    );
}
