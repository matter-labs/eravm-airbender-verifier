//! Native peak-live-heap measurement of the verifier's `verify()`, per batch.
//!
//! Wraps the global allocator with a high-water tracker and runs the *native*
//! `verify()` (the same computation the guest performs) on each batch, printing
//! the peak simultaneously-live heap in bytes as CSV:
//!
//!   batch_number,native_peak_bytes
//!
//! This is the fast, many-batch signal for calibrating the RAM estimator. It is
//! a *proxy* for the in-guest peak, and a lower bound: the 32-bit guest packs
//! pointers/usizes smaller, but talc fragmentation + transient realloc doubling
//! push the true guest peak higher. Anchor the native→guest scale with
//! `scripts/probe_guest_memory.sh` (exact in-guest peak via a heap sweep).
//!
//! Usage (point at a dir holding the real <number>.bin[.gz] corpus):
//!   cargo run --release -p eravm-prover-host --example mem_peak -- \
//!       <batches-dir> [batch-file ...]
//! With no batch files listed, every batch in the directory is measured.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use zksync_airbender_verifier::Verify;
use zksync_cli_utils::{load_batch, resolve_batch_inputs};

/// Live bytes currently allocated, and the running high-water mark. Relaxed is
/// fine: we only need a correct max, and `verify()` on the host is effectively
/// single-threaded for allocation purposes.
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct TrackingAlloc;

// SAFETY: delegates every operation to the System allocator; the atomics only
// observe sizes and never affect the returned pointers. The `realloc` default
// trait method routes through this type's `alloc`/`dealloc`, so growth is
// tracked without an explicit override.
unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOC: TrackingAlloc = TrackingAlloc;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let batches_dir = PathBuf::from(
        args.next()
            .context("usage: mem_peak <batches-dir> [batch-file ...]")?,
    )
    .canonicalize()
    .context("canonicalizing batches dir")?;

    let batch_files: Vec<PathBuf> = args.map(PathBuf::from).collect();
    let (files, all) = if batch_files.is_empty() {
        (None, true)
    } else {
        (Some(batch_files.as_slice()), false)
    };
    let inputs =
        resolve_batch_inputs(&batches_dir, files, all).context("resolving batch inputs")?;

    // CSV to stdout; progress/errors to stderr so a redirect captures clean data.
    println!("batch_number,native_peak_bytes");
    for bi in inputs {
        eprintln!("[mem_peak] batch {} ...", bi.number);
        let input = load_batch(&bi).with_context(|| format!("loading batch {}", bi.number))?;

        // Reset the high-water mark to the current live total: the decoded input
        // is already resident and stays live through verify(), so the peak we
        // record is the max *total* simultaneously-live heap (input + working
        // set) — exactly the quantity that must fit the guest heap.
        PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);

        let _result = input
            .verify()
            .with_context(|| format!("native verify() failed for batch {}", bi.number))?;

        let peak = PEAK.load(Ordering::Relaxed);
        println!("{},{}", bi.number, peak);
    }
    Ok(())
}
