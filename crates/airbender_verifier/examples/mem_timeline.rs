//! Native per-phase live-heap timeline for one batch. Requires
//! `--features mem-markers`.
//!
//!   cargo run --release -p zksync_airbender_verifier --example mem_timeline -- \
//!       <path-to-batch.bin.gz>
//!
//! A tracking global allocator feeds `mem_probe::{LIVE,PEAK}`, which `execute()`
//! prints at each phase boundary — so we see how each step moves live memory.
use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;

use zksync_airbender_verifier::{execute, mem_probe};
use zksync_cli_utils::{load_batch, BatchInputFile};

struct Tracking;
// SAFETY: delegates to System; only records sizes via non-allocating atomics.
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            mem_probe::on_alloc(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        mem_probe::on_dealloc(l.size());
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            mem_probe::on_alloc(l.size());
        }
        p
    }
}
#[global_allocator]
static A: Tracking = Tracking;

fn main() -> anyhow::Result<()> {
    let path = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: mem_timeline <batch.bin.gz>"),
    );
    let input = load_batch(&BatchInputFile { number: 0, path })?;
    mem_probe::checkpoint("after load+decode (input live)");
    let _ = execute(input)?;
    mem_probe::checkpoint("after execute returned");
    Ok(())
}
