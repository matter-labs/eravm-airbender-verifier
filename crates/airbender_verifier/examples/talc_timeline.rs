//! Per-phase heap footprint under **talc**, the guest's own allocator, run
//! natively. Requires `--features mem-markers`.
//!
//! Runs the verifier under **talc** (the guest's allocator) over a fixed static
//! arena, natively. At each phase boundary `execute()` prints talc's live
//! requested bytes and the running high-water of the real footprint
//! (`claimed - available`, i.e. allocated + talc metadata/fragmentation) — a
//! much closer proxy to the in-guest peak than the System-allocator sum (still
//! 64-bit, so pointer-heavy structures read a bit larger than the 32-bit guest).
//!
//!   cargo run --release -p zksync_airbender_verifier \
//!       --features mem-markers --example talc_timeline -- \
//!       testdata/era_mainnet_batches/binary/<batch>.bin.gz
//!
//! Add `relax-version-pin` for a pre-v31-protocol batch (e.g. the 513xxx set).
use core::sync::atomic::Ordering;
use std::alloc::{GlobalAlloc, Layout};
use std::path::PathBuf;

use talc::locking::AssumeUnlockable;
use talc::{ClaimOnOom, Span, Talc, Talck};

use zksync_airbender_verifier::{execute, mem_probe};
use zksync_cli_utils::{load_batch, BatchInputFile};

/// Sized just above the guest's ~1 GiB heap ceiling, so a batch that overflows
/// this arena is one that would also overflow the guest — the failure is the
/// signal. Raise it to measure headroom, but note the arena is a static BSS array
/// and macOS/aarch64 fails to load the binary at all above ~1 GiB (dyld cannot map
/// its shared region); Linux tolerates more.
const ARENA_MIB: usize = 1024;
static mut ARENA: [u8; ARENA_MIB * 1024 * 1024] = [0; ARENA_MIB * 1024 * 1024];

struct Probe(Talck<AssumeUnlockable, ClaimOnOom>);

#[global_allocator]
static ALLOC: Probe = Probe(
    Talc::new(unsafe { ClaimOnOom::new(Span::from_array(core::ptr::addr_of_mut!(ARENA))) }).lock(),
);

impl Probe {
    #[inline]
    fn sample(&self) {
        let c = *self.0.lock().get_counters();
        // requested-live (what a naive sum sees) and the true footprint in use.
        mem_probe::LIVE.store(c.allocated_bytes, Ordering::Relaxed);
        let used = c.claimed_bytes.saturating_sub(c.available_bytes);
        mem_probe::PEAK.fetch_max(used, Ordering::Relaxed);
    }
}

// SAFETY: delegates to the inner Talck; sample() only reads counters.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = self.0.alloc(l);
        self.sample();
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        self.0.dealloc(p, l);
        self.sample();
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = self.0.alloc_zeroed(l);
        self.sample();
        p
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, ns: usize) -> *mut u8 {
        let np = self.0.realloc(p, l, ns);
        self.sample();
        np
    }
}

fn main() -> anyhow::Result<()> {
    let path = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: talc_timeline <batch.bin.gz | proof_inputs.json>"),
    );
    let input: zksync_airbender_verifier::types::AirbenderVerifierInput =
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(&path)?))?
        } else {
            load_batch(&BatchInputFile { number: 0, path })?
        };
    mem_probe::checkpoint("after load+decode");
    let _ = execute(input)?;
    mem_probe::checkpoint("after execute returned");
    let c = *ALLOC.0.lock().get_counters();
    eprintln!(
        "[talc] arena={ARENA_MIB} MiB | final allocated={} MiB claimed={} MiB | PEAK footprint (claimed-available) = {:.1} MiB",
        c.allocated_bytes >> 20,
        c.claimed_bytes >> 20,
        mem_probe::PEAK.load(Ordering::Relaxed) as f64 / 1048576.0,
    );
    Ok(())
}
