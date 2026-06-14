//! Optional memory-profiling harness (native).
//!
//! Runs the verifier's `execute()` on a flat proof-inputs JSON and reports the
//! witness sizes; wrap it with the OS peak-RSS reporter to get native peak-live
//! memory:
//!   /usr/bin/time -l  cargo run --release -p zksync_airbender_verifier \
//!       --example mem_check -- <proof_inputs.json>   # macOS: "maximum resident set size"
//!   /usr/bin/time -v  ...                             # Linux: "Maximum resident set size"
//!
//! This is a *relative* signal (regression checks / before-after comparisons)
//! and a lower bound: the in-guest peak runs higher (talc fragmentation +
//! transient doubling). For the true guest peak during simulation use
//! `scripts/probe_guest_memory.sh`.
use std::fs::File;
use std::io::BufReader;

use zksync_airbender_verifier::execute;
use zksync_airbender_verifier::types::V1AirbenderVerifierInput;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: mem_check <proof_inputs.json>");
    let input: V1AirbenderVerifierInput =
        serde_json::from_reader(BufReader::new(File::open(&path).expect("open batch json")))
            .expect("parse batch json");
    let refunds = input.vm_run_data.storage_refunds.len();
    let pubdata = input.vm_run_data.pubdata_costs.len();
    let state = execute(input).expect("execute failed");
    println!(
        "execute ok: refunds={refunds} pubdata_costs={pubdata} pubdata_bytes={}",
        state.pubdata().len()
    );
}
