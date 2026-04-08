use std::net::SocketAddr;
use std::time::Duration;

use vise::{
    Buckets, Counter, EncodeLabelSet, EncodeLabelValue, Family, Gauge, Histogram, Metrics, Unit,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelValue)]
#[metrics(rename_all = "snake_case")]
pub enum ProofStatus {
    Success,
    Failure,
}

/// Labels attached to proof generation metrics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct ProofLabels {
    pub batch_number: u32,
    pub protocol_version: u16,
    pub status: ProofStatus,
}

#[derive(Debug, Metrics)]
#[metrics(prefix = "prover")]
pub struct ProverMetrics {
    /// Time taken by the GPU prover to generate a proof, in seconds.
    #[metrics(buckets = Buckets::LATENCIES, unit = Unit::Seconds)]
    pub proof_duration: Family<ProofLabels, Histogram<Duration>>,

    /// Total number of proof generation attempts.
    pub proof_count: Family<ProofLabels, Counter>,

    /// Number of jobs that have been fetched from the server but not yet submitted.
    pub pending_jobs: Gauge,
}

#[vise::register]
pub static METRICS: vise::Global<ProverMetrics> = vise::Global::new();

/// Starts the Prometheus metrics scrape endpoint on the given port.
///
/// Spawns a background thread with its own single-threaded tokio runtime.
/// Panics if the server cannot bind to the address.
pub fn start_metrics_server(port: u16) {
    let addr: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .expect("invalid metrics address");
    std::thread::Builder::new()
        .name("metrics-server".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime for metrics server");
            rt.block_on(async move {
                vise_exporter::MetricsExporter::default()
                    .start(addr)
                    .await
                    .expect("metrics server error");
            });
        })
        .expect("failed to spawn metrics server thread");
}
