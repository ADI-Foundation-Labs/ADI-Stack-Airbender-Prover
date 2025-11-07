use std::net::Ipv4Addr;

use tokio::sync::watch;
use vise::{Counter, Gauge, Histogram, Metrics, MetricsCollection};
use vise_exporter::MetricsExporter;

pub async fn start_metrics_exporter(
    port: u16,
    mut stop_receiver: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tracing::info!("Starting metrics exporter on port {port}");
    let registry = MetricsCollection::lazy().collect();
    let metrics_exporter =
        MetricsExporter::new(registry.into()).with_graceful_shutdown(async move {
            stop_receiver.changed().await.ok();
        });

    let prom_bind_address = (Ipv4Addr::UNSPECIFIED, port).into();
    metrics_exporter
        .start(prom_bind_address)
        .await
        .map_err(|e| anyhow::anyhow!("Failed starting metrics server: {e}"))?;

    Ok(())
}

#[derive(Debug, Clone, Metrics)]
#[metrics(prefix = "snark_prover")]
pub struct SnarkProverMetrics {
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_startup: Histogram,
    #[metrics(buckets = vise::Buckets::linear(1.0..=150.0, 20.0), unit = vise::Unit::Seconds)]
    pub time_taken_merge_fri: Histogram,
    #[metrics(buckets = vise::Buckets::linear(5.0..=20.0, 2.5), unit = vise::Unit::Seconds)]
    pub time_taken_final_proof: Histogram,
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_snark: Histogram,
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_full: Histogram,
    pub fri_proofs_merged: Gauge,
    pub latest_proven_batch: Gauge,
    /// Number of timeout errors when communicating with sequencer
    pub timeout_errors: Counter,
}

#[vise::register]
pub(crate) static SNARK_PROVER_METRICS: vise::Global<SnarkProverMetrics> = vise::Global::new();
