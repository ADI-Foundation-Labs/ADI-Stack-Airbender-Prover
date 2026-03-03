use core::fmt;
use std::{collections::HashMap, net::Ipv4Addr, time::Duration};

use tokio::{sync::watch, time::Instant};
use vise::{Counter, EncodeLabelSet, Family, Gauge, Histogram, Metrics, MetricsCollection};
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct SequencerLabel {
    pub sequencer: String,
}

#[derive(Debug, Clone, Metrics)]
#[metrics(prefix = "snark_prover")]
pub struct SnarkProverMetrics {
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_startup: Histogram,
    #[metrics(buckets = vise::Buckets::linear(1.0..=150.0, 20.0), unit = vise::Unit::Seconds)]
    pub time_taken_merge_fri: Family<SequencerLabel, Histogram>,
    #[metrics(buckets = vise::Buckets::linear(5.0..=20.0, 2.5), unit = vise::Unit::Seconds)]
    pub time_taken_final_proof: Family<SequencerLabel, Histogram>,
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_snark: Family<SequencerLabel, Histogram>,
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_full: Family<SequencerLabel, Histogram>,
    pub fri_proofs_merged: Family<SequencerLabel, Gauge>,
    pub latest_proven_batch: Family<SequencerLabel, Gauge>,
    /// Number of timeout errors when communicating with sequencer
    pub timeout_errors: Family<SequencerLabel, Counter>,
}

#[vise::register]
pub(crate) static SNARK_PROVER_METRICS: vise::Global<SnarkProverMetrics> = vise::Global::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SnarkStage {
    MergeFri,
    FinalProof,
    Snark,
    Full,
}

impl fmt::Display for SnarkStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SnarkStage::MergeFri => "merge_fri",
                SnarkStage::FinalProof => "final_proof",
                SnarkStage::Snark => "snark",
                SnarkStage::Full => "full",
            }
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SnarkProofTimeStats {
    time_taken: HashMap<SnarkStage, Duration>,
    label: SequencerLabel,
}

impl fmt::Display for SnarkProofTimeStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SnarkProofTimeStats {{")?;
        for (stage, duration) in &self.time_taken {
            write!(f, "{stage}: {duration:?}, ")?;
        }
        write!(f, "}}")
    }
}

impl SnarkProofTimeStats {
    pub fn new(label: SequencerLabel) -> Self {
        Self {
            time_taken: HashMap::new(),
            label,
        }
    }

    pub fn observe_step(&mut self, stage: SnarkStage, duration: Duration) {
        self.time_taken.insert(stage, duration);
        match stage {
            SnarkStage::MergeFri => SNARK_PROVER_METRICS.time_taken_merge_fri[&self.label]
                .observe(duration.as_secs_f64()),
            SnarkStage::FinalProof => SNARK_PROVER_METRICS.time_taken_final_proof[&self.label]
                .observe(duration.as_secs_f64()),
            SnarkStage::Snark => SNARK_PROVER_METRICS.time_taken_snark[&self.label]
                .observe(duration.as_secs_f64()),
            SnarkStage::Full => SNARK_PROVER_METRICS.time_taken_full[&self.label]
                .observe(duration.as_secs_f64()),
        }
    }

    pub fn observe_full(&mut self) {
        let merge_fri = self.time_taken.get(&SnarkStage::MergeFri);
        let final_proof = self.time_taken.get(&SnarkStage::FinalProof);
        let snark = self.time_taken.get(&SnarkStage::Snark);

        if let (Some(merge_fri), Some(final_proof), Some(snark)) = (merge_fri, final_proof, snark) {
            let full_duration = *merge_fri + *final_proof + *snark;
            self.observe_step(SnarkStage::Full, full_duration);
        } else {
            tracing::error!("Failed to observe full duration of snark proof, some of the items are missing: {:?}", self.time_taken);
        }
    }

    pub fn measure_step<F, T>(&mut self, stage: SnarkStage, step: F) -> T
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = step();
        self.observe_step(stage, start.elapsed());
        result
    }
}
