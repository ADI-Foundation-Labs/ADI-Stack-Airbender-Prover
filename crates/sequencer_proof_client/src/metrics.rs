use vise::{EncodeLabelSet, EncodeLabelValue, Family, Histogram, Metrics};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, EncodeLabelValue, EncodeLabelSet,
)]
#[metrics(label = "type", rename_all = "snake_case")]
pub(crate) enum Method {
    PickFri,
    SubmitFri,
    PickSnark,
    SubmitSnark,
    FriJobStatus,
    SnarkRunStatus,
}

#[derive(Debug, Clone, Metrics)]
#[metrics(prefix = "sequencer_client")]
pub struct SequencerClientMetrics {
    #[metrics(buckets = vise::Buckets::exponential(0.001..=2.0, 2.0), unit = vise::Unit::Seconds)]
    pub time_taken: Family<Method, Histogram>,
}

#[vise::register]
pub(crate) static SEQUENCER_CLIENT_METRICS: vise::Global<SequencerClientMetrics> =
    vise::Global::new();
