use vise::{EncodeLabelSet, EncodeLabelValue, Family, Histogram, Metrics};

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct SequencerLabel {
    pub sequencer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub(crate) struct SequencerClientLabel {
    pub sequencer: String,
    pub r#type: Method,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, EncodeLabelValue,
)]
#[metrics(rename_all = "snake_case")]
pub(crate) enum Method {
    PickFri,
    SubmitFri,
    PickSnark,
    SubmitSnark,
}

#[derive(Debug, Clone, Metrics)]
#[metrics(prefix = "sequencer_client")]
pub struct SequencerClientMetrics {
    #[metrics(buckets = vise::Buckets::exponential(0.001..=2.0, 2.0), unit = vise::Unit::Seconds)]
    pub(crate) time_taken: Family<SequencerClientLabel, Histogram>,
}

#[vise::register]
pub(crate) static SEQUENCER_CLIENT_METRICS: vise::Global<SequencerClientMetrics> =
    vise::Global::new();
