//! Per-request timeouts a [`SequencerProofClient`](crate::SequencerProofClient) applies.

use std::time::Duration;

/// How long the client waits for each class of sequencer request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTimeouts {
    /// Bounds every request except the two ownership reads.
    pub request: Duration,
    /// Bounds the two ownership reads. Separate from `request` so the watchdog's cadence
    /// does not follow a value sized for proof submission.
    pub cancel_request: Duration,
}

impl ClientTimeouts {
    /// Builds both timeouts from whole seconds, as the prover binaries take them.
    #[must_use]
    pub fn new(request_secs: u64, cancel_request_secs: u64) -> Self {
        Self {
            request: Duration::from_secs(request_secs),
            cancel_request: Duration::from_secs(cancel_request_secs),
        }
    }
}

impl Default for ClientTimeouts {
    fn default() -> Self {
        Self {
            request: Duration::from_secs(2),
            cancel_request: Duration::from_secs(5),
        }
    }
}
