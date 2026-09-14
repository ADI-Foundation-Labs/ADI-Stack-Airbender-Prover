//! Which backend answers a sequencer URL, and the probe that finds out.

use std::{
    fmt,
    sync::Mutex,
    time::{Duration, Instant},
};

use reqwest::StatusCode;
use url::Url;

/// How long a plain-sequencer answer stands before a client asks again.
///
/// Only the negative expires. Reading a mux wrongly costs unwanted polls; reading a plain
/// sequencer wrongly costs cancellation altogether.
pub(crate) const REPROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Which backend answers a sequencer URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// A mux, which serves the SNARK status route.
    Mux,
    /// A plain sequencer, which does not.
    Sequencer,
}

impl Backend {
    /// True only for [`Self::Mux`] — the one backend cancellation runs against.
    #[must_use]
    pub fn supports_cancellation(self) -> bool {
        matches!(self, Self::Mux)
    }

    /// Returns what this backend means for the cancel path, as the startup log says it.
    pub(crate) fn cancellation_posture(self) -> &'static str {
        match self {
            Self::Mux => "ownership checks run against it",
            Self::Sequencer => "ownership checks wait for a re-probe to find a mux",
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mux => f.write_str("a mux"),
            Self::Sequencer => f.write_str("a plain sequencer"),
        }
    }
}

/// One probe answer, and the moment the probe took it.
#[derive(Debug, Clone, Copy)]
struct Reading {
    backend: Backend,
    at: Instant,
}

/// The probe answer a client holds. Clients are shared by reference, so it locks.
#[derive(Debug, Default)]
pub(crate) struct Latch(Mutex<Option<Reading>>);

impl Latch {
    /// True once a probe has answered [`Backend::Mux`]; an unprobed latch never cancels.
    pub(crate) fn supports_cancellation(&self) -> bool {
        self.read()
            .is_some_and(|reading| reading.backend.supports_cancellation())
    }

    /// True when the held answer is a plain sequencer older than `max_age`.
    pub(crate) fn wants_reprobe(&self, max_age: Duration) -> bool {
        self.read().is_some_and(|reading| {
            !reading.backend.supports_cancellation() && reading.at.elapsed() >= max_age
        })
    }

    /// Records a probe answer.
    pub(crate) fn set(&self, backend: Backend) {
        let Ok(mut held) = self.0.lock() else {
            return;
        };

        *held = Some(Reading {
            backend,
            at: Instant::now(),
        });
    }

    /// A poisoned latch reads as unprobed, which never cancels.
    fn read(&self) -> Option<Reading> {
        self.0.lock().ok().and_then(|held| *held)
    }
}

/// Asks the SNARK status route at `url` which backend serves it.
///
/// Only a `404` is a sound negative, because that route exists on a mux alone.
/// Every other answer, and every failure, reads as [`Backend::Mux`], so a URL that will not
/// answer at boot never quietly loses cancellation.
pub(crate) async fn probe(http: &reqwest::Client, url: &Url, timeout: Duration) -> Backend {
    let answered_404 = http
        .get(url.clone())
        .timeout(timeout)
        .send()
        .await
        .inspect_err(|err| {
            tracing::warn!("Backend probe of {url} failed, reading it as a mux: {err}");
        })
        .is_ok_and(|response| response.status() == StatusCode::NOT_FOUND);

    if answered_404 {
        return Backend::Sequencer;
    }

    Backend::Mux
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unprobed_latch_neither_cancels_nor_reprobes() {
        let latch = Latch::default();

        assert!(!latch.supports_cancellation());
        assert!(!latch.wants_reprobe(Duration::ZERO));
    }

    #[test]
    fn a_fresh_sequencer_answer_stands() {
        let latch = Latch::default();
        latch.set(Backend::Sequencer);

        assert!(!latch.supports_cancellation());
        assert!(!latch.wants_reprobe(REPROBE_INTERVAL));
    }

    /// One 404 from an ingress mid-rollout must not cost a prover cancellation for life.
    #[test]
    fn a_sequencer_answer_expires() {
        let latch = Latch::default();
        latch.set(Backend::Sequencer);

        assert!(latch.wants_reprobe(Duration::ZERO));
    }

    /// Reading a mux wrongly costs unwanted polls, which the fail-open rule accepts.
    #[test]
    fn a_mux_answer_never_expires() {
        let latch = Latch::default();
        latch.set(Backend::Mux);

        assert!(!latch.wants_reprobe(Duration::ZERO));
    }

    #[test]
    fn a_reprobe_that_finds_a_mux_turns_cancellation_on() {
        let latch = Latch::default();
        latch.set(Backend::Sequencer);
        latch.set(Backend::Mux);

        assert!(latch.supports_cancellation());
        assert!(!latch.wants_reprobe(Duration::ZERO));
    }
}
