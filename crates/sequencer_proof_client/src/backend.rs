//! Which backend answers a sequencer URL, and the probe that finds out.

use std::{
    fmt,
    sync::Mutex,
    time::{Duration, Instant},
};

use reqwest::{header::HeaderMap, StatusCode};
use url::Url;

/// How long a plain-sequencer answer stands before a client asks again.
///
/// Only the negative expires. Reading a mux wrongly costs unwanted polls; reading a plain
/// sequencer wrongly costs cancellation altogether.
pub(crate) const REPROBE_INTERVAL: Duration = Duration::from_secs(60);

/// The header mux stamps on every answer it gives, from mux v0.3.0 on.
pub(crate) const VERSION_HEADER: &str = "mux-version";

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

    /// Reads the backend an answer announces, or `None` when it announces nothing.
    ///
    /// Only the positive is sound. A missing [`VERSION_HEADER`] is either a plain sequencer
    /// or a mux pod older than v0.3.0, and the two are told apart by the probe below.
    pub(crate) fn announced(headers: &HeaderMap) -> Option<Self> {
        headers.contains_key(VERSION_HEADER).then_some(Self::Mux)
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

    /// Records [`Backend::Mux`] when `headers` announce it, and leaves the latch alone
    /// otherwise, because a missing [`VERSION_HEADER`] proves nothing.
    pub(crate) fn observe(&self, headers: &HeaderMap) {
        let Some(backend) = Backend::announced(headers) else {
            return;
        };

        self.set(backend);
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
/// [`VERSION_HEADER`] settles the answer when it is there. Without it, only a `404` is a
/// sound negative, because that route exists on a mux alone. Every other answer, and every
/// failure, reads as [`Backend::Mux`], so a URL that will not answer at boot never quietly
/// loses cancellation.
pub(crate) async fn probe(http: &reqwest::Client, url: &Url, timeout: Duration) -> Backend {
    let Ok(response) = http
        .get(url.clone())
        .timeout(timeout)
        .send()
        .await
        .inspect_err(|err| {
            tracing::warn!("Backend probe of {url} failed, reading it as a mux: {err}");
        })
    else {
        return Backend::Mux;
    };

    if let Some(announced) = Backend::announced(response.headers()) {
        return announced;
    }

    if response.status() == StatusCode::NOT_FOUND {
        return Backend::Sequencer;
    }

    Backend::Mux
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a header map carrying `mux-version`, as mux v0.3.0 and later answer.
    fn announced_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(VERSION_HEADER, "0.3.0 (abc1234)".parse().expect("valid"));
        headers
    }

    #[test]
    fn the_version_header_names_a_mux() {
        assert_eq!(Backend::announced(&announced_headers()), Some(Backend::Mux));
    }

    /// A mux pod older than v0.3.0 also answers without the header, so absence proves nothing.
    #[test]
    fn a_missing_version_header_names_nothing() {
        assert_eq!(Backend::announced(&HeaderMap::new()), None);
    }

    #[test]
    fn an_announced_mux_turns_cancellation_on() {
        let latch = Latch::default();
        latch.observe(&announced_headers());

        assert!(latch.supports_cancellation());
    }

    /// The header is the one signal that outranks a held negative, because it is certain.
    #[test]
    fn an_announced_mux_overrides_a_held_sequencer_answer() {
        let latch = Latch::default();
        latch.set(Backend::Sequencer);
        latch.observe(&announced_headers());

        assert!(latch.supports_cancellation());
    }

    /// An unannounced answer must not undo a probe, nor stand in for one.
    #[test]
    fn an_unannounced_answer_leaves_the_latch_alone() {
        let latch = Latch::default();
        latch.observe(&HeaderMap::new());
        assert!(!latch.supports_cancellation());

        latch.set(Backend::Mux);
        latch.observe(&HeaderMap::new());
        assert!(latch.supports_cancellation());
    }

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
