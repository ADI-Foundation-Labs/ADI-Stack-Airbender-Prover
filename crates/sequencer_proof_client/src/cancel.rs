//! Cancellation flag for an in-flight FRI job, and the watchdog that sets it.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc,
    },
    time::Duration,
};

use tokio::runtime::Handle;

use crate::{FriJobOwnership, ProofClient};

/// Shared "stop proving this batch" flag, set by the watchdog and read at phase boundaries.
#[derive(Debug, Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    /// True once the batch has been reassigned to another prover.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Runs `proving` with a watchdog thread polling `client` for loss of ownership.
///
/// `interval` of `None` disables the watchdog entirely; the flag is then never set.
/// The watchdog runs on a dedicated OS thread because `proving` blocks its own.
pub fn with_watchdog<T>(
    client: &dyn ProofClient,
    batch_number: u32,
    interval: Option<Duration>,
    proving: impl FnOnce(&CancelFlag) -> T,
) -> T {
    let flag = CancelFlag::default();

    let Some(interval) = interval else {
        return proving(&flag);
    };

    let runtime = Handle::current();

    std::thread::scope(|scope| {
        // Dropping the sender wakes the watchdog out of its sleep, so a finished
        // job does not pay up to `interval` waiting for the thread to join.
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let watched = flag.clone();

        scope.spawn(move || {
            while matches!(
                stop_rx.recv_timeout(interval),
                Err(RecvTimeoutError::Timeout)
            ) {
                match runtime.block_on(client.fri_job_ownership(batch_number)) {
                    Ok(FriJobOwnership::Lost { owner }) => {
                        tracing::warn!(
                            "Batch {batch_number} is now assigned to prover {owner}, cancelling"
                        );
                        watched.cancel();
                        return;
                    }
                    Ok(ownership) => {
                        tracing::debug!("Batch {batch_number} ownership: {ownership:?}");
                    }
                    // Fail open: an unreachable or unreadable sequencer must never
                    // be read as a cancellation. Warn rather than debug — while this
                    // keeps failing the prover cannot be cancelled at all, and the
                    // rate is bounded by the length of one job.
                    Err(err) => {
                        tracing::warn!(
                            "Ownership check for batch {batch_number} failed, \
                             continuing to prove: {err}"
                        );
                    }
                }
            }
        });

        let outcome = proving(&flag);
        drop(stop_tx);
        outcome
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use async_trait::async_trait;
    use url::Url;
    use zkos_wrapper::SnarkWrapperProof;

    use super::*;
    use crate::{FriJobInputs, L2BatchNumber, SnarkProofInputs};

    /// Answers ownership checks from a fixed script, one entry per poll.
    struct ScriptedClient {
        url: Url,
        answers: Vec<anyhow::Result<FriJobOwnership>>,
        polls: AtomicUsize,
    }

    impl ScriptedClient {
        fn new(answers: Vec<anyhow::Result<FriJobOwnership>>) -> Self {
            Self {
                url: Url::parse("http://localhost:3124").expect("valid url"),
                answers,
                polls: AtomicUsize::new(0),
            }
        }

        fn polls(&self) -> usize {
            self.polls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl ProofClient for ScriptedClient {
        fn sequencer_url(&self) -> &Url {
            &self.url
        }

        async fn fri_job_ownership(&self, _batch_number: u32) -> anyhow::Result<FriJobOwnership> {
            let poll = self.polls.fetch_add(1, Ordering::Relaxed);
            match self.answers.get(poll) {
                Some(Ok(ownership)) => Ok(ownership.clone()),
                Some(Err(err)) => Err(anyhow::anyhow!("{err}")),
                None => Ok(FriJobOwnership::Ours),
            }
        }

        async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
            unimplemented!("not used by the watchdog")
        }

        async fn submit_fri_proof(&self, _: u32, _: String, _: String) -> anyhow::Result<()> {
            unimplemented!("not used by the watchdog")
        }

        async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
            unimplemented!("not used by the watchdog")
        }

        async fn submit_snark_proof(
            &self,
            _: L2BatchNumber,
            _: L2BatchNumber,
            _: String,
            _: SnarkWrapperProof,
        ) -> anyhow::Result<()> {
            unimplemented!("not used by the watchdog")
        }
    }

    const TICK: Duration = Duration::from_millis(50);

    /// Stands in for proving: spins until cancelled or `ticks` elapse.
    fn prove_until_cancelled(cancel: &CancelFlag, ticks: u32) -> bool {
        for _ in 0..ticks {
            if cancel.is_cancelled() {
                return false;
            }
            std::thread::sleep(TICK);
        }
        !cancel.is_cancelled()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reassigned_batch_cancels_proving() {
        let client = ScriptedClient::new(vec![
            Ok(FriJobOwnership::Ours),
            Ok(FriJobOwnership::Lost {
                owner: "prover-b".to_string(),
            }),
        ]);

        let finished = with_watchdog(&client, 7, Some(TICK), |cancel| {
            prove_until_cancelled(cancel, 40)
        });

        assert!(!finished, "proving should have been abandoned");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unreachable_sequencer_keeps_proving() {
        let client = ScriptedClient::new(vec![
            Err(anyhow::anyhow!("connection refused")),
            Err(anyhow::anyhow!("connection refused")),
            Err(anyhow::anyhow!("connection refused")),
        ]);

        let finished = with_watchdog(&client, 7, Some(TICK), |cancel| {
            prove_until_cancelled(cancel, 8)
        });

        assert!(finished, "a failed ownership check must not cancel");
        assert!(client.polls() > 0, "the watchdog should have polled");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unassigned_and_absent_batches_keep_proving() {
        let client = ScriptedClient::new(vec![
            Ok(FriJobOwnership::Unassigned),
            Ok(FriJobOwnership::Unknown),
        ]);

        let finished = with_watchdog(&client, 7, Some(TICK), |cancel| {
            prove_until_cancelled(cancel, 8)
        });

        assert!(finished, "neither state means someone else took the batch");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn zero_interval_disables_the_watchdog() {
        let client = ScriptedClient::new(vec![Ok(FriJobOwnership::Lost {
            owner: "prover-b".to_string(),
        })]);

        let finished = with_watchdog(&client, 7, None, |cancel| prove_until_cancelled(cancel, 4));

        assert!(finished, "no watchdog means no cancellation");
        assert_eq!(client.polls(), 0, "the sequencer must not be polled at all");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finished_job_does_not_wait_for_the_next_poll() {
        let client = ScriptedClient::new(vec![]);
        let started_at = std::time::Instant::now();

        with_watchdog(&client, 7, Some(Duration::from_secs(30)), |_| ());

        assert!(
            started_at.elapsed() < Duration::from_secs(1),
            "joining the watchdog took {:?}, it should be woken by the dropped sender",
            started_at.elapsed()
        );
    }
}
