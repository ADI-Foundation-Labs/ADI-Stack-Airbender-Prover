//! Cancellation flag for an in-flight job, and the watchdog that sets it.

use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc,
    },
    time::Duration,
};

use tokio::runtime::Handle;

use crate::{FriJobOwnership, ProofClient, SnarkRunOwnership};

/// Shared "stop proving this batch" flag, set by the watchdog and read at phase boundaries.
#[derive(Debug, Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    /// True once the batch has been reassigned to another prover.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// The raw flag, for handing to the System prover's cancellable entry points.
    #[must_use]
    pub fn as_arc(&self) -> &Arc<AtomicBool> {
        &self.0
    }

    fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
        #[cfg(feature = "gpu")]
        zkos_wrapper::cancel::request();
    }
}

/// The job a watchdog follows: one FRI batch, or the range of a SNARK run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watched {
    /// A single FRI batch, read from `GET /status/`.
    Fri(u32),
    /// Every batch of a SNARK run, read from `GET /SNARK/status/`.
    Snark { from: u32, to: u32 },
}

impl fmt::Display for Watched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fri(batch_number) => write!(f, "batch {batch_number}"),
            Self::Snark { from, to } => write!(f, "run {from}-{to}"),
        }
    }
}

impl Watched {
    /// Names a lost batch, adding the run it belongs to when the job spans more than one.
    fn name_lost(self, batch_number: u32) -> String {
        match self {
            Self::Fri(_) => format!("Batch {batch_number}"),
            Self::Snark { .. } => format!("Batch {batch_number} of {self}"),
        }
    }
}

/// A batch taken by another prover, and who holds it now.
struct Loss {
    batch_number: u32,
    owner: String,
}

/// Asks the stage's status endpoint whether anything was taken from us.
fn poll(
    client: &dyn ProofClient,
    watched: Watched,
    runtime: &Handle,
) -> anyhow::Result<Option<Loss>> {
    match watched {
        Watched::Fri(batch_number) => {
            let ownership = runtime.block_on(client.fri_job_ownership(batch_number))?;
            tracing::debug!("Batch {batch_number} ownership: {ownership:?}");

            Ok(match ownership {
                FriJobOwnership::Lost { owner } => Some(Loss {
                    batch_number,
                    owner,
                }),
                _ => None,
            })
        }
        Watched::Snark { from, to } => {
            let ownership = runtime.block_on(client.snark_run_ownership(from, to))?;
            tracing::debug!("Run {from}-{to} ownership: {ownership:?}");

            Ok(match ownership {
                SnarkRunOwnership::Lost {
                    batch_number,
                    owner,
                } => Some(Loss {
                    batch_number,
                    owner,
                }),
                _ => None,
            })
        }
    }
}

/// Everything the watchdog thread needs to follow one job.
struct Watchdog<'a> {
    client: &'a dyn ProofClient,
    watched: Watched,
    runtime: Handle,
    interval: Duration,
    flag: CancelFlag,
}

impl Watchdog<'_> {
    /// Polls until the job is lost or `stop` is dropped.
    fn run(self, stop: &mpsc::Receiver<()>) {
        while matches!(
            stop.recv_timeout(self.interval),
            Err(RecvTimeoutError::Timeout)
        ) {
            let Some(loss) = self.check() else {
                continue;
            };
            let Loss {
                batch_number,
                owner,
            } = loss;
            tracing::warn!(
                "{} is now assigned to prover {owner}, cancelling",
                self.watched.name_lost(batch_number)
            );
            self.flag.cancel();
            return;
        }
    }

    /// One ownership check, with the fail-open rule applied: any error keeps proving.
    fn check(&self) -> Option<Loss> {
        poll(self.client, self.watched, &self.runtime)
            .inspect_err(|err| {
                // Warn rather than debug: while this keeps failing the prover cannot be
                // cancelled at all, and the rate is bounded by the length of one job.
                tracing::warn!(
                    "Ownership check for {} failed, continuing to prove: {err}",
                    self.watched
                );
            })
            .ok()
            .flatten()
    }
}

/// Runs `proving` with a watchdog thread polling `client` for loss of ownership.
///
/// `None` disables the watchdog. It needs its own OS thread because `proving` blocks.
pub fn with_watchdog<T>(
    client: &dyn ProofClient,
    watched: Watched,
    interval: Option<Duration>,
    proving: impl FnOnce(&CancelFlag) -> T,
) -> T {
    // No arming step: the wrapper's stage timers capture the cancel generation when the
    // run starts, so a request left over from an earlier job cannot reach this one.
    let flag = CancelFlag::default();

    let Some(interval) = interval else {
        return proving(&flag);
    };

    let watchdog = Watchdog {
        client,
        watched,
        runtime: Handle::current(),
        interval,
        flag: flag.clone(),
    };

    std::thread::scope(|scope| {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        scope.spawn(move || watchdog.run(&stop_rx));

        let outcome = proving(&flag);
        // Dropping the sender wakes the watchdog out of its sleep, so a finished job does
        // not pay up to `interval` waiting for the thread to join.
        drop(stop_tx);
        outcome
    })
}

#[cfg(test)]
mod tests;
