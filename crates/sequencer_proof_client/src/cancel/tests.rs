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
    snark_answers: Vec<anyhow::Result<SnarkRunOwnership>>,
    polls: AtomicUsize,
}

impl ScriptedClient {
    fn new(answers: Vec<anyhow::Result<FriJobOwnership>>) -> Self {
        Self {
            url: Url::parse("http://localhost:3124").expect("valid url"),
            answers,
            snark_answers: vec![],
            polls: AtomicUsize::new(0),
        }
    }

    fn snark(snark_answers: Vec<anyhow::Result<SnarkRunOwnership>>) -> Self {
        Self {
            snark_answers,
            ..Self::new(vec![])
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

    async fn snark_run_ownership(&self, _: u32, _: u32) -> anyhow::Result<SnarkRunOwnership> {
        let poll = self.polls.fetch_add(1, Ordering::Relaxed);
        match self.snark_answers.get(poll) {
            Some(Ok(ownership)) => Ok(ownership.clone()),
            Some(Err(err)) => Err(anyhow::anyhow!("{err}")),
            None => Ok(SnarkRunOwnership::Ours),
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

    let finished = with_watchdog(&client, Watched::Fri(7), Some(TICK), |cancel| {
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

    let finished = with_watchdog(&client, Watched::Fri(7), Some(TICK), |cancel| {
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

    let finished = with_watchdog(&client, Watched::Fri(7), Some(TICK), |cancel| {
        prove_until_cancelled(cancel, 8)
    });

    assert!(finished, "neither state means someone else took the batch");
}

#[tokio::test(flavor = "multi_thread")]
async fn reassigned_snark_batch_cancels_the_whole_run() {
    let client = ScriptedClient::snark(vec![
        Ok(SnarkRunOwnership::Ours),
        Ok(SnarkRunOwnership::Lost {
            batch_number: 11,
            owner: "snark-b".to_string(),
        }),
    ]);

    let finished = with_watchdog(
        &client,
        Watched::Snark { from: 10, to: 13 },
        Some(TICK),
        |cancel| prove_until_cancelled(cancel, 40),
    );

    assert!(!finished, "losing one batch abandons the whole run");
}

#[tokio::test(flavor = "multi_thread")]
async fn unconfirmed_snark_batches_keep_proving() {
    let client = ScriptedClient::snark(vec![Ok(SnarkRunOwnership::Unconfirmed {
        unassigned: 1,
        unknown: 2,
    })]);

    let finished = with_watchdog(
        &client,
        Watched::Snark { from: 10, to: 13 },
        Some(TICK),
        |cancel| prove_until_cancelled(cancel, 8),
    );

    assert!(finished, "free or absent batches are not a reassignment");
}

#[tokio::test(flavor = "multi_thread")]
async fn zero_interval_disables_the_watchdog() {
    let client = ScriptedClient::new(vec![Ok(FriJobOwnership::Lost {
        owner: "prover-b".to_string(),
    })]);

    let finished = with_watchdog(&client, Watched::Fri(7), None, |cancel| {
        prove_until_cancelled(cancel, 4)
    });

    assert!(finished, "no watchdog means no cancellation");
    assert_eq!(client.polls(), 0, "the sequencer must not be polled at all");
}

#[tokio::test(flavor = "multi_thread")]
async fn finished_job_does_not_wait_for_the_next_poll() {
    let client = ScriptedClient::new(vec![]);
    let started_at = std::time::Instant::now();

    with_watchdog(
        &client,
        Watched::Fri(7),
        Some(Duration::from_secs(30)),
        |_| (),
    );

    assert!(
        started_at.elapsed() < Duration::from_secs(1),
        "joining the watchdog took {:?}, it should be woken by the dropped sender",
        started_at.elapsed()
    );
}
