//! Who holds a FRI batch or the batches of a SNARK run, per the status endpoints.

use serde::Deserialize;

/// The nested `fri_job` key of a `GET /status/` entry.
#[derive(Debug, Deserialize)]
struct FriJobKey {
    batch_number: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FriJobStatusPayload {
    fri_job: FriJobKey,
    assigned_to_prover_id: Option<String>,
}

/// The nested `snark_job` key of a `GET /SNARK/status/` entry.
#[derive(Debug, Deserialize)]
struct SnarkJobKey {
    batch_number: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SnarkJobStatusPayload {
    snark_job: SnarkJobKey,
    assigned_to_prover_id: Option<String>,
}

/// Who holds a FRI batch, as reported by `GET /status/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FriJobOwnership {
    /// Present and still assigned to us.
    Ours,
    /// Present and assigned to a different prover — the only state that cancels.
    Lost { owner: String },
    /// Present with no assignee, e.g. just reaped.
    Unassigned,
    /// Absent from the report.
    Unknown,
}

impl FriJobOwnership {
    /// True only for [`Self::Lost`] — every other state means keep proving.
    #[must_use]
    pub fn is_lost(&self) -> bool {
        matches!(self, Self::Lost { .. })
    }

    /// Finds `batch_number` in a `GET /status/` body and reads off who holds it.
    pub(crate) fn classify(
        entries: Vec<FriJobStatusPayload>,
        batch_number: u32,
        prover_name: &str,
    ) -> FriJobOwnership {
        let Some(entry) = entries
            .into_iter()
            .find(|entry| entry.fri_job.batch_number == u64::from(batch_number))
        else {
            return FriJobOwnership::Unknown;
        };

        match entry.assigned_to_prover_id {
            Some(owner) if owner == prover_name => FriJobOwnership::Ours,
            Some(owner) => FriJobOwnership::Lost { owner },
            None => FriJobOwnership::Unassigned,
        }
    }
}

/// Who holds the batches of a SNARK run, per `GET /SNARK/status/`.
///
/// Ownership is per batch, so a run is lost as soon as any one of its batches is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnarkRunOwnership {
    /// Every batch of the range is present and still assigned to us.
    Ours,
    /// A batch went to a different prover — the only state that cancels.
    Lost { batch_number: u32, owner: String },
    /// Nothing was taken, but some batches are unassigned or absent.
    Unconfirmed { unassigned: usize, unknown: usize },
}

impl SnarkRunOwnership {
    /// True only for [`Self::Lost`] — every other state means keep proving.
    #[must_use]
    pub fn is_lost(&self) -> bool {
        matches!(self, Self::Lost { .. })
    }

    /// Who holds each batch of `from..=to`, given a `GET /SNARK/status/` body.
    ///
    /// One lost batch outranks any number of unassigned or absent ones.
    pub(crate) fn classify(
        entries: Vec<SnarkJobStatusPayload>,
        from: u32,
        to: u32,
        prover_name: &str,
    ) -> SnarkRunOwnership {
        let mut unassigned = 0;
        let mut unknown = 0;

        for batch_number in from..=to {
            let entry = entries
                .iter()
                .find(|entry| entry.snark_job.batch_number == u64::from(batch_number));

            match entry.map(|entry| &entry.assigned_to_prover_id) {
                Some(Some(owner)) if owner == prover_name => {}
                Some(Some(owner)) => {
                    return SnarkRunOwnership::Lost {
                        batch_number,
                        owner: owner.clone(),
                    }
                }
                Some(None) => unassigned += 1,
                None => unknown += 1,
            }
        }

        if unassigned == 0 && unknown == 0 {
            SnarkRunOwnership::Ours
        } else {
            SnarkRunOwnership::Unconfirmed {
                unassigned,
                unknown,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `GET /status/` body as the server and mux emit it, extra fields included.
    const STATUS_BODY: &str = r#"[
      {
        "fri_job": {"batch_number": 41, "vk_hash": "0xdead"},
        "added_seconds_ago": 12,
        "assigned_seconds_ago": 3,
        "assigned_to_prover_id": "prover-a",
        "current_attempt": 1
      },
      {
        "fri_job": {"batch_number": 42, "vk_hash": "0xdead"},
        "added_seconds_ago": 9,
        "assigned_seconds_ago": null,
        "assigned_to_prover_id": null,
        "current_attempt": 2
      }
    ]"#;

    pub(crate) fn classify(batch_number: u32, prover_name: &str) -> FriJobOwnership {
        let entries: Vec<FriJobStatusPayload> =
            serde_json::from_str(STATUS_BODY).expect("status body should parse");
        FriJobOwnership::classify(entries, batch_number, prover_name)
    }

    #[test]
    fn batch_held_by_us_keeps_proving() {
        assert_eq!(classify(41, "prover-a"), FriJobOwnership::Ours);
        assert!(!classify(41, "prover-a").is_lost());
    }

    #[test]
    fn batch_held_by_another_prover_cancels() {
        let ownership = classify(41, "prover-b");
        assert_eq!(
            ownership,
            FriJobOwnership::Lost {
                owner: "prover-a".to_string()
            }
        );
        assert!(ownership.is_lost());
    }

    #[test]
    fn unassigned_batch_keeps_proving() {
        assert_eq!(classify(42, "prover-a"), FriJobOwnership::Unassigned);
        assert!(!classify(42, "prover-a").is_lost());
    }

    #[test]
    fn absent_batch_keeps_proving() {
        assert_eq!(classify(99, "prover-a"), FriJobOwnership::Unknown);
        assert!(!classify(99, "prover-a").is_lost());
    }

    /// A `GET /SNARK/status/` body as mux emits it, extra fields included.
    ///
    /// Batches 10-12 are a run held by `snark-a`; 13 is free and 14 is missing.
    const SNARK_STATUS_BODY: &str = r#"[
      {
        "snark_job": {"batch_number": 10, "vk_hash": "0xdead"},
        "added_seconds_ago": 40,
        "assigned_seconds_ago": 20,
        "assigned_to_prover_id": "snark-a",
        "current_attempt": 1
      },
      {
        "snark_job": {"batch_number": 11, "vk_hash": "0xdead"},
        "added_seconds_ago": 38,
        "assigned_seconds_ago": 20,
        "assigned_to_prover_id": "snark-a",
        "current_attempt": 1
      },
      {
        "snark_job": {"batch_number": 12, "vk_hash": "0xdead"},
        "added_seconds_ago": 36,
        "assigned_seconds_ago": 20,
        "assigned_to_prover_id": "snark-a",
        "current_attempt": 1
      },
      {
        "snark_job": {"batch_number": 13, "vk_hash": "0xdead"},
        "added_seconds_ago": 34,
        "assigned_seconds_ago": null,
        "assigned_to_prover_id": null,
        "current_attempt": 2
      }
    ]"#;

    fn classify_run(from: u32, to: u32, prover_name: &str) -> SnarkRunOwnership {
        let entries: Vec<SnarkJobStatusPayload> =
            serde_json::from_str(SNARK_STATUS_BODY).expect("status body should parse");
        SnarkRunOwnership::classify(entries, from, to, prover_name)
    }

    #[test]
    fn run_held_by_us_keeps_proving() {
        assert_eq!(classify_run(10, 12, "snark-a"), SnarkRunOwnership::Ours);
        assert!(!classify_run(10, 12, "snark-a").is_lost());
    }

    #[test]
    fn one_reassigned_batch_loses_the_whole_run() {
        let ownership = classify_run(10, 12, "snark-b");
        assert_eq!(
            ownership,
            SnarkRunOwnership::Lost {
                batch_number: 10,
                owner: "snark-a".to_string()
            }
        );
        assert!(ownership.is_lost());
    }

    #[test]
    fn a_lost_batch_outranks_free_and_absent_ones() {
        // 13 is free and 14 absent, but 12 went elsewhere — that decides it.
        assert_eq!(
            classify_run(12, 14, "snark-b"),
            SnarkRunOwnership::Lost {
                batch_number: 12,
                owner: "snark-a".to_string()
            }
        );
    }

    #[test]
    fn free_and_absent_batches_keep_proving() {
        let ownership = classify_run(12, 14, "snark-a");
        assert_eq!(
            ownership,
            SnarkRunOwnership::Unconfirmed {
                unassigned: 1,
                unknown: 1
            }
        );
        assert!(!ownership.is_lost());
    }

    #[test]
    fn a_run_absent_from_the_report_keeps_proving() {
        let ownership = classify_run(90, 92, "snark-a");
        assert_eq!(
            ownership,
            SnarkRunOwnership::Unconfirmed {
                unassigned: 0,
                unknown: 3
            }
        );
        assert!(!ownership.is_lost());
    }
}
