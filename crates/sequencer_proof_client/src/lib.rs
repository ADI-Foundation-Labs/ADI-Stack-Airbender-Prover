// TODO: Currently disabled as it's not used anywhere. Needs a rework anyways.
// pub mod file_based_proof_client;

pub mod cancel;
pub mod ownership;
pub mod sequencer_endpoint;
pub mod sequencer_proof_client;

pub use cancel::{with_watchdog, CancelFlag, Watched};
pub use ownership::{FriJobOwnership, SnarkRunOwnership};
pub use sequencer_endpoint::SequencerEndpoint;
pub use sequencer_proof_client::SequencerProofClient;

use crate::metrics::SEQUENCER_CLIENT_METRICS;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;
use zkos_wrapper::SnarkWrapperProof;
use zksync_airbender_execution_utils::ProgramProof;

mod metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct L2BatchNumber(pub u32);

impl fmt::Display for L2BatchNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct NextFriProverJobPayload {
    batch_number: u32,
    vk_hash: String,
    prover_input: String, // base64-encoded
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitFriProofPayload {
    batch_number: u64,
    vk_hash: String,
    proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GetSnarkProofPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    fri_proofs: Vec<String>, // base64‑encoded FRI proofs
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitSnarkProofPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    proof: String, // base64‑encoded SNARK proof
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FailedFriProofPayload {
    pub batch_number: u64,
    pub last_block_timestamp: u64,
    pub expected_hash_u32s: [u32; 8],
    pub proof_final_register_values: [u32; 16],
    pub vk_hash: String,
    pub proof: String, // base64‑encoded FRI proof
}

impl TryInto<SnarkProofInputs> for GetSnarkProofPayload {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<SnarkProofInputs, Self::Error> {
        let mut fri_proofs = vec![];
        for encoded_proof in self.fri_proofs {
            let (fri_proof, _) = bincode::serde::decode_from_slice(
                &STANDARD.decode(encoded_proof)?,
                bincode::config::standard(),
            )?;
            fri_proofs.push(fri_proof);
        }

        Ok(SnarkProofInputs {
            from_batch_number: L2BatchNumber(
                self.from_batch_number
                    .try_into()
                    .expect("from_batch_number should fit into L2BatchNumber(u32)"),
            ),
            to_batch_number: L2BatchNumber(
                self.to_batch_number
                    .try_into()
                    .expect("to_batch_number should fit into L2BatchNumber(u32)"),
            ),
            vk_hash: self.vk_hash,
            fri_proofs,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnarkProofInputs {
    pub from_batch_number: L2BatchNumber,
    pub to_batch_number: L2BatchNumber,
    pub vk_hash: String,
    pub fri_proofs: Vec<ProgramProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FriJobInputs {
    pub batch_number: u32,
    pub vk_hash: String,
    pub prover_input: Vec<u8>,
}

#[async_trait]
pub trait ProofClient: Send + Sync {
    /// Returns the sequencer URL for logging purposes.
    fn sequencer_url(&self) -> &Url;

    /// Fetch the next FRI batch to prove.
    /// Returns `Ok(None)` if there's no batch pending (204 No Content).
    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>>;

    /// Submit a FRI proof for the processed batch.
    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
    ) -> anyhow::Result<()>;

    /// Fetch the next SNARK job to prove.
    /// Returns `Ok(None)` if there's no job pending (204 No Content).
    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>>;

    /// Read who currently holds `batch_number`, per `GET /status/`.
    ///
    /// # Errors
    /// Never a cancellation: the caller must read any error as "keep proving".
    async fn fri_job_ownership(&self, batch_number: u32) -> anyhow::Result<FriJobOwnership>;

    /// Read who currently holds the batches of `from..=to`, per `GET /SNARK/status/`.
    ///
    /// # Errors
    /// The path is multiplexer-only, so a raw sequencer answers 404 — keep proving.
    async fn snark_run_ownership(&self, from: u32, to: u32) -> anyhow::Result<SnarkRunOwnership>;

    /// Submit a SNARK proof for the processed batch range.
    async fn submit_snark_proof(
        &self,
        from_batch_number: L2BatchNumber,
        to_batch_number: L2BatchNumber,
        vk_hash: String,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()>;
}

#[async_trait]
pub trait PeekableProofClient {
    /// Peek at a FRI job by batch number.
    /// Note: you can only peek failed jobs as successful ones are removed.
    async fn peek_fri_job(&self, batch_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>>;

    /// Peek at a SNARK job by batch range.
    async fn peek_snark_job(
        &self,
        from_batch_number: u32,
        to_batch_number: u32,
    ) -> anyhow::Result<Option<SnarkProofInputs>>;

    /// Get a failed FRI proof by batch number.
    async fn get_failed_fri_proof(
        &self,
        batch_number: u32,
    ) -> anyhow::Result<Option<FailedFriProofPayload>>;
}
