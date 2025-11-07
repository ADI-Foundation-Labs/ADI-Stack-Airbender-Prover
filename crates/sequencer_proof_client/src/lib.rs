// TODO: Currently disabled as it's not used anywhere. Needs a rework anyways.
// pub mod file_based_proof_client;

pub mod sequencer_proof_client;

use crate::metrics::SEQUENCER_CLIENT_METRICS;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::fmt;
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
pub trait ProofClient {
    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>>;
    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
    ) -> anyhow::Result<()>;
    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>>;
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
    async fn peek_fri_job(&self, batch_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>>;
    async fn peek_snark_job(
        &self,
        from_batch_number: u32,
        to_batch_number: u32,
    ) -> anyhow::Result<Option<SnarkProofInputs>>;
    async fn get_failed_fri_proof(
        &self,
        batch_number: u32,
    ) -> anyhow::Result<Option<FailedFriProofPayload>>;
}
