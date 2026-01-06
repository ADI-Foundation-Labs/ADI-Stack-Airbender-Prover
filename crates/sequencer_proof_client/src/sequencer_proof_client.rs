use std::time::{Duration, Instant};

use crate::metrics::Method;
use crate::{
    FailedFriProofPayload, FriJobInputs, GetSnarkProofPayload, NextFriProverJobPayload,
    PeekableProofClient, ProofClient, SnarkProofInputs, SubmitFriProofPayload,
    SubmitSnarkProofPayload,
};
use crate::{L2BatchNumber, SEQUENCER_CLIENT_METRICS};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bellman::{bn256::Bn256, plonk::better_better_cs::proof::Proof as PlonkProof};
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit;
use reqwest::StatusCode;
use serde_json;
use url::Url;
use zkos_wrapper::SnarkWrapperProof;

// TODO!: Refactor all these strings from string concat to url joining
const SEQUENCER_PROVER_API_PATH: &str = "prover-jobs/v1";

#[derive(Debug)]
pub struct SequencerProofClient {
    client: reqwest::Client,
    url: Url,
    sanitized_url: Url,
    prover_name: String,
}

impl SequencerProofClient {
    /// Create a new proof sequencer client.
    ///
    /// # Arguments
    /// * `url` - The URL of the sequencer server
    /// * `prover_name` - The name of the prover (used for identification in sequencer prover api)
    /// * `timeout` - Optional timeout for requests (None defaults to 2 seconds)
    ///
    /// # Errors
    /// * if building the reqwest client fails
    pub fn new(url: Url, prover_name: String, timeout: Option<Duration>) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout.unwrap_or(Duration::from_secs(2)))
            .build()
            .context("Failed to build reqwest client")?;

        let sanitized_url = Self::sanitize_url(url.clone());

        Ok(Self {
            client,
            url,
            sanitized_url,
            prover_name,
        })
    }

    /// Create multiple sequencer proof clients from a list of URLs.
    ///
    /// # Arguments
    /// * `urls` - A vector of sequencer URLs
    /// * `prover_name` - The name of the prover (used for identification in sequencer prover api)
    /// * `timeout` - Optional timeout for requests (None defaults to 2 seconds)
    ///
    /// # Errors
    /// * if creating any of the clients fails
    pub fn new_clients(
        urls: Vec<Url>,
        prover_name: String,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Vec<Box<dyn ProofClient + Send + Sync>>> {
        let mut clients: Vec<Box<dyn ProofClient + Send + Sync>> = vec![];
        for url in urls {
            let client = SequencerProofClient::new(url.clone(), prover_name.clone(), timeout)
                .with_context(|| format!("failed to create sequencer with url {url}"))?;
            clients.push(Box::new(client) as Box<dyn ProofClient + Send + Sync>);
        }
        Ok(clients)
    }

    /// Serialize a SNARK proof into a base64-encoded string suitable for submission.
    ///
    /// # Arguments
    /// * `proof` - The SNARK proof to serialize
    ///
    /// # Errors
    /// * if serialization/deserialization fails (needed for conversion)
    pub fn serialize_snark_proof(&self, proof: &SnarkWrapperProof) -> anyhow::Result<String> {
        let serialized_proof = serde_json::to_string(&proof)?;

        let codegen_snark_proof: PlonkProof<Bn256, ZkSyncSnarkWrapperCircuit> =
            serde_json::from_str(&serialized_proof)?;
        let (_, serialized_proof) = crypto_codegen::serialize_proof(&codegen_snark_proof);

        let byte_serialized_proof = serialized_proof
            .iter()
            .flat_map(|chunk| {
                let mut buf = [0u8; 32];
                chunk.to_big_endian(&mut buf);
                buf
            })
            .collect::<Vec<u8>>();

        Ok(STANDARD.encode(byte_serialized_proof))
    }

    /// Sanitizes authentication credentials from a URL for safe logging.
    /// Replaces the password with "******" if present.
    fn sanitize_url(mut url: Url) -> Url {
        if url.password().is_some() && url.set_password(Some("******")).is_ok() {
            return url;
        }
        url
    }
}

#[async_trait]
impl ProofClient for SequencerProofClient {
    fn sequencer_url(&self) -> &Url {
        &self.sanitized_url
    }

    /// Fetch the next batch to prove.
    /// Returns `Ok(None)` if there's no batch pending (204 No Content).
    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
        let url = self.url.join(&format!(
            "{SEQUENCER_PROVER_API_PATH}/FRI/pick?id={}",
            self.prover_name
        ))?;

        let started_at = Instant::now();

        let resp = self.client.post(url.clone()).send().await?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::PickFri]
            .observe(started_at.elapsed().as_secs_f64());

        match resp.status() {
            StatusCode::OK => {
                let body: NextFriProverJobPayload = resp.json().await?;
                let data = STANDARD
                    .decode(&body.prover_input)
                    .map_err(|e| anyhow!("Failed to decode batch data: {e}"))?;
                Ok(Some(FriJobInputs {
                    batch_number: body.batch_number,
                    vk_hash: body.vk_hash,
                    prover_input: data,
                }))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!(
                "Unexpected status {s} when fetching next batch at address {url}"
            )),
        }
    }

    /// Submit a proof for the processed batch
    /// Returns the vector of u32 as returned by the server.
    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
    ) -> anyhow::Result<()> {
        let url = self.url.join(&format!(
            "{SEQUENCER_PROVER_API_PATH}/FRI/submit?id={}",
            self.prover_name
        ))?;

        let payload = SubmitFriProofPayload {
            batch_number: batch_number as u64,
            vk_hash,
            proof,
        };

        let started_at = Instant::now();

        let resp = self.client.post(url).json(&payload).send().await?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SubmitFri]
            .observe(started_at.elapsed().as_secs_f64());

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Server returned {} when submitting proof",
                resp.status()
            ))
        }
    }

    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = self.url.join(&format!(
            "{SEQUENCER_PROVER_API_PATH}/SNARK/pick?id={}",
            self.prover_name
        ))?;

        let started_at = Instant::now();

        let resp = self.client.post(url).send().await?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::PickSnark]
            .observe(started_at.elapsed().as_secs_f64());

        match resp.status() {
            StatusCode::OK => {
                let get_snark_proof_payload = resp.json::<GetSnarkProofPayload>().await?;
                Ok(Some(
                    get_snark_proof_payload
                        .try_into()
                        .context("failed to parse SnarkProofPayload")?,
                ))
            }
            StatusCode::NO_CONTENT => Ok(None),
            _ => Err(anyhow!("Failed to pick SNARK job: {resp:?}")),
        }
    }

    async fn submit_snark_proof(
        &self,
        from_batch_number: L2BatchNumber,
        to_batch_number: L2BatchNumber,
        vk_hash: String,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        let url = self.url.join(&format!(
            "{SEQUENCER_PROVER_API_PATH}/SNARK/submit?id={}",
            self.prover_name
        ))?;

        let started_at = Instant::now();

        let serialized_proof = self
            .serialize_snark_proof(&proof)
            .context("Failed to serialize SNARK proof")?;

        let payload = SubmitSnarkProofPayload {
            from_batch_number: from_batch_number.0 as u64,
            to_batch_number: to_batch_number.0 as u64,
            vk_hash,
            proof: serialized_proof,
        };
        self.client
            .post(url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SubmitSnark]
            .observe(started_at.elapsed().as_secs_f64());
        Ok(())
    }
}

#[async_trait]
impl PeekableProofClient for SequencerProofClient {
    /// Note: you can peek only failed jobs as successful ones are removed.
    async fn peek_fri_job(&self, batch_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let url = self.url.join(&format!(
            "{SEQUENCER_PROVER_API_PATH}/FRI/{batch_number}/peek"
        ))?;
        let resp = self.client.get(url).send().await?;
        match resp.status() {
            StatusCode::OK => {
                let body: NextFriProverJobPayload = resp.json().await?;
                let data = STANDARD
                    .decode(&body.prover_input)
                    .map_err(|e| anyhow!("Failed to decode batch data: {e}"))?;
                Ok(Some((body.batch_number, data)))
            }
            StatusCode::NO_CONTENT => Ok(None),
            _ => Err(anyhow!(
                "Unexpected status {resp:?} when peeking the batch {batch_number}"
            )),
        }
    }

    async fn peek_snark_job(
        &self,
        from_batch_number: u32,
        to_batch_number: u32,
    ) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = self.url.join(&format!(
            "{SEQUENCER_PROVER_API_PATH}/SNARK/{from_batch_number}/{to_batch_number}/peek"
        ))?;
        let resp = self.client.get(url).send().await?;
        match resp.status() {
            StatusCode::OK => {
                let get_snark_proof_payload = resp.json::<GetSnarkProofPayload>().await?;
                Ok(Some(
                    get_snark_proof_payload
                        .try_into()
                        .context("failed to parse SnarkProofPayload")?,
                ))
            }
            StatusCode::NO_CONTENT => Ok(None),
            _ => Err(anyhow!("Unexpected status {resp:?} when peeking FRI proofs from {from_batch_number} to {to_batch_number}")),
        }
    }

    async fn get_failed_fri_proof(
        &self,
        batch_number: u32,
    ) -> anyhow::Result<Option<FailedFriProofPayload>> {
        let url = self.url.join(&format!(
            "{SEQUENCER_PROVER_API_PATH}/FRI/{batch_number}/failed"
        ))?;
        let resp = self.client.get(url).send().await?;
        match resp.status() {
            StatusCode::OK => {
                let body: FailedFriProofPayload = resp.json().await?;
                Ok(Some(body))
            }
            StatusCode::NO_CONTENT => Ok(None),
            _ => Err(anyhow!(
                "Unexpected status {resp:?} when peeking failed FRI proof for batch {batch_number}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_sequencer_url() {
        let original_url: Url = "http://user:password123@localhost:3124".parse().unwrap();
        let mut expected_url = original_url.clone();
        expected_url.set_password(Some("******")).unwrap();

        let client =
            SequencerProofClient::new(original_url.clone(), "test_prover".to_string(), None)
                .expect("failed to create client");

        assert_eq!(&expected_url, &client.sanitized_url);
        check_url(&expected_url, &client.sequencer_url());
        check_url(&original_url, &client.url);
    }

    fn check_url(expected: &Url, got: &Url) {
        assert_eq!(expected.scheme(), got.scheme());
        assert_eq!(expected.host(), got.host());
        assert_eq!(expected.port(), got.port());
        assert_eq!(expected.username(), got.username());
        assert_eq!(expected.password(), got.password());
    }
}
