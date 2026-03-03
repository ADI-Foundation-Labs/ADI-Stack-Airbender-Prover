use std::time::{Duration, Instant};

use crate::metrics::{Method, SequencerClientLabel};
use crate::sequencer_endpoint::SequencerEndpoint;
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
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::StatusCode;
use serde_json;
use url::Url;
use zkos_wrapper::SnarkWrapperProof;

#[derive(Debug)]
pub struct SequencerProofClient {
    client: reqwest::Client,
    endpoint: Url,
    prover_name: String,
}

impl SequencerProofClient {
    /// Create a new proof sequencer client.
    ///
    /// # Arguments
    /// * `endpoint` - The sequencer endpoint (URL + optional credentials)
    /// * `prover_name` - The name of the prover (used for identification in sequencer prover api)
    /// * `timeout` - Optional timeout for requests (None defaults to 2 seconds)
    ///
    /// # Errors
    /// * if building the reqwest client fails
    pub fn new(
        endpoint: SequencerEndpoint,
        prover_name: String,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();

        // Add Basic Auth header if credentials are present
        if let Some(creds) = &endpoint.credentials {
            use secrecy::ExposeSecret;
            let auth_value = format!(
                "Basic {}",
                STANDARD.encode(format!(
                    "{}:{}",
                    creds.username,
                    creds.password.expose_secret()
                ))
            );
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_value).context("Failed to create auth header value")?,
            );
        }

        let client = reqwest::Client::builder()
            .timeout(timeout.unwrap_or(Duration::from_secs(2)))
            .default_headers(headers)
            .build()
            .context("Failed to build reqwest client")?;

        Ok(Self {
            client,
            endpoint: endpoint.url,
            prover_name,
        })
    }

    /// Create multiple sequencer proof clients from a list of endpoints.
    ///
    /// # Arguments
    /// * `endpoints` - A vector of sequencer endpoints
    /// * `prover_name` - The name of the prover (used for identification in sequencer prover api)
    /// * `timeout` - Optional timeout for requests (None defaults to 2 seconds)
    ///
    /// # Errors
    /// * if there are no endpoints provided (empty vector)
    /// * if creating any of the clients fails
    pub fn new_clients(
        endpoints: Vec<SequencerEndpoint>,
        prover_name: String,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Vec<Box<dyn ProofClient + Send + Sync>>> {
        if endpoints.is_empty() {
            return Err(anyhow!("No sequencer endpoints provided"));
        }

        endpoints
            .into_iter()
            .enumerate()
            .map(|(i, endpoint)| {
                let url = endpoint.url.clone();
                let client = SequencerProofClient::new(endpoint, prover_name.clone(), timeout)
                    .with_context(|| {
                        format!("Failed to create sequencer client #{i} at url {url:?}")
                    })?;

                Ok(Box::new(client) as Box<dyn ProofClient + Send + Sync>)
            })
            .collect()
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

    /// Constructs a prover API endpoint URL.
    fn build_url(&self, path: &str) -> anyhow::Result<Url> {
        let url = self
            .endpoint
            .join("prover-jobs/v1/")?
            .join(path)
            .with_context(|| format!("Failed to build URL for path: {path}"))?;
        Ok(url)
    }
}

#[async_trait]
impl ProofClient for SequencerProofClient {
    fn sequencer_url(&self) -> &Url {
        &self.endpoint
    }

    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
        let url = self.build_url(&format!("FRI/pick?id={}", self.prover_name))?;

        let started_at = Instant::now();

        let resp = self
            .client
            .post(url.clone())
            .send()
            .await
            .context("Pick Fri Job request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&SequencerClientLabel {
            sequencer: self.endpoint.to_string(),
            r#type: Method::PickFri,
        }]
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

    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
    ) -> anyhow::Result<()> {
        let url = self.build_url(&format!("FRI/submit?id={}", self.prover_name))?;

        let payload = SubmitFriProofPayload {
            batch_number: batch_number as u64,
            vk_hash,
            proof,
        };

        let started_at = Instant::now();

        let resp = self
            .client
            .post(url.clone())
            .json(&payload)
            .send()
            .await
            .context("Submit Fri Proof request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&SequencerClientLabel {
            sequencer: self.endpoint.to_string(),
            r#type: Method::SubmitFri,
        }]
        .observe(started_at.elapsed().as_secs_f64());

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Server returned {} when submitting proof to {}",
                resp.status(),
                url
            ))
        }
    }

    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = self.build_url(&format!("SNARK/pick?id={}", self.prover_name))?;

        let started_at = Instant::now();

        let resp = self
            .client
            .post(url.clone())
            .send()
            .await
            .context("Pick Snark Job request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&SequencerClientLabel {
            sequencer: self.endpoint.to_string(),
            r#type: Method::PickSnark,
        }]
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
            s => Err(anyhow!("Failed to pick SNARK job: status {s} from {url}")),
        }
    }

    async fn submit_snark_proof(
        &self,
        from_batch_number: L2BatchNumber,
        to_batch_number: L2BatchNumber,
        vk_hash: String,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        let url = self.build_url(&format!("SNARK/submit?id={}", self.prover_name))?;

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
            .post(url.clone())
            .json(&payload)
            .send()
            .await
            .context("Submit Snark Proof request failed")?
            .error_for_status()
            .context("Request returned error status")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&SequencerClientLabel {
            sequencer: self.endpoint.to_string(),
            r#type: Method::SubmitSnark,
        }]
        .observe(started_at.elapsed().as_secs_f64());
        Ok(())
    }
}

#[async_trait]
impl PeekableProofClient for SequencerProofClient {
    async fn peek_fri_job(&self, batch_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let url = self.build_url(&format!("FRI/{batch_number}/peek"))?;
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .context("Peek Fri Job request failed")?;

        match resp.status() {
            StatusCode::OK => {
                let body: NextFriProverJobPayload = resp.json().await?;
                let data = STANDARD
                    .decode(&body.prover_input)
                    .map_err(|e| anyhow!("Failed to decode batch data: {e}"))?;
                Ok(Some((body.batch_number, data)))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!(
                "Unexpected status {s} when peeking the batch {batch_number} at {url}",
            )),
        }
    }

    async fn peek_snark_job(
        &self,
        from_batch_number: u32,
        to_batch_number: u32,
    ) -> anyhow::Result<Option<SnarkProofInputs>> {
        let url = self.build_url(&format!("SNARK/{from_batch_number}/{to_batch_number}/peek"))?;
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .context("Peek Snark Job request failed")?;

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
            s => Err(anyhow!(
                "Unexpected status {s} when peeking FRI proofs from {from_batch_number} to {to_batch_number} at {url}",
            )),
        }
    }

    async fn get_failed_fri_proof(
        &self,
        batch_number: u32,
    ) -> anyhow::Result<Option<FailedFriProofPayload>> {
        let url = self.build_url(&format!("FRI/{batch_number}/failed"))?;
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .context("Get Failed Fri Proof request failed")?;

        match resp.status() {
            StatusCode::OK => {
                let body: FailedFriProofPayload = resp.json().await?;
                Ok(Some(body))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!(
                "Unexpected status {s} when peeking failed FRI proof for batch {batch_number} at {url}",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_strips_credentials() {
        let endpoint = SequencerEndpoint::parse("http://user:password123@localhost:3124").unwrap();

        let client = SequencerProofClient::new(endpoint, "test_prover".to_string(), None)
            .expect("failed to create client");

        // URL should be clean (no credentials)
        let url = client.sequencer_url();
        assert_eq!(url.username(), "");
        assert_eq!(url.password(), None);
        assert_eq!(url.as_str(), "http://localhost:3124/");
    }

    #[test]
    fn test_client_without_credentials() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();

        let client = SequencerProofClient::new(endpoint, "test_prover".to_string(), None)
            .expect("failed to create client");

        let url = client.sequencer_url();
        assert_eq!(url.as_str(), "http://localhost:3124/");
    }
}
