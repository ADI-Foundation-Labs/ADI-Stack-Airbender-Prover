use std::time::Instant;

use crate::metrics::Method;
use crate::ownership::{FriJobStatusPayload, SnarkJobStatusPayload};
use crate::sequencer_endpoint::SequencerEndpoint;
use crate::{
    backend::{self, Backend, Latch},
    ClientTimeouts, FailedFriProofPayload, FriJobInputs, FriJobOwnership, GetSnarkProofPayload,
    NextFriProverJobPayload, PeekableProofClient, ProofClient, SnarkProofInputs, SnarkRunOwnership,
    SubmitFriProofPayload, SubmitSnarkProofPayload,
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
    timeouts: ClientTimeouts,
    supported_vk_hashes: Vec<String>,
    /// Which backend answers `endpoint`, once [`Self::detect_backend`] has asked.
    backend: Latch,
}

impl SequencerProofClient {
    /// Creates a proof client for one sequencer endpoint.
    ///
    /// `supported_vk_hashes` rides on every pick request, so the sequencer only assigns jobs
    /// of those versions; an empty list declares nothing and takes jobs of any version.
    ///
    /// Crate-private: it leaves the backend unprobed, and such a client never cancels.
    /// [`Self::new_clients`] is the public constructor.
    ///
    /// # Errors
    /// * if building the reqwest client fails
    pub(crate) fn new(
        endpoint: SequencerEndpoint,
        prover_name: String,
        timeouts: ClientTimeouts,
        supported_vk_hashes: Vec<String>,
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
            .timeout(timeouts.request)
            .default_headers(headers)
            .build()
            .context("Failed to build reqwest client")?;

        Ok(Self {
            client,
            endpoint: endpoint.url,
            prover_name,
            timeouts,
            supported_vk_hashes,
            backend: Latch::default(),
        })
    }

    /// Probes the endpoint for the first time and names the backend it found.
    ///
    /// # Errors
    /// * if the SNARK status URL cannot be built
    pub(crate) async fn detect_backend(&self) -> anyhow::Result<()> {
        let backend = self.probe_backend().await?;

        tracing::info!(
            "Sequencer {} answers as {backend}, so {}",
            self.endpoint,
            backend.cancellation_posture()
        );

        Ok(())
    }

    /// Probes the endpoint and stores the answer in the latch.
    async fn probe_backend(&self) -> anyhow::Result<Backend> {
        let url = self.build_url(&format!("SNARK/status/?id={}", self.prover_name))?;
        let backend = backend::probe(&self.client, &url, self.timeouts.cancel_request).await;

        self.backend.set(backend);
        Ok(backend)
    }

    /// Creates one client per sequencer endpoint, all sharing the same configuration, and
    /// probes each endpoint for the backend behind it.
    ///
    /// # Errors
    /// * if there are no endpoints provided (empty vector)
    /// * if creating or probing any of the clients fails
    pub async fn new_clients(
        endpoints: Vec<SequencerEndpoint>,
        prover_name: String,
        timeouts: ClientTimeouts,
        supported_vk_hashes: Vec<String>,
    ) -> anyhow::Result<Vec<Box<dyn ProofClient + Send + Sync>>> {
        if endpoints.is_empty() {
            return Err(anyhow!("No sequencer endpoints provided"));
        }

        let mut clients: Vec<Box<dyn ProofClient + Send + Sync>> =
            Vec::with_capacity(endpoints.len());

        for (i, endpoint) in endpoints.into_iter().enumerate() {
            let url = endpoint.url.clone();
            let client = SequencerProofClient::new(
                endpoint,
                prover_name.clone(),
                timeouts,
                supported_vk_hashes.clone(),
            )
            .with_context(|| format!("Failed to create sequencer client #{i} at url {url:?}"))?;

            client
                .detect_backend()
                .await
                .with_context(|| format!("Failed to probe sequencer client #{i} at url {url:?}"))?;

            clients.push(Box::new(client));
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

    /// Sends `request`, noting the backend its answer announces.
    ///
    /// Every call the prover already makes carries the announcement, so a mux names itself
    /// on the first real request and the probe above is only the fallback.
    async fn send(&self, request: reqwest::RequestBuilder) -> reqwest::Result<reqwest::Response> {
        let response = request.send().await?;
        self.backend.observe(response.headers());

        Ok(response)
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

    /// Query string for pick requests: prover id plus, if declared, the supported VK hashes.
    /// Sequencers aware of `supported_vk_hashes` only assign jobs of these versions;
    /// older sequencers ignore the parameter.
    fn pick_query(&self) -> String {
        if self.supported_vk_hashes.is_empty() {
            format!("id={}", self.prover_name)
        } else {
            format!(
                "id={}&supported_vk_hashes={}",
                self.prover_name,
                self.supported_vk_hashes.join(",")
            )
        }
    }
}

#[async_trait]
impl ProofClient for SequencerProofClient {
    fn sequencer_url(&self) -> &Url {
        &self.endpoint
    }

    fn supports_cancellation(&self) -> bool {
        self.backend.supports_cancellation()
    }

    async fn refresh_backend(&self) {
        if !self.backend.wants_reprobe(backend::REPROBE_INTERVAL) {
            return;
        }

        let Ok(backend) = self.probe_backend().await.inspect_err(|err| {
            tracing::warn!("Backend re-probe of {} failed: {err}", self.endpoint);
        }) else {
            return;
        };

        if !backend.supports_cancellation() {
            return;
        }

        tracing::info!(
            "Sequencer {} now answers as {backend}, so ownership checks start against it",
            self.endpoint
        );
    }

    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
        let url = self.build_url(&format!("FRI/pick?{}", self.pick_query()))?;

        let started_at = Instant::now();

        let resp = self
            .send(self.client.post(url.clone()))
            .await
            .context("Pick Fri Job request failed")?;

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
            .send(self.client.post(url.clone()).json(&payload))
            .await
            .context("Submit Fri Proof request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SubmitFri]
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
        let url = self.build_url(&format!("SNARK/pick?{}", self.pick_query()))?;

        let started_at = Instant::now();

        let resp = self
            .send(self.client.post(url.clone()))
            .await
            .context("Pick Snark Job request failed")?;

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
            s => Err(anyhow!("Failed to pick SNARK job: status {s} from {url}")),
        }
    }

    async fn fri_job_ownership(&self, batch_number: u32) -> anyhow::Result<FriJobOwnership> {
        let url = self.build_url(&format!("status/?id={}", self.prover_name))?;

        let started_at = Instant::now();

        let resp = self
            .send(
                self.client
                    .get(url.clone())
                    .timeout(self.timeouts.cancel_request),
            )
            .await
            .context("Fri Job Status request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::FriJobStatus]
            .observe(started_at.elapsed().as_secs_f64());

        if resp.status() != StatusCode::OK {
            return Err(anyhow!(
                "Unexpected status {} when reading job status at {url}",
                resp.status()
            ));
        }

        let entries: Vec<FriJobStatusPayload> = resp
            .json()
            .await
            .context("Failed to parse job status body")?;

        Ok(FriJobOwnership::classify(
            entries,
            batch_number,
            &self.prover_name,
        ))
    }

    async fn snark_run_ownership(&self, from: u32, to: u32) -> anyhow::Result<SnarkRunOwnership> {
        let url = self.build_url(&format!("SNARK/status/?id={}", self.prover_name))?;

        let started_at = Instant::now();

        let resp = self
            .send(
                self.client
                    .get(url.clone())
                    .timeout(self.timeouts.cancel_request),
            )
            .await
            .context("Snark Run Status request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SnarkRunStatus]
            .observe(started_at.elapsed().as_secs_f64());

        if resp.status() != StatusCode::OK {
            return Err(anyhow!(
                "Unexpected status {} when reading SNARK job status at {url}",
                resp.status()
            ));
        }

        let entries: Vec<SnarkJobStatusPayload> = resp
            .json()
            .await
            .context("Failed to parse SNARK job status body")?;

        Ok(SnarkRunOwnership::classify(
            entries,
            from,
            to,
            &self.prover_name,
        ))
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
        self.send(self.client.post(url.clone()).json(&payload))
            .await
            .context("Submit Snark Proof request failed")?
            .error_for_status()
            .context("Request returned error status")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SubmitSnark]
            .observe(started_at.elapsed().as_secs_f64());
        Ok(())
    }
}

#[async_trait]
impl PeekableProofClient for SequencerProofClient {
    async fn peek_fri_job(&self, batch_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let url = self.build_url(&format!("FRI/{batch_number}/peek"))?;
        let resp = self
            .send(self.client.get(url.clone()))
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
            .send(self.client.get(url.clone()))
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
            .send(self.client.get(url.clone()))
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
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::*;

    #[test]
    fn test_client_strips_credentials() {
        let endpoint = SequencerEndpoint::parse("http://user:password123@localhost:3124").unwrap();

        let client = SequencerProofClient::new(
            endpoint,
            "test_prover".to_string(),
            ClientTimeouts::default(),
            vec![],
        )
        .expect("failed to create client");

        // URL should be clean (no credentials)
        let url = client.sequencer_url();
        assert_eq!(url.username(), "");
        assert_eq!(url.password(), None);
        assert_eq!(url.as_str(), "http://localhost:3124/");
    }

    #[test]
    fn test_pick_query_without_supported_vk_hashes() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
        let client = SequencerProofClient::new(
            endpoint,
            "test_prover".to_string(),
            ClientTimeouts::default(),
            vec![],
        )
        .expect("failed to create client");

        assert_eq!(client.pick_query(), "id=test_prover");
    }

    #[test]
    fn test_pick_query_with_supported_vk_hashes() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
        let client = SequencerProofClient::new(
            endpoint,
            "test_prover".to_string(),
            ClientTimeouts::default(),
            vec!["0xaaaa".to_string(), "0xbbbb".to_string()],
        )
        .expect("failed to create client");

        assert_eq!(
            client.pick_query(),
            "id=test_prover&supported_vk_hashes=0xaaaa,0xbbbb"
        );
    }

    #[test]
    fn test_client_without_credentials() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();

        let client = SequencerProofClient::new(
            endpoint,
            "test_prover".to_string(),
            ClientTimeouts::default(),
            vec![],
        )
        .expect("failed to create client");

        let url = client.sequencer_url();
        assert_eq!(url.as_str(), "http://localhost:3124/");
    }

    fn test_client() -> SequencerProofClient {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
        SequencerProofClient::new(
            endpoint,
            "prover-a".to_string(),
            ClientTimeouts::default(),
            vec![],
        )
        .expect("failed to create client")
    }

    /// A pick URL carries two parameters, and `build_url`'s second join is the one that
    /// could drop them.
    #[test]
    fn built_pick_urls_keep_every_parameter() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
        let client = SequencerProofClient::new(
            endpoint,
            "prover-a".to_string(),
            ClientTimeouts::default(),
            vec!["0xaaaa".to_string(), "0xbbbb".to_string()],
        )
        .expect("failed to create client");

        let url = client
            .build_url(&format!("FRI/pick?{}", client.pick_query()))
            .expect("failed to build url");

        assert_eq!(
            url.as_str(),
            "http://localhost:3124/prover-jobs/v1/FRI/pick?id=prover-a&supported_vk_hashes=0xaaaa,0xbbbb"
        );
    }

    /// `build_url` joins twice, and the second join is the one that could drop a query.
    #[test]
    fn built_urls_keep_the_query_string() {
        let client = test_client();

        assert_eq!(
            client.build_url("status/?id=prover-a").unwrap().as_str(),
            "http://localhost:3124/prover-jobs/v1/status/?id=prover-a"
        );
        assert_eq!(
            client
                .build_url("SNARK/status/?id=prover-a")
                .unwrap()
                .as_str(),
            "http://localhost:3124/prover-jobs/v1/SNARK/status/?id=prover-a"
        );
    }

    /// mux answers 400 without an id, because `/status/` carries no chain field and it
    /// cannot tell whose batch a number refers to. A raw sequencer ignores the param.
    #[test]
    fn ownership_urls_name_the_prover() {
        let client = test_client();

        let fri = client
            .build_url(&format!("status/?id={}", client.prover_name))
            .unwrap();
        let snark = client
            .build_url(&format!("SNARK/status/?id={}", client.prover_name))
            .unwrap();

        assert_eq!(fri.query(), Some("id=prover-a"));
        assert_eq!(snark.query(), Some("id=prover-a"));
        assert_eq!(fri.path(), "/prover-jobs/v1/status/");
        assert_eq!(snark.path(), "/prover-jobs/v1/SNARK/status/");
    }

    /// Accepts a connection and never answers, so a request to it can only time out.
    fn silent_url() -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
        let address = listener.local_addr().expect("bound socket has an address");

        std::thread::spawn(move || {
            // Accepted streams are held, not dropped: a closed connection would fail the
            // request instantly instead of letting it run into the timeout.
            let mut accepted = Vec::new();
            while let Ok((stream, _)) = listener.accept() {
                accepted.push(stream);
            }
        });

        Url::parse(&format!("http://{address}")).expect("valid url")
    }

    /// A client whose ownership reads are bounded far tighter than its client-wide timeout,
    /// pointed at a server that never answers.
    fn client_against_silence() -> SequencerProofClient {
        let endpoint = SequencerEndpoint::parse(silent_url().as_str()).expect("valid url");

        SequencerProofClient::new(
            endpoint,
            "prover-a".to_string(),
            ClientTimeouts {
                request: Duration::from_secs(10),
                cancel_request: Duration::from_millis(200),
            },
            vec![],
        )
        .expect("failed to create client")
    }

    /// Fails unless the read gave up on `cancel_request` rather than on the client-wide
    /// `request` timeout that pick and submit share.
    fn assert_gave_up_on_the_cancel_timeout(err: &anyhow::Error, elapsed: Duration) {
        assert!(
            err.downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout),
            "expected a timeout, got: {err:#}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the read waited {elapsed:?}, so it used the client-wide timeout"
        );
    }

    #[tokio::test]
    async fn fri_ownership_reads_use_the_cancel_timeout() {
        let client = client_against_silence();

        let started_at = Instant::now();
        let err = client
            .fri_job_ownership(1)
            .await
            .expect_err("a silent server cannot answer");

        assert_gave_up_on_the_cancel_timeout(&err, started_at.elapsed());
    }

    /// The SNARK read carries its own `.timeout()` call, and it is the whole cancellation
    /// path of the SNARK prover.
    #[tokio::test]
    async fn snark_ownership_reads_use_the_cancel_timeout() {
        let client = client_against_silence();

        let started_at = Instant::now();
        let err = client
            .snark_run_ownership(1, 2)
            .await
            .expect_err("a silent server cannot answer");

        assert_gave_up_on_the_cancel_timeout(&err, started_at.elapsed());
    }

    /// An HTTP server that answers every request with one fixed status and keeps the
    /// request lines it was sent.
    struct FakeBackend {
        url: Url,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl FakeBackend {
        /// Starts a server answering `status_line`, e.g. `"404 Not Found"`.
        fn answering(status_line: &str) -> Self {
            Self::serving(status_line, "")
        }

        /// Starts a server answering `status_line` and naming itself a mux, as v0.3.0 does.
        fn announcing(status_line: &str) -> Self {
            Self::serving(status_line, "mux-version: 0.3.0 (abc1234)\r\n")
        }

        /// Starts a server answering `status_line` with `extra_headers` appended.
        fn serving(status_line: &str, extra_headers: &str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
            let address = listener.local_addr().expect("bound socket has an address");
            let response = format!(
                "HTTP/1.1 {status_line}\r\n{extra_headers}content-length: 0\r\nconnection: close\r\n\r\n"
            );

            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorder = Arc::clone(&requests);

            std::thread::spawn(move || {
                while let Ok((mut stream, _)) = listener.accept() {
                    // Drain the request before answering: closing on unread bytes reaches
                    // the client as a reset instead of the status we want it to read.
                    let mut buffer = [0u8; 1024];
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    if let Some(line) = request.lines().next() {
                        recorder
                            .lock()
                            .expect("request log is not poisoned")
                            .push(line.to_string());
                    }

                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });

            Self {
                url: Url::parse(&format!("http://{address}")).expect("valid url"),
                requests,
            }
        }

        /// The request lines the server has been sent so far.
        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("request log is not poisoned")
                .clone()
        }
    }

    /// Builds a client against `url` without probing it.
    fn unprobed_client(url: &Url) -> SequencerProofClient {
        let endpoint = SequencerEndpoint::parse(url.as_str()).expect("valid url");

        SequencerProofClient::new(
            endpoint,
            "prover-a".to_string(),
            ClientTimeouts {
                request: Duration::from_secs(10),
                cancel_request: Duration::from_millis(200),
            },
            vec![],
        )
        .expect("failed to create client")
    }

    /// Builds a client against `url` and probes it, as `new_clients` does at startup.
    async fn probed_client(url: &Url) -> SequencerProofClient {
        let client = unprobed_client(url);

        client.detect_backend().await.expect("failed to probe");
        client
    }

    /// The probe is the SNARK status read, named after this prover: mux rejects the route
    /// without an id, so a probe that dropped it would read every mux as a plain sequencer.
    #[tokio::test]
    async fn the_probe_asks_the_snark_status_route() {
        let backend = FakeBackend::answering("200 OK");

        probed_client(&backend.url).await;

        assert_eq!(
            backend.requests(),
            vec!["GET /prover-jobs/v1/SNARK/status/?id=prover-a HTTP/1.1".to_string()]
        );
    }

    /// The route exists on a mux alone, so answering it at all is the positive.
    #[tokio::test]
    async fn a_served_snark_status_route_reads_as_mux() {
        let backend = FakeBackend::answering("200 OK");

        assert!(probed_client(&backend.url).await.supports_cancellation());
    }

    /// The sequencer's route table has no SNARK status path, so axum falls through to 404.
    #[tokio::test]
    async fn a_404_reads_as_a_plain_sequencer() {
        let backend = FakeBackend::answering("404 Not Found");

        assert!(!probed_client(&backend.url).await.supports_cancellation());
    }

    /// The header is certain where the route table is a guess, so it outranks the status.
    /// An ingress that 404s a live mux mid-rollout must not cost cancellation.
    #[tokio::test]
    async fn an_announced_mux_outranks_a_404() {
        let backend = FakeBackend::announcing("404 Not Found");

        assert!(probed_client(&backend.url).await.supports_cancellation());
    }

    /// Every call carries the announcement, so a mux names itself without a probe at all.
    #[tokio::test]
    async fn a_pick_against_an_announced_mux_turns_cancellation_on() {
        let backend = FakeBackend::announcing("204 No Content");
        let client = unprobed_client(&backend.url);
        assert!(!client.supports_cancellation());

        client.pick_fri_job().await.expect("204 is an empty pick");

        assert!(client.supports_cancellation());
        assert_eq!(
            backend.requests(),
            vec!["POST /prover-jobs/v1/FRI/pick?id=prover-a HTTP/1.1".to_string()],
            "the pick alone must settle the backend, with no probe beside it"
        );
    }

    /// mux answers 503 when its store is unreadable, which says nothing about the backend.
    #[tokio::test]
    async fn an_unreadable_store_still_reads_as_mux() {
        let backend = FakeBackend::answering("503 Service Unavailable");

        assert!(probed_client(&backend.url).await.supports_cancellation());
    }

    /// A URL that will not answer must not block startup, nor lose cancellation silently.
    #[tokio::test]
    async fn a_silent_url_reads_as_mux() {
        let url = silent_url();
        let started_at = Instant::now();

        assert!(probed_client(&url).await.supports_cancellation());
        assert!(
            started_at.elapsed() < Duration::from_secs(3),
            "the probe waited {:?}, so it ignored the cancel timeout",
            started_at.elapsed()
        );
    }

    /// A sequencer that is not up yet reads as mux too — only a 404 is a sound negative.
    #[tokio::test]
    async fn a_refused_connection_reads_as_mux() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
        let address = listener.local_addr().expect("bound socket has an address");
        drop(listener);
        let url = Url::parse(&format!("http://{address}")).expect("valid url");

        assert!(probed_client(&url).await.supports_cancellation());
    }

    /// Cancellation is opt-in per URL: a client built by hand has not probed anything.
    #[test]
    fn an_unprobed_client_does_not_cancel() {
        assert!(!test_client().supports_cancellation());
    }
}
