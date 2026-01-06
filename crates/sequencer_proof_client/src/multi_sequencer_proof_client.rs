use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use url::Url;

use crate::{FriJobInputs, L2BatchNumber, ProofClient, SnarkProofInputs};
use zkos_wrapper::SnarkWrapperProof;

/// A proof client that distributes requests across multiple sequencer URLs using round-robin.
///
/// This client maintains a current index that cycles through the list of available clients,
/// ensuring load distribution across multiple sequencers.
pub struct MultiSequencerProofClient {
    clients: Vec<Box<dyn ProofClient + Send + Sync>>,
    current_index: AtomicUsize,
}

impl std::fmt::Debug for MultiSequencerProofClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("MultiSequencerProofClient");
        debug.field(
            "clients",
            &format_args!(
                "[{}]",
                self.clients
                    .iter()
                    .map(|c| format!("ProofClient(\"{}\")", c.sequencer_url()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        debug.field("current_index", &self.current_index.load(Ordering::SeqCst));
        debug.finish()
    }
}

impl MultiSequencerProofClient {
    /// Create a new `MultiSequencerProofClient` with a list of sequencer URLs.
    ///
    /// # Arguments
    /// * `clients` - A vector of sequencer client implementations
    pub fn new(clients: Vec<Box<dyn ProofClient + Send + Sync>>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !clients.is_empty(),
            "At least one sequencer client must be provided"
        );

        tracing::info!(
            "Initializing MultiSequencerProofClient with {} sequencer(s):",
            clients.len()
        );
        for c in clients.iter() {
            tracing::info!("  - {}", c.sequencer_url());
        }

        Ok(Self {
            clients,
            current_index: AtomicUsize::new(0),
        })
    }

    /// Get the current client without advancing the counter.
    fn current_client(&self) -> &(dyn ProofClient + Send + Sync) {
        let index = self.current_index.load(Ordering::SeqCst);
        &*self.clients[index]
    }

    /// Get the current client in round-robin fashion and advance the counter for next calls.
    fn current_client_and_increment(&self) -> &(dyn ProofClient + Send + Sync) {
        let index = self
            .current_index
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current_index| {
                Some((current_index + 1) % self.clients.len())
            })
            .expect("failed to update current index, should never happen");
        &*self.clients[index]
    }
}

#[async_trait]
impl ProofClient for MultiSequencerProofClient {
    fn sequencer_url(&self) -> &Url {
        self.current_client().sequencer_url()
    }

    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
        self.current_client().pick_fri_job().await
    }

    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
    ) -> anyhow::Result<()> {
        self.current_client_and_increment()
            .submit_fri_proof(batch_number, vk_hash, proof)
            .await
    }

    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        self.current_client().pick_snark_job().await
    }

    async fn submit_snark_proof(
        &self,
        from_batch_number: L2BatchNumber,
        to_batch_number: L2BatchNumber,
        vk_hash: String,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()> {
        self.current_client_and_increment()
            .submit_snark_proof(from_batch_number, to_batch_number, vk_hash, proof)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::SequencerProofClient;

    use super::*;

    // Mock client for testing pick and submit sequence
    struct MockProofClient {
        url: Url,
    }

    impl MockProofClient {
        fn new(url: Url) -> Self {
            Self { url }
        }

        fn new_clients(urls: Vec<Url>) -> Vec<Box<dyn ProofClient + Send + Sync>> {
            urls.into_iter()
                .map(|url| {
                    Box::new(MockProofClient::new(url)) as Box<dyn ProofClient + Send + Sync>
                })
                .collect()
        }
    }

    #[async_trait]
    impl ProofClient for MockProofClient {
        fn sequencer_url(&self) -> &Url {
            &self.url
        }

        async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
            Ok(None)
        }

        async fn submit_fri_proof(
            &self,
            _batch_number: u32,
            // Used as url for testing purposes, no VK here
            vk_hash: String,
            _proof: String,
        ) -> anyhow::Result<()> {
            assert_eq!(vk_hash, self.url.to_string());
            Ok(())
        }

        async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
            Ok(None)
        }

        async fn submit_snark_proof(
            &self,
            _from_batch_number: L2BatchNumber,
            _to_batch_number: L2BatchNumber,
            // Used as url for testing purposes, no VK here
            vk_hash: String,
            _proof: SnarkWrapperProof,
        ) -> anyhow::Result<()> {
            assert_eq!(vk_hash, self.url.to_string());
            Ok(())
        }
    }

    #[test]
    fn test_client_advances_and_returns_correct_index() {
        let urls = vec![
            "http://client-1.com".parse().unwrap(),
            "http://client-2.com".parse().unwrap(),
            "http://client-3.com".parse().unwrap(),
        ];
        let clients =
            SequencerProofClient::new_clients(urls.clone(), "test_prover".to_string(), None)
                .unwrap();
        let multi_client = MultiSequencerProofClient::new(clients).unwrap();

        // Check that current_client_and_increment() returns the correct client and advances the index, including wrapping around
        // When 3 is hit, we should be back to 0
        for i in 0..3 {
            let current_client = multi_client.current_client();
            assert_eq!(current_client.sequencer_url(), &urls[i]);
            let still_current_client = multi_client.current_client_and_increment();
            assert_eq!(still_current_client.sequencer_url(), &urls[i]);
            let next_client = multi_client.current_client();
            let expected_next_index = (i + 1) % urls.len();
            assert_eq!(next_client.sequencer_url(), &urls[expected_next_index]);
        }
    }

    // Test that FRI pick and submit happen to the same client via round-robin
    #[tokio::test]
    async fn test_fri_pick_and_submit_use_same_client() {
        let urls = vec![
            "http://client-1.com".parse().unwrap(),
            "http://client-2.com".parse().unwrap(),
            "http://client-3.com".parse().unwrap(),
        ];

        let multi_client =
            MultiSequencerProofClient::new(MockProofClient::new_clients(urls.clone())).unwrap();

        for i in 0..3 {
            multi_client.pick_fri_job().await.unwrap();
            assert_eq!(multi_client.sequencer_url(), &urls[i]);
            multi_client
                .submit_fri_proof(1, urls[i].to_string(), "proof".to_string())
                .await
                .unwrap();
            assert_eq!(multi_client.sequencer_url(), &urls[(i + 1) % urls.len()]);
        }
    }

    // Test that SNARK pick and submit happen to the same client via round-robin
    #[tokio::test]
    async fn test_snark_pick_and_submit_use_same_client() {
        let urls = vec![
            "http://client-1.com".parse().unwrap(),
            "http://client-2.com".parse().unwrap(),
            "http://client-3.com".parse().unwrap(),
        ];

        let multi_client =
            MultiSequencerProofClient::new(MockProofClient::new_clients(urls.clone())).unwrap();

        // Create a minimal dummy proof for testing - the mock client doesn't actually use it
        let dummy_proof: SnarkWrapperProof = serde_json::from_str(
            r#"{
                "n": 1,
                "inputs": [[0, 0, 0, 0]],
                "state_polys_commitments": [{"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false}],
                "witness_polys_commitments": [],
                "copy_permutation_grand_product_commitment": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false},
                "lookup_s_poly_commitment": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false},
                "lookup_grand_product_commitment": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false},
                "quotient_poly_parts_commitments": [{"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false}],
                "state_polys_openings_at_z": [[0, 0, 0, 0]],
                "state_polys_openings_at_dilations": [],
                "witness_polys_openings_at_z": [],
                "witness_polys_openings_at_dilations": [],
                "gate_setup_openings_at_z": [],
                "gate_selectors_openings_at_z": [],
                "copy_permutation_polys_openings_at_z": [[0, 0, 0, 0]],
                "copy_permutation_grand_product_opening_at_z_omega": [0, 0, 0, 0],
                "lookup_s_poly_opening_at_z_omega": [0, 0, 0, 0],
                "lookup_grand_product_opening_at_z_omega": [0, 0, 0, 0],
                "lookup_t_poly_opening_at_z": [0, 0, 0, 0],
                "lookup_t_poly_opening_at_z_omega": [0, 0, 0, 0],
                "lookup_selector_poly_opening_at_z": [0, 0, 0, 0],
                "lookup_table_type_poly_opening_at_z": [0, 0, 0, 0],
                "quotient_poly_opening_at_z": [0, 0, 0, 0],
                "linearization_poly_opening_at_z": [0, 0, 0, 0],
                "opening_proof_at_z": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false},
                "opening_proof_at_z_omega": {"x": [0, 0, 0, 0], "y": [0, 0, 0, 0], "infinity": false}
            }"#
        ).unwrap();

        for i in 0..3 {
            multi_client.pick_snark_job().await.unwrap();
            assert_eq!(multi_client.sequencer_url(), &urls[i]);
            multi_client
                .submit_snark_proof(
                    L2BatchNumber(1),
                    L2BatchNumber(2),
                    urls[i].to_string(),
                    dummy_proof.clone(),
                )
                .await
                .unwrap();
            assert_eq!(multi_client.sequencer_url(), &urls[(i + 1) % urls.len()]);
        }
    }
}
