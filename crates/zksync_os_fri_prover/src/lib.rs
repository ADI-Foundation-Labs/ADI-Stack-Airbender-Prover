use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD, Engine as _};

use clap::Parser;
use protocol_version::SupportedProtocolVersions;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use url::Url;
use zksync_airbender_cli::prover_utils::{
    create_proofs_internal, create_recursion_proofs, load_binary_from_path, serialize_to_file,
    GpuSharedState,
};
use zksync_airbender_execution_utils::{Machine, ProgramProof, RecursionStrategy};
use zksync_sequencer_proof_client::{
    FriJobInputs, MultiSequencerProofClient, ProofClient, SequencerProofClient,
};

use crate::metrics::FRI_PROVER_METRICS;

pub mod metrics;

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// List of sequencer URLs to poll for tasks (e.g., "http://<IP>:<PORT>")
    /// The prover will poll sequencers in round-robin fashion
    #[arg(
        short,
        long,
        alias = "base-url",
        value_delimiter = ',',
        default_value = "http://localhost:3124",
        value_parser = clap::value_parser!(Url)
    )]
    pub sequencer_urls: Vec<Url>,
    /// Enable logging and use the logging-enabled binary
    /// This is not used in the FRI prover, but is kept for backward compatibility.
    #[arg(long)]
    pub enabled_logging: bool,
    /// Path to `app.bin`
    #[arg(long)]
    pub app_bin_path: Option<PathBuf>,
    /// Circuit limit - max number of MainVM circuits to instantiate to run the batch fully
    #[arg(long, default_value = "10000")]
    pub circuit_limit: usize,
    /// Number of iterations before exiting. Only successfully generated proofs count. If not specified, runs indefinitely
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Port to run the Prometheus metrics server on
    #[arg(long, default_value = "3124")]
    pub prometheus_port: u16,

    /// Timeout for HTTP requests to sequencer in seconds. If no response is received within this time, the prover will exit.
    #[arg(long, default_value = "2")]
    pub request_timeout_secs: u64,

    /// Name of the prover for identification in the sequencer's prover api
    #[arg(long, default_value = "unknown_prover")]
    pub prover_name: String,
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

pub fn create_proof(
    prover_input: Vec<u32>,
    binary: &Vec<u32>,
    circuit_limit: usize,
    _gpu_state: &mut GpuSharedState,
) -> ProgramProof {
    let mut timing = Some(0f64);
    let (proof_list, proof_metadata) = create_proofs_internal(
        binary,
        prover_input,
        &Machine::Standard,
        circuit_limit,
        None,
        #[cfg(feature = "gpu")]
        &mut Some(_gpu_state),
        #[cfg(not(feature = "gpu"))]
        &mut None,
        &mut timing, // timing info
    );
    let (recursion_proof_list, recursion_proof_metadata) = create_recursion_proofs(
        proof_list,
        proof_metadata,
        // This is the default strategy (where recursion is done on reduced machine, and final step on 23 machine).
        RecursionStrategy::UseReducedLog23Machine,
        &None,
        #[cfg(feature = "gpu")]
        &mut Some(_gpu_state),
        #[cfg(not(feature = "gpu"))]
        &mut None,
        &mut timing, // timing info
    );

    ProgramProof::from_proof_list_and_metadata(&recursion_proof_list, &recursion_proof_metadata)
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(args.request_timeout_secs);

    let clients =
        SequencerProofClient::new_clients(args.sequencer_urls, args.prover_name, Some(timeout))
            .context("failed to create sequencer proof clients")?;

    let multi_client = MultiSequencerProofClient::new(clients)
        .context("failed to create multi sequencer proof client")?;
    tracing::debug!("Using sequencer client {:#?}", multi_client);

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };

    let supported_versions = SupportedProtocolVersions::default();
    tracing::info!("{:#?}", supported_versions);

    let binary_path = args
        .app_bin_path
        .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));
    let binary = load_binary_from_path(&binary_path.to_str().unwrap().to_string());
    // For regular fri proving, we keep using reduced RiscV machine.
    #[cfg(feature = "gpu")]
    let mut gpu_state = GpuSharedState::new(
        &binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    );
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = GpuSharedState::new(&binary);

    tracing::info!(
        "Starting Zksync OS FRI prover with request timeout of {}s",
        args.request_timeout_secs
    );

    let mut proof_count = 0;

    loop {
        tracing::debug!("Polling sequencer: {}", multi_client.sequencer_url());

        let proof_generated = run_inner(
            &multi_client,
            &binary,
            args.circuit_limit,
            &mut gpu_state,
            args.path.clone(),
            &supported_versions,
        )
        .await
        .expect("Failed to run FRI prover");

        if proof_generated {
            proof_count += 1;

            // Check if we've reached the iteration limit
            if let Some(max_proofs_generated) = args.iterations {
                if proof_count >= max_proofs_generated {
                    tracing::info!(
                        "Reached maximum iterations ({max_proofs_generated}), exiting...",
                    );
                    return Ok(());
                }
            }
        } else {
            // If no task was found, wait before trying again
            tracing::info!("No pending batches to prove from sequencer, retrying in 100ms...");
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
}

pub async fn run_inner(
    client: &dyn ProofClient,
    binary: &Vec<u32>,
    circuit_limit: usize,
    #[cfg(feature = "gpu")] gpu_state: &mut GpuSharedState,
    #[cfg(not(feature = "gpu"))] gpu_state: &mut GpuSharedState<'_>,
    path: Option<PathBuf>,
    supported_versions: &SupportedProtocolVersions,
) -> anyhow::Result<bool> {
    let FriJobInputs {
        batch_number,
        vk_hash,
        prover_input,
    } = match client.pick_fri_job().await {
        Err(err) => {
            // Check if the error is a timeout error
            if err
                .downcast_ref::<reqwest::Error>()
                .map(|e| e.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout waiting for response from sequencer {}: {err}",
                    client.sequencer_url()
                );
                tracing::error!("Exiting prover due to timeout");
                FRI_PROVER_METRICS.timeout_errors.inc();
                return Ok(false);
            }
            tracing::error!(
                "Error fetching next prover job from sequencer {}: {err}",
                client.sequencer_url()
            );
            return Ok(false);
        }
        Ok(Some(fri_job_input)) => {
            if !supported_versions.contains(&fri_job_input.vk_hash) {
                tracing::error!(
                    "Unsupported protocol version with vk_hash: {} for batch number {}",
                    fri_job_input.vk_hash,
                    fri_job_input.batch_number
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                return Ok(false);
            }
            fri_job_input
        }

        Ok(None) => {
            tracing::debug!(
                "No pending batches to prove from sequencer {}",
                client.sequencer_url()
            );
            return Ok(false);
        }
    };

    let started_at = Instant::now();

    // make prover_input (Vec<u8>) into Vec<u32>:
    let prover_input: Vec<u32> = prover_input
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();

    tracing::info!(
        "Starting proving batch number {} with vk hash {} from sequencer {}",
        batch_number,
        vk_hash,
        client.sequencer_url()
    );

    let proof = create_proof(prover_input, binary, circuit_limit, gpu_state);

    tracing::info!(
        "Finished proving batch number {} with vk hash {}",
        batch_number,
        vk_hash
    );

    let proof_bytes: Vec<u8> = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .expect("failed to bincode-serialize proof");

    // 2) base64-encode that binary blob
    let proof_b64 = STANDARD.encode(&proof_bytes);

    if let Some(ref path) = path {
        serialize_to_file(&proof_b64, path);
    }

    FRI_PROVER_METRICS
        .latest_proven_batch
        .set(batch_number as i64);

    FRI_PROVER_METRICS
        .time_taken
        .observe(started_at.elapsed().as_secs_f64());

    match client
        .submit_fri_proof(batch_number, vk_hash.clone(), proof_b64)
        .await
    {
        Ok(_) => tracing::info!(
            "Successfully submitted proof for batch number {} with vk hash {} to sequencer {}",
            batch_number,
            vk_hash,
            client.sequencer_url()
        ),
        Err(err) => {
            // Check if the error is a timeout error
            if err
                .downcast_ref::<reqwest::Error>()
                .map(|e| e.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout submitting proof for batch number {} with vk hash {} to sequencer {}: {}",
                    batch_number,
                    vk_hash,
                    client.sequencer_url(),
                    err
                );
                tracing::error!("Exiting prover due to timeout");
                FRI_PROVER_METRICS.timeout_errors.inc();
            }
            tracing::error!(
                "Failed to submit proof for batch number {} with vk hash {} to sequencer {}: {}",
                batch_number,
                vk_hash,
                client.sequencer_url(),
                err
            );
        }
    }

    Ok(true)
}
