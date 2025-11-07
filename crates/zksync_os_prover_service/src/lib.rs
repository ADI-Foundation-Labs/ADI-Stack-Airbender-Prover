// TODO!: This code base should be moved in a single binary.
// SNARK & FRI should be libs only and expose no binaries themselves.
// We'll need slightly more "involved" CLI args, but nothing too complex.
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use clap::Parser;
use protocol_version::SupportedProtocolVersions;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
#[cfg(feature = "gpu")]
use zkos_wrapper::gpu::snark::gpu_create_snark_setup_data;
use zksync_airbender_cli::prover_utils::load_binary_from_path;
#[cfg(not(feature = "gpu"))]
use zksync_airbender_cli::prover_utils::GpuSharedState;
#[cfg(feature = "gpu")]
use zksync_airbender_cli::prover_utils::GpuSharedState;
use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
#[cfg(feature = "gpu")]
use zksync_os_snark_prover::compute_compression_vk;
use zksync_sequencer_proof_client::sequencer_proof_client::SequencerProofClient;

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// Max SNARK latency in seconds (default value - 1 hour)
    #[arg(long, default_value = "3600", conflicts_with = "max_fris_per_snark")]
    pub max_snark_latency: Option<u64>,
    /// Max amount of FRI proofs per SNARK (default value - 100)
    #[arg(long, default_value = "100", conflicts_with = "max_snark_latency")]
    pub max_fris_per_snark: Option<usize>,
    /// Base URL for the proof-data server (e.g., "http://<IP>:<PORT>")
    #[arg(short, long, default_value = "http://localhost:3124")]
    pub base_url: String,
    /// Path to `app.bin`
    #[arg(long)]
    pub app_bin_path: Option<PathBuf>,
    /// Circuit limit - max number of MainVM circuits to instantiate to run the batch fully
    #[arg(long, default_value = "10000")]
    pub circuit_limit: usize,
    /// Directory to store the output files for SNARK prover
    #[arg(long)]
    pub output_dir: String,
    /// Path to the trusted setup file for SNARK prover
    #[arg(long)]
    pub trusted_setup_file: String,
    /// Number of iterations before exiting. Only successfully generated SNARK proofs count. If not specified, runs indefinitely
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file for FRI proofs
    #[arg(short, long)]
    pub fri_path: Option<PathBuf>,
    /// Disable ZK for SNARK proofs
    #[arg(long, default_value_t = false)]
    pub disable_zk: bool,
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

pub async fn run(args: Args) {
    let client = SequencerProofClient::new(args.base_url);

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };
    let binary_path = args
        .app_bin_path
        .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));
    let binary = load_binary_from_path(&binary_path.to_str().unwrap().to_string());
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    let supported_versions = SupportedProtocolVersions::default();
    tracing::info!("{:#?}", supported_versions);

    #[cfg(feature = "gpu")]
    let precomputations = {
        tracing::info!("Computing SNARK precomputations");
        let compression_vk = compute_compression_vk(binary_path.to_str().unwrap().to_string());
        let precomputations =
            gpu_create_snark_setup_data(&compression_vk, &args.trusted_setup_file);
        tracing::info!("Finished computing SNARK precomputations");
        precomputations
    };

    tracing::info!(
        "Starting Zksync OS Prover Service for {}",
        client.sequencer_url()
    );

    let mut snark_proof_count = 0;
    let mut snark_latency = Instant::now();

    loop {
        let mut fri_proof_count = 0;

        // For regular fri proving, we keep using reduced RiscV machine.
        #[cfg(feature = "gpu")]
        let mut gpu_state = GpuSharedState::new(
            &binary,
            zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
        );
        #[cfg(not(feature = "gpu"))]
        let mut gpu_state = GpuSharedState::new(&binary);

        // Run FRI prover until we hit one of the limits
        tracing::info!("Running FRI prover");
        loop {
            let proof_generated = zksync_os_fri_prover::run_inner(
                &client,
                &binary,
                args.circuit_limit,
                &mut gpu_state,
                args.fri_path.clone(),
                &supported_versions,
            )
            .await
            .expect("Failed to run FRI prover");

            fri_proof_count += proof_generated as usize;

            if let Some(max_snark_latency) = args.max_snark_latency {
                if snark_latency.elapsed().as_secs() >= max_snark_latency {
                    tracing::info!("SNARK latency reached max_snark_latency ({max_snark_latency} seconds), exiting FRI prover");
                    break;
                }
            }
            if let Some(max_fris_per_snark) = args.max_fris_per_snark {
                if fri_proof_count >= max_fris_per_snark {
                    tracing::info!("FRI proof count reached max_fris_per_snark ({max_fris_per_snark}), exiting FRI prover");
                    break;
                }
            }
        }
        #[cfg(feature = "gpu")]
        drop(gpu_state);

        // Here we do exactly one SNARK proof
        tracing::info!("Running SNARK prover");
        loop {
            let proof_generated = zksync_os_snark_prover::run_inner(
                &client,
                &verifier_binary,
                args.output_dir.clone(),
                args.trusted_setup_file.clone(),
                #[cfg(feature = "gpu")]
                &precomputations,
                args.disable_zk,
                &supported_versions,
            )
            .await
            .expect("Failed to run SNARK prover");

            if proof_generated {
                // Increment SNARK proof counter
                tracing::info!("Successfully run SNARK prover");
                snark_proof_count += proof_generated as usize;
                snark_latency = Instant::now();
                break;
            }
        }

        // Check if we've reached the iteration limit
        if let Some(max_iterations) = args.iterations {
            if snark_proof_count >= max_iterations {
                tracing::info!("Reached maximum iterations ({max_iterations}), exiting...",);
                break;
            }
        }
    }
}
