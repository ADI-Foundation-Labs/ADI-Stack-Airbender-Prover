use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use zkos_wrapper::gpu_config::{parse_byte_size, MAX_DEVICE_ALLOCATION_ENV};
use zksync_os_snark_prover::{
    generate_verification_key, init_tracing, metrics, run_linking_fri_snark,
};
use zksync_sequencer_proof_client::{ClientManager, SequencerEndpoint};

#[derive(Default, Debug, Serialize, Deserialize, Parser, Clone)]
pub struct SetupOptions {
    #[arg(long)]
    binary_path: String,

    #[arg(long)]
    output_dir: String,

    #[arg(long)]
    trusted_setup_file: String,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Cap the GPU device-memory pool used by zkos-wrapper / shivini. Accepts decimal
    /// (`32G`, `32GB`) or binary (`32Gi`, `32GiB`) Kubernetes-style sizes; bare
    /// integers are bytes. When unset, falls back to the
    /// `ZKOS_WRAPPER_MAX_DEVICE_ALLOCATION` env var, then to shivini's default
    /// (grab all free device memory at startup).
    #[arg(long, global = true, value_parser = parse_byte_size)]
    memory_limit: Option<usize>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // TODO: redo this command, naming is confusing
    /// Generate the snark verification keys
    GenerateKeys {
        #[clap(flatten)]
        setup: SetupOptions,
        /// Path to the output verification key file
        #[arg(long)]
        vk_verification_key_file: Option<String>,
    },

    RunProver {
        /// Sequencer URL(s) to poll for tasks. Comma-separated for round-robin.
        ///
        /// Format: http[s]://[username:password@]host:port
        ///
        /// Examples:
        ///   --sequencer-urls http://localhost:3124,https://user1:pass1@sequencer1.com:3124,https://user2:pass2@sequencer2.com
        ///
        /// Credentials are extracted and sent via HTTP Authorization headers.
        #[arg(
            short,
            long,
            alias = "sequencer-url",
            value_delimiter = ',',
            num_args = 1..,
            default_value = "http://localhost:3124"
        )]
        sequencer_urls: Vec<SequencerEndpoint>,
        /// Path to a file containing sequencer URLs (one per line).
        /// When provided, takes precedence over --sequencer-urls.
        /// The file is re-read if its modification time changes between proving rounds.
        #[arg(long)]
        sequencer_urls_file: Option<std::path::PathBuf>,
        #[clap(flatten)]
        setup: SetupOptions,
        /// Number of iterations before exiting. Only successfully generated proofs count. If not specified, runs indefinitely
        #[arg(long)]
        iterations: Option<usize>,
        /// Port to run the Prometheus metrics server on
        #[arg(long, default_value = "3124")]
        prometheus_port: u16,
        /// Timeout for HTTP requests to sequencer in seconds. If no response is received within this time, the prover will exit.
        #[arg(long, default_value = "2")]
        request_timeout_secs: u64,
        /// Disable ZK for SNARK proofs
        #[arg(long, default_value_t = false)]
        disable_zk: bool,
        /// Name of the prover for identification in the sequencer
        #[arg(long, default_value = "unknown_prover")]
        prover_name: String,
    },
}

fn main() {
    init_tracing();
    let cli = Cli::parse();

    // If --memory-limit was passed, expose it to zkos-wrapper via env var. The wrapper
    // reads this at every ProverContext::create site, so no further plumbing is needed.
    // An env var that's already set takes precedence (k8s Pod env wins, lets ops cap
    // memory without having to touch the prover command line).
    if let Some(bytes) = cli.memory_limit {
        if std::env::var_os(MAX_DEVICE_ALLOCATION_ENV).is_none() {
            // Safe: called before any threads spawn or any wrapper code runs.
            std::env::set_var(MAX_DEVICE_ALLOCATION_ENV, bytes.to_string());
        } else {
            tracing::warn!(
                "{MAX_DEVICE_ALLOCATION_ENV} is already set; --memory-limit value ignored"
            );
        }
    }
    if let Ok(raw) = std::env::var(MAX_DEVICE_ALLOCATION_ENV) {
        tracing::info!("GPU device memory pool capped at {raw} (via {MAX_DEVICE_ALLOCATION_ENV})");
    }

    match cli.command {
        Commands::GenerateKeys {
            setup:
                SetupOptions {
                    binary_path,
                    output_dir,
                    trusted_setup_file,
                },
            vk_verification_key_file,
        } => generate_verification_key(
            binary_path,
            output_dir,
            trusted_setup_file,
            vk_verification_key_file,
        ),
        Commands::RunProver {
            sequencer_urls,
            sequencer_urls_file,
            setup:
                SetupOptions {
                    binary_path,
                    output_dir,
                    trusted_setup_file,
                },
            iterations,
            prometheus_port,
            request_timeout_secs,
            disable_zk,
            prover_name,
        } => {
            // TODO: edit this comment
            // we need a bigger stack, due to crypto code exhausting default stack size, 40 MBs picked here
            // note that size is not allocated, only limits the amount to which it can grow
            let stack_size = 40 * 1024 * 1024;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .thread_stack_size(stack_size)
                .enable_all()
                .build()
                .expect("failed to build tokio context");

            let (stop_sender, stop_receiver) = watch::channel(false);

            runtime.block_on(async move {
                let metrics_handle = tokio::spawn(async move {
                    metrics::start_metrics_exporter(prometheus_port, stop_receiver).await
                });

                let timeout = Duration::from_secs(request_timeout_secs);

                let client_manager = ClientManager::new(
                    sequencer_urls_file,
                    sequencer_urls,
                    prover_name,
                    Some(timeout),
                )
                .expect("failed to create sequencer proof clients");

                tracing::info!(
                    "Starting zksync_os_snark_prover with request timeout of {}s",
                    request_timeout_secs
                );

                tokio::select! {
                    result = run_linking_fri_snark(
                        binary_path,
                        client_manager,
                        output_dir,
                        trusted_setup_file,
                        iterations,
                        disable_zk,
                    ) => {
                        tracing::info!("SNARK prover finished");
                        result.expect("SNARK prover finished with error");
                        stop_sender.send(true).expect("failed to send stop signal");
                    }
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("Stop request received, shutting down");
                    },
                }

                match tokio::time::timeout(Duration::from_secs(10), metrics_handle).await {
                    Ok(join_result) => {
                        if let Err(join_err) = join_result {
                            tracing::warn!("metrics task panicked or was cancelled: {join_err}");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Metrics exporter timed out, aborting: {e}");
                    }
                }
            });
        }
    }
}
