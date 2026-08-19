#[cfg(feature = "gpu")]
use proof_compression::serialization::PlonkSnarkVerifierCircuitDeviceSetupWrapper;
use protocol_version::SupportedProtocolVersions;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing_subscriber::{EnvFilter, FmtSubscriber};
#[cfg(feature = "gpu")]
use zkos_wrapper::{
    generate_risk_wrapper_vk,
    gpu::{compression::get_compression_setup, snark::gpu_create_snark_setup_data},
    BoojumWorker, CompressionVK, SnarkWrapperVK, StageTimer,
};
use zkos_wrapper::{prove_cancellable, serialize_to_file, SnarkWrapperProof};
use zksync_airbender_cli::prover_utils::{
    create_final_proofs_from_program_proof, create_proofs_internal, GpuSharedState,
};
use zksync_airbender_execution_utils::{
    generate_oracle_data_for_universal_verifier, generate_oracle_data_from_metadata_and_proof_list,
    get_padded_binary, Machine, ProgramProof, RecursionStrategy, VerifierCircuitsIdentifiers,
    UNIVERSAL_CIRCUIT_VERIFIER,
};
use zksync_sequencer_proof_client::{
    with_watchdog, CancelFlag, ProofClient, SnarkProofInputs, Watched,
};

use crate::metrics::{SnarkProofTimeStats, SnarkStage, SNARK_PROVER_METRICS};

pub mod metrics;

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

pub fn generate_verification_key(
    binary_path: String,
    output_dir: String,
    trusted_setup_file: String,
    vk_verification_key_file: Option<String>,
) {
    match zkos_wrapper::generate_vk(
        Some(binary_path),
        output_dir,
        Some(trusted_setup_file),
        true,
        zksync_airbender_execution_utils::RecursionStrategy::UseReducedLog23Machine,
    ) {
        Ok(key) => {
            if let Some(vk_file) = vk_verification_key_file {
                std::fs::write(vk_file, format!("{key:?}"))
                    .expect("Failed to write verification key to file");
            } else {
                tracing::info!("Verification key generated successfully: {:#?}", key);
            }
        }
        Err(e) => {
            tracing::error!("Error generating keys: {e}");
        }
    }
}

pub fn merge_fris(
    snark_proof_input: SnarkProofInputs,
    verifier_binary: &Vec<u32>,
    gpu_state: &mut Option<&mut GpuSharedState>,
    cancel: &CancelFlag,
) -> Option<ProgramProof> {
    SNARK_PROVER_METRICS
        .fri_proofs_merged
        .set(snark_proof_input.fri_proofs.len() as i64);

    if snark_proof_input.fri_proofs.len() == 1 {
        tracing::info!("No proof merging needed, only one proof provided");
        return Some(snark_proof_input.fri_proofs[0].clone());
    }
    tracing::info!("Starting proof merging");

    let mut proof = snark_proof_input.fri_proofs[0].clone();
    for i in 1..snark_proof_input.fri_proofs.len() {
        if cancel.is_cancelled() {
            tracing::info!(
                "Cancelled after linking {} of {} proofs",
                i,
                snark_proof_input.fri_proofs.len()
            );
            return None;
        }

        let up_to_batch = snark_proof_input.from_batch_number.0 + i as u32 - 1;
        let curr_batch = snark_proof_input.from_batch_number.0 + i as u32;
        tracing::info!(
            "Linking proofs up to {} with proof for batch {}",
            up_to_batch,
            curr_batch
        );
        let second_proof = snark_proof_input.fri_proofs[i].clone();

        let (first_metadata, first_proof_list) = proof.to_metadata_and_proof_list();
        let (second_metadata, second_proof_list) = second_proof.to_metadata_and_proof_list();

        let first_oracle =
            generate_oracle_data_from_metadata_and_proof_list(&first_metadata, &first_proof_list);
        let second_oracle =
            generate_oracle_data_from_metadata_and_proof_list(&second_metadata, &second_proof_list);

        let mut merged_input = vec![VerifierCircuitsIdentifiers::CombinedRecursionLayers as u32];
        merged_input.extend(first_oracle);
        merged_input.extend(second_oracle);

        let (mut current_proof_list, mut proof_metadata) = create_proofs_internal(
            verifier_binary,
            merged_input,
            &zksync_airbender_execution_utils::Machine::Reduced,
            100, // Guessing - FIXME!!
            Some(first_metadata.create_prev_metadata()),
            gpu_state,
            &mut Some(0f64),
        );
        // Let's do recursion.
        let mut recursion_level = 0;

        while current_proof_list.reduced_proofs.len() > 2 {
            if cancel.is_cancelled() {
                tracing::info!(
                    "Cancelled at recursion step {recursion_level} of batch {curr_batch}"
                );
                return None;
            }

            tracing::info!("Recursion step {} after fri merging", recursion_level);
            recursion_level += 1;
            let non_determinism_data =
                generate_oracle_data_for_universal_verifier(&proof_metadata, &current_proof_list);

            (current_proof_list, proof_metadata) = create_proofs_internal(
                verifier_binary,
                non_determinism_data,
                &Machine::Reduced,
                proof_metadata.total_proofs(),
                Some(proof_metadata.create_prev_metadata()),
                gpu_state,
                &mut Some(0f64),
            );
        }

        proof = ProgramProof::from_proof_list_and_metadata(&current_proof_list, &proof_metadata);
        tracing::info!("Finished linking proofs up to batch {}", up_to_batch);
    }

    // TODO: We can do a recursion step here as well, IIUC
    tracing::info!(
        "Finishing linking all proofs from {} to {}",
        snark_proof_input.from_batch_number,
        snark_proof_input.to_batch_number
    );
    Some(proof)
}

/// Both steps report onto their own stage timer and can stop on a cancel, so this returns
/// rather than panicking — nothing enforces "no cancel has been requested yet" locally.
#[cfg(feature = "gpu")]
pub fn compute_compression_vk(binary_path: String) -> anyhow::Result<CompressionVK> {
    let worker = BoojumWorker::new();
    let mut stages = StageTimer::new();

    let risc_wrapper_vk = generate_risk_wrapper_vk(
        Some(binary_path),
        true,
        RecursionStrategy::UseReducedLog23Machine,
        &worker,
    )
    .map_err(|err| anyhow::anyhow!("failed to generate the risc wrapper vk: {err}"))?;

    let (_, compression_vk, _) = get_compression_setup(&worker, risc_wrapper_vk, &mut stages)?;
    stages.finish();

    Ok(compression_vk)
}

pub async fn run_linking_fri_snark(
    _binary_path: String,
    clients: Vec<Box<dyn ProofClient + Send + Sync>>,
    output_dir: String,
    trusted_setup_file: String,
    iterations: Option<usize>,
    disable_zk: bool,
    cancel_poll_interval: Option<Duration>,
) -> anyhow::Result<()> {
    let startup_started_at = Instant::now();

    tracing::info!(
        "Initializing SNARK prover with {} sequencer(s):",
        clients.len()
    );
    for client in clients.iter() {
        tracing::info!("  - {}", client.sequencer_url());
    }

    let supported_versions = SupportedProtocolVersions::default();
    tracing::info!("{:#?}", supported_versions);

    match cancel_poll_interval {
        Some(interval) => tracing::info!("Checking run ownership every {}s", interval.as_secs()),
        None => tracing::warn!("Run ownership checks disabled, jobs will never be cancelled"),
    }

    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    #[cfg(feature = "gpu")]
    let precomputations = {
        tracing::info!("Computing SNARK precomputations");
        let compression_vk = compute_compression_vk(_binary_path)?;
        let precomputations = gpu_create_snark_setup_data(&compression_vk, &trusted_setup_file);
        tracing::info!("Finished computing SNARK precomputations");
        precomputations
    };

    SNARK_PROVER_METRICS
        .time_taken_startup
        .observe(startup_started_at.elapsed().as_secs_f64());

    let mut proof_count = 0;

    // Cycle through clients in round-robin fashion
    for client in clients.iter().cycle() {
        tracing::debug!("Polling sequencer: {}", client.sequencer_url());

        let proof_generated = run_inner(
            client.as_ref(),
            &verifier_binary,
            output_dir.clone(),
            trusted_setup_file.clone(),
            #[cfg(feature = "gpu")]
            &precomputations,
            disable_zk,
            &supported_versions,
            cancel_poll_interval,
        )
        .await
        .expect("Failed to run SNARK prover");

        if proof_generated {
            proof_count += 1;

            if let Some(max_proofs_generated) = iterations {
                if proof_count >= max_proofs_generated {
                    tracing::info!(
                        "Reached maximum iterations ({max_proofs_generated}), exiting..."
                    );
                    return Ok(());
                }
            }
        } else {
            // If no task was found, wait before trying again
            tracing::info!("No pending SNARK jobs from sequencer, retrying in 5s...");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    Ok(())
}

pub async fn run_inner(
    client: &dyn ProofClient,
    verifier_binary: &Vec<u32>,
    output_dir: String,
    trusted_setup_file: String,
    #[cfg(feature = "gpu")] precomputations: &(
        PlonkSnarkVerifierCircuitDeviceSetupWrapper,
        SnarkWrapperVK,
    ),
    disable_zk: bool,
    supported_protocol_versions: &SupportedProtocolVersions,
    cancel_poll_interval: Option<Duration>,
) -> anyhow::Result<bool> {
    tracing::debug!("Picking job from sequencer {}", client.sequencer_url());
    let snark_proof_input = match client.pick_snark_job().await {
        Ok(Some(snark_proof_input)) => {
            if snark_proof_input.fri_proofs.is_empty() {
                let err_msg =
                    "No FRI proofs were sent, issue with Prover API/Sequencer, quitting...";
                tracing::error!(err_msg);
                return Err(anyhow::anyhow!(err_msg));
            }
            if !supported_protocol_versions.contains(&snark_proof_input.vk_hash) {
                tracing::error!(
                    "Received unsupported protocol version with vk_hash {} for batches between [{} and {}] from sequencer {}, skipping",
                    snark_proof_input.vk_hash,
                    snark_proof_input.from_batch_number.0,
                    snark_proof_input.to_batch_number.0,
                    client.sequencer_url()
                );
                return Ok(false);
            }
            snark_proof_input
        }
        Ok(None) => {
            tracing::debug!(
                "No SNARK jobs found from sequencer {}",
                client.sequencer_url()
            );
            return Ok(false);
        }
        Err(e) => {
            // Check if the error is a timeout error
            if e.downcast_ref::<reqwest::Error>()
                .map(|err| err.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout waiting for response from sequencer {}: {e:?}",
                    client.sequencer_url()
                );
                tracing::error!("Exiting prover due to timeout");
                SNARK_PROVER_METRICS.timeout_errors.inc();
                return Ok(false);
            }
            tracing::error!(
                "Failed to pick SNARK job from sequencer {}: {e:?}",
                client.sequencer_url()
            );
            return Ok(false);
        }
    };
    let start_batch = snark_proof_input.from_batch_number;
    let end_batch = snark_proof_input.to_batch_number;
    let vk_hash = snark_proof_input.vk_hash.clone();

    tracing::info!(
        "Finished picking job from sequencer {} with VK hash {}, will aggregate from {} to {} inclusive",
        client.sequencer_url(),
        vk_hash,
        start_batch,
        end_batch,
    );
    let snark_proof = with_watchdog(
        client,
        Watched::Snark {
            from: start_batch.0,
            to: end_batch.0,
        },
        cancel_poll_interval,
        |cancel| {
            tracing::info!("Initializing GPU state");
            #[cfg(feature = "gpu")]
            let mut gpu_state_store = GpuSharedState::new(
                verifier_binary,
                zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
            );
            #[cfg(feature = "gpu")]
            let mut gpu_state = Some(&mut gpu_state_store);
            #[cfg(not(feature = "gpu"))]
            let mut gpu_state = None;
            tracing::info!("Finished initializing GPU state");

            let mut stats = SnarkProofTimeStats::new();

            let proof = stats.measure_step(SnarkStage::MergeFri, || {
                merge_fris(snark_proof_input, verifier_binary, &mut gpu_state, cancel)
            })?;

            // Drop GPU state to release the airbender GPU resources (as now Final Proof will be taking them).
            #[cfg(feature = "gpu")]
            drop(gpu_state_store);

            if cancel.is_cancelled() {
                tracing::info!("Cancelled after merging, before the final proof");
                return None;
            }

            tracing::info!("Creating final proof before SNARKification");

            let final_proof = stats.measure_step(SnarkStage::FinalProof, || {
                create_final_proofs_from_program_proof(
                    proof,
                    RecursionStrategy::UseReducedLog23Machine,
                    #[cfg(feature = "gpu")]
                    true,
                    #[cfg(not(feature = "gpu"))]
                    false,
                )
            });

            tracing::info!("Finished creating final proof");

            if cancel.is_cancelled() {
                tracing::info!("Cancelled after the final proof, before SNARKification");
                return None;
            }

            let one_fri_path = Path::new(&output_dir).join("one_fri.tmp");

            serialize_to_file(&final_proof, &one_fri_path);

            tracing::info!("SNARKifying proof");
            let start = Instant::now();
            match prove_cancellable(
                one_fri_path.into_os_string().into_string().unwrap(),
                output_dir.clone(),
                Some(trusted_setup_file.clone()),
                false,
                #[cfg(feature = "gpu")]
                Some(precomputations),
                // note that the API is use_zk, so we invert the disable_zk flag
                !disable_zk,
            ) {
                Ok(None) => {
                    tracing::info!("cancelled while proving, time stats: {}", stats);
                    return None;
                }
                Ok(Some(())) => {
                    stats.observe_step(SnarkStage::Snark, start.elapsed());

                    stats.observe_full();

                    tracing::info!("Finished generating proof, time stats: {}", stats);
                }
                Err(e) => {
                    tracing::error!("failed to SNARKify proof: {e:?}, time stats: {}", stats);
                }
            }

            let snark_proof: SnarkWrapperProof = deserialize_from_file(
                Path::new(&output_dir)
                    .join("snark_proof.json")
                    .to_str()
                    .unwrap(),
            );

            Some(snark_proof)
        },
    );

    let Some(snark_proof) = snark_proof else {
        tracing::warn!(
            "Abandoned SNARK run {} to {} after it was reassigned by sequencer {}",
            start_batch,
            end_batch,
            client.sequencer_url()
        );
        SNARK_PROVER_METRICS.cancelled_jobs.inc();
        return Ok(false);
    };

    match client
        .submit_snark_proof(start_batch, end_batch, vk_hash.clone(), snark_proof)
        .await
    {
        Ok(()) => {
            tracing::info!(
                "Successfully submitted SNARK proof for batches {} to {} with vk hash {} to sequencer {}",
                start_batch,
                end_batch,
                vk_hash,
                client.sequencer_url()
            );

            SNARK_PROVER_METRICS
                .latest_proven_batch
                .set(end_batch.0 as i64);

            Ok(true)
        }
        Err(e) => {
            // Check if the error is a timeout error
            if e.downcast_ref::<reqwest::Error>()
                .map(|err| err.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout submitting SNARK proof with vk hash {} for batches {} to {} to sequencer {}: {e:?}",
                    vk_hash,
                    start_batch,
                    end_batch,
                    client.sequencer_url()
                );
                tracing::error!("Exiting prover due to timeout");
                SNARK_PROVER_METRICS.timeout_errors.inc();
            } else {
                tracing::error!(
                    "Failed to submit SNARK job with vk hash {}, batches {} to {} to sequencer {} due to {e:?}, skipping",
                    vk_hash,
                    start_batch,
                    end_batch,
                    client.sequencer_url(),
                );
            }
            // Return false so caller doesn't increment proof counter
            Ok(false)
        }
    }
}

pub fn deserialize_from_file<T: serde::de::DeserializeOwned>(filename: &str) -> T {
    let src = std::fs::File::open(filename).unwrap();
    serde_json::from_reader(src).unwrap()
}
