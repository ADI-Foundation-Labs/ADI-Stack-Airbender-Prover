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
    BoojumWorker, CompressionVK, SnarkWrapperVK,
};
use zkos_wrapper::{prove, serialize_to_file, SnarkWrapperProof};
use zksync_airbender_cli::prover_utils::{
    create_final_proofs_from_program_proof, create_proofs_internal, GpuSharedState,
};
use zksync_airbender_execution_utils::{
    generate_oracle_data_for_universal_verifier, generate_oracle_data_from_metadata_and_proof_list,
    get_padded_binary, Machine, ProgramProof, RecursionStrategy, VerifierCircuitsIdentifiers,
    UNIVERSAL_CIRCUIT_VERIFIER,
};
use zksync_sequencer_proof_client::{
    sequencer_proof_client::SequencerProofClient, ProofClient, SnarkProofInputs,
};

use crate::metrics::SNARK_PROVER_METRICS;

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
) -> ProgramProof {
    SNARK_PROVER_METRICS
        .fri_proofs_merged
        .set(snark_proof_input.fri_proofs.len() as i64);

    if snark_proof_input.fri_proofs.len() == 1 {
        tracing::info!("No proof merging needed, only one proof provided");
        return snark_proof_input.fri_proofs[0].clone();
    }
    tracing::info!("Starting proof merging");

    let started_at = Instant::now();

    let mut proof = snark_proof_input.fri_proofs[0].clone();
    for i in 1..snark_proof_input.fri_proofs.len() {
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

    SNARK_PROVER_METRICS
        .time_taken_merge_fri
        .observe(started_at.elapsed().as_secs_f64());

    // TODO: We can do a recursion step here as well, IIUC
    tracing::info!(
        "Finishing linking all proofs from {} to {}",
        snark_proof_input.from_batch_number,
        snark_proof_input.to_batch_number
    );
    proof
}

#[cfg(feature = "gpu")]
pub fn compute_compression_vk(binary_path: String) -> CompressionVK {
    let worker = BoojumWorker::new();

    let risc_wrapper_vk = generate_risk_wrapper_vk(
        Some(binary_path),
        true,
        RecursionStrategy::UseReducedLog23Machine,
        &worker,
    )
    .unwrap();

    let (_, compression_vk, _) = get_compression_setup(&worker, risc_wrapper_vk);
    compression_vk
}

pub async fn run_linking_fri_snark(
    _binary_path: String,
    sequencer_url: Option<String>,
    output_dir: String,
    trusted_setup_file: String,
    iterations: Option<usize>,
    request_timeout_secs: u64,
    disable_zk: bool,
) -> anyhow::Result<()> {
    let sequencer_url = sequencer_url.unwrap_or("http://localhost:3124".to_string());
    let timeout = Duration::from_secs(request_timeout_secs);
    let sequencer_client =
        SequencerProofClient::new_with_timeout(sequencer_url.clone(), Some(timeout));

    let startup_started_at = Instant::now();

    let supported_versions = SupportedProtocolVersions::default();
    tracing::info!("{:#?}", supported_versions);

    tracing::info!(
        "Starting zksync_os_snark_prover for {} with request timeout of {}s",
        sequencer_url,
        request_timeout_secs
    );
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    #[cfg(feature = "gpu")]
    let precomputations = {
        tracing::info!("Computing SNARK precomputations");
        let compression_vk = compute_compression_vk(_binary_path);
        let precomputations = gpu_create_snark_setup_data(&compression_vk, &trusted_setup_file);
        tracing::info!("Finished computing SNARK precomputations");
        precomputations
    };

    SNARK_PROVER_METRICS
        .time_taken_startup
        .observe(startup_started_at.elapsed().as_secs_f64());

    let mut proof_count = 0;

    loop {
        let proof_generated = run_inner(
            &sequencer_client,
            &verifier_binary,
            output_dir.clone(),
            trusted_setup_file.clone(),
            #[cfg(feature = "gpu")]
            &precomputations,
            disable_zk,
            &supported_versions,
        )
        .await
        .expect("Failed to run SNARK prover");

        proof_count += proof_generated as usize;

        if let Some(max_proofs_generated) = iterations {
            if proof_count >= max_proofs_generated {
                tracing::info!("Reached maximum iterations ({max_proofs_generated}), exiting...");
                return Ok(());
            }
        }
    }
}

pub async fn run_inner<P: ProofClient>(
    client: &P,
    verifier_binary: &Vec<u32>,
    output_dir: String,
    trusted_setup_file: String,
    #[cfg(feature = "gpu")] precomputations: &(
        PlonkSnarkVerifierCircuitDeviceSetupWrapper,
        SnarkWrapperVK,
    ),
    disable_zk: bool,
    supported_protocol_versions: &SupportedProtocolVersions,
) -> anyhow::Result<bool> {
    let proof_time = Instant::now();
    tracing::info!("Started picking job");
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
                    "Received unsupported protocol version with vk_hash {} for batches between [{} and {}], skipping",
                    snark_proof_input.vk_hash,
                    snark_proof_input.from_batch_number.0,
                    snark_proof_input.to_batch_number.0
                );
                return Ok(false);
            }
            snark_proof_input
        }
        Ok(None) => {
            tracing::info!("No SNARK jobs found, retrying in 5s");
            tokio::time::sleep(Duration::from_secs(5)).await;
            return Ok(false);
        }
        Err(e) => {
            // Check if the error is a timeout error
            if e.downcast_ref::<reqwest::Error>()
                .map(|err| err.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!("Timeout waiting for response from sequencer: {e:?}");
                tracing::error!("Exiting prover due to timeout");
                SNARK_PROVER_METRICS.timeout_errors.inc();
                return Ok(false);
            }
            tracing::info!("Failed to pick SNARK job due to {e:?}, retrying in 30s");
            tokio::time::sleep(Duration::from_secs(30)).await;
            return Ok(false);
        }
    };
    let start_batch = snark_proof_input.from_batch_number;
    let end_batch = snark_proof_input.to_batch_number;
    let vk_hash = snark_proof_input.vk_hash.clone();

    tracing::info!(
        "Finished picking job with VK hash {}, will aggregate from {} to {} inclusive",
        vk_hash,
        start_batch,
        end_batch,
    );
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
    let proof = merge_fris(snark_proof_input, verifier_binary, &mut gpu_state);

    // Drop GPU state to release the airbender GPU resources (as now Final Proof will be taking them).
    #[cfg(feature = "gpu")]
    drop(gpu_state_store);

    tracing::info!("Creating final proof before SNARKification");

    let final_proof_started_at = Instant::now();
    let final_proof = create_final_proofs_from_program_proof(
        proof,
        RecursionStrategy::UseReducedLog23Machine,
        #[cfg(feature = "gpu")]
        true,
        #[cfg(not(feature = "gpu"))]
        false,
    );
    SNARK_PROVER_METRICS
        .time_taken_final_proof
        .observe(final_proof_started_at.elapsed().as_secs_f64());

    tracing::info!("Finished creating final proof");
    let one_fri_path = Path::new(&output_dir).join("one_fri.tmp");

    serialize_to_file(&final_proof, &one_fri_path);

    tracing::info!("SNARKifying proof");
    let snark_time = Instant::now();
    match prove(
        one_fri_path.into_os_string().into_string().unwrap(),
        output_dir.clone(),
        Some(trusted_setup_file.clone()),
        false,
        #[cfg(feature = "gpu")]
        Some(precomputations),
        // note that the API is use_zk, so we invert the disable_zk flag
        !disable_zk,
    ) {
        Ok(()) => {
            tracing::info!(
                "SNARKification took {:?}, with total proving time being {:?}",
                snark_time.elapsed(),
                proof_time.elapsed()
            );
            SNARK_PROVER_METRICS
                .time_taken_snark
                .observe(snark_time.elapsed().as_secs_f64());
            SNARK_PROVER_METRICS
                .time_taken_full
                .observe(proof_time.elapsed().as_secs_f64());
        }
        Err(e) => {
            tracing::error!("failed to SNARKify proof: {e:?}");
        }
    }
    let snark_proof: SnarkWrapperProof = deserialize_from_file(
        Path::new(&output_dir)
            .join("snark_proof.json")
            .to_str()
            .unwrap(),
    );

    match client
        .submit_snark_proof(start_batch, end_batch, vk_hash.clone(), snark_proof)
        .await
    {
        Ok(()) => {
            tracing::info!(
                "Successfully submitted SNARK proof for batches {} to {} with vk hash {}",
                start_batch,
                end_batch,
                vk_hash,
            );

            SNARK_PROVER_METRICS
                .latest_proven_batch
                .set(end_batch.0 as i64);
        }
        Err(e) => {
            // Check if the error is a timeout error
            if e.downcast_ref::<reqwest::Error>()
                .map(|err| err.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout submitting SNARK proof with vk hash {} for batches {} to {}: {e:?}",
                    vk_hash,
                    start_batch,
                    end_batch,
                );
                tracing::error!("Exiting prover due to timeout");
                SNARK_PROVER_METRICS.timeout_errors.inc();
            }
            tracing::error!(
                "Failed to submit SNARK job with vk hash {}, batches {} to {} due to {e:?}, skipping",
                vk_hash,
                start_batch,
                end_batch
            );
        }
    };

    Ok(true)
}

pub fn deserialize_from_file<T: serde::de::DeserializeOwned>(filename: &str) -> T {
    let src = std::fs::File::open(filename).unwrap();
    serde_json::from_reader(src).unwrap()
}
