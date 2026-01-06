use std::time::Duration;

use clap::Parser;
use tokio::sync::watch;
use zksync_os_fri_prover::{init_tracing, metrics};

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args = zksync_os_fri_prover::Args::parse();

    let (stop_sender, stop_receiver) = watch::channel(false);

    let prometheus_port = args.prometheus_port;

    let metrics_handle = tokio::spawn(async move {
        metrics::start_metrics_exporter(prometheus_port, stop_receiver).await
    });

    tokio::select! {
        err = zksync_os_fri_prover::run(args) => {
            match err {
                Ok(_) => tracing::info!("Zksync OS FRI prover finished successfully"),
                Err(e) => tracing::error!("Zksync OS FRI prover finished with error: {e}"),
            }
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

    Ok(())
}
