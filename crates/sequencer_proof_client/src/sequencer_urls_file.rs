use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::Context;

use crate::{ProofClient, SequencerEndpoint, SequencerProofClient};

/// Read sequencer endpoints from a file.
///
/// File format: one URL per line. Empty lines and lines starting with `#` are ignored.
/// Returns an error if the file cannot be read or contains no valid URLs.
pub fn load_endpoints_from_file(path: &Path) -> anyhow::Result<Vec<SequencerEndpoint>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read sequencer URLs file: {}", path.display()))?;

    let endpoints: Vec<SequencerEndpoint> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .enumerate()
        .map(|(i, line)| {
            SequencerEndpoint::parse(line).with_context(|| {
                format!(
                    "Invalid URL on line {} of {}: {:?}",
                    i + 1,
                    path.display(),
                    line
                )
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    if endpoints.is_empty() {
        anyhow::bail!(
            "Sequencer URLs file {} contains no valid URLs",
            path.display()
        );
    }

    Ok(endpoints)
}

/// Manages sequencer proof clients with optional file-based hot-reload.
///
/// When created with a file path, checks the file's modification time on each
/// `maybe_reload()` call and recreates clients if the file has changed.
/// When created from CLI URLs, `maybe_reload()` is a no-op.
pub struct ClientManager {
    clients: Vec<Box<dyn ProofClient + Send + Sync>>,
    file_path: Option<PathBuf>,
    last_mtime: SystemTime,
    prover_name: String,
    timeout: Option<Duration>,
}

impl ClientManager {
    /// Create a ClientManager from a file or from CLI-provided URLs.
    ///
    /// If `file_path` is `Some`, endpoints are loaded from the file (takes precedence).
    /// Otherwise, endpoints are created from `cli_urls`.
    pub fn new(
        file_path: Option<PathBuf>,
        cli_urls: Vec<SequencerEndpoint>,
        prover_name: String,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        if let Some(ref path) = file_path {
            let endpoints = load_endpoints_from_file(path)
                .context("Failed to load initial sequencer URLs from file")?;
            let mtime = std::fs::metadata(path)?.modified()?;

            tracing::info!(
                "Loaded {} sequencer endpoint(s) from {}",
                endpoints.len(),
                path.display(),
            );

            let clients =
                SequencerProofClient::new_clients(endpoints, prover_name.clone(), timeout)?;

            Ok(Self {
                clients,
                file_path,
                last_mtime: mtime,
                prover_name,
                timeout,
            })
        } else {
            tracing::info!(
                "Creating {} sequencer proof clients for urls: {:?}",
                cli_urls.len(),
                cli_urls
            );

            let clients =
                SequencerProofClient::new_clients(cli_urls, prover_name.clone(), timeout)
                    .context("failed to create sequencer proof clients")?;

            Ok(Self {
                clients,
                file_path: None,
                last_mtime: SystemTime::UNIX_EPOCH,
                prover_name,
                timeout,
            })
        }
    }

    /// If backed by a file, check if it has been modified and reload clients.
    /// Safe to call frequently — no-op when there is no file or no changes.
    pub fn maybe_reload(&mut self) {
        let path = match self.file_path {
            Some(ref p) => p,
            None => return,
        };

        let mtime = match std::fs::metadata(path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    "Failed to stat sequencer URLs file {}: {e}. Keeping current clients.",
                    path.display()
                );
                return;
            }
        };

        if mtime <= self.last_mtime {
            return;
        }

        tracing::info!(
            "Sequencer URLs file {} has changed, reloading...",
            path.display()
        );

        match load_endpoints_from_file(path) {
            Ok(endpoints) => {
                match SequencerProofClient::new_clients(
                    endpoints,
                    self.prover_name.clone(),
                    self.timeout,
                ) {
                    Ok(new_clients) => {
                        tracing::info!(
                            "Reloaded {} sequencer client(s) from {}",
                            new_clients.len(),
                            path.display(),
                        );
                        self.clients = new_clients;
                        self.last_mtime = mtime;
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to create clients from {}: {e}. Keeping current clients.",
                            path.display()
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    "Failed to reload sequencer URLs from {}: {e}. Keeping current clients.",
                    path.display()
                );
            }
        }
    }

    /// Returns the current list of clients.
    pub fn clients(&self) -> &[Box<dyn ProofClient + Send + Sync>] {
        &self.clients
    }
}