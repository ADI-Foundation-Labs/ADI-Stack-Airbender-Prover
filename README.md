# ADI Stack OS: Airbender Prover

This repo contains the Prover Service implementation for ADI Stack OS Airbender prover.

ADI Stack utilizing the [MatterLabs zkOS stack](https://github.com/matter-labs/zksync-airbender-prover)

## Overview

This repo contains 3 crates:

- sequencer_proof_client
- zksync_os_fri_prover
- zksync_os_snark_prover
- zksync_os_prover_service

### Sequencer Proof Client

Small HTTP wrapper around the Sequencer Prover API.
Apart from providing lib to use in provers, it also has a binary that acts as a CLI.
Useful for troubleshooting (i.e. manually pushing a SNARK proof to sequencer, instead of running the entire sequencer).

### ADI Stack OS FRI Prover

The FRI prover for ZKsync OS. Retrieves proof input, proves a batch (which is a set of blocks) and submits it back to sequencer.
There's no state persisted in between.

### ADI Stack OS SNARK Prover

SNARKs the final proof. Gets a set of continuous FRIs from sequencer, merges them into a single FRI, creates a FINAL proof out of it and then SNARKs it.

### ADI Stack OS Prover Service

The ZKsync OS Prover Service is made for running both FRI and SNARK provers on the same machine. You can configure `max_snark_latency` and `max_fris_per_snark` parameters.

### Usage

Before starting, make sure that your **sequencer** has fake proofs disabled:

```
prover_api_fake_fri_provers_enabled=false prover_api_fake_snark_provers_enabled=false
```

Before starting, please download the trusted setup file (see info in crs/README.md).

Sample usage for commands.

**This command currently requires a GPU (at least 24GB of VRAM)**

```bash
# start FRI prover with a single sequencer
cargo run --release --features gpu --bin zksync_os_fri_prover -- --sequencer-urls http://localhost:3124 --app-bin-path ./multiblock_batch.bin --path ./output/fri_proof.json

# start FRI prover with multiple sequencers (round-robin polling)
cargo run --release --features gpu --bin zksync_os_fri_prover -- --sequencer-urls http://localhost:3124,http://localhost:3125,http://localhost:3126 --app-bin-path ./multiblock_batch.bin --path ./output/fri_proof.json
```

Specify optional `--iterations` argument to run FRI prover N times and then exit.
Specify optional `--path` argument if you want to serialize FRI proof to file.
Specify `--request_timeout_secs` argument to set a timeout for HTTP requests (default value is 2s).
Specify `--sequencer-urls` to provide a comma-separated list of sequencer URLs to poll in round-robin fashion.

**This command currently requires around 140 GB of RAM - and GPU**

```bash
# optional - increase stack size to 300M (TODO: check if this could be lower)
ulimit -s 300000

# start SNARK prover with a single sequencer
RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-urls http://localhost:3124 --binary-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs

# start SNARK prover with multiple sequencers (round-robin polling)
RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-urls http://localhost:3124,http://localhost:3125,http://localhost:3126 --binary-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs
```

Specify optional `--iterations` argument to run SNARK prover N times and then exit.
Specify `--request_timeout_secs` argument to set a timeout for HTTP requests (default value is 2s).
Specify `--sequencer-urls` to provide a comma-separated list of sequencer URLs to poll in round-robin fashion.

**This one is only needed if you want to manually upload.**

```bash
# pick a FRI job manually and serialize to file specified in `--path`
cargo run --release --bin zksync_sequencer_proof_client -- pick-fri --url http://localhost:3124 --path "./fri_job.json"
# submit a FRI proof specified in `--path` manually to sequencer
cargo run --release --bin zksync_sequencer_proof_client -- submit-fri --batch-number 1 --url http://localhost:3124 --path "./fri_proof.json"
# pick a SNARK job manually and serialize to file specified in `--path`
cargo run --release --bin zksync_sequencer_proof_client -- pick-snark --url http://localhost:3124 --path "./snark_job.json"
# submit a SNARK proof specified in `--path` manually to sequencer
cargo run --release --bin zksync_sequencer_proof_client -- submit-snark --from-batch-number 1 --to-batch-number 2 --url http://localhost:3124 --path "./snark_proof.json"
```

Specify --path argument to override default location.

**This command starts ZKsync OS Prover Service**

```bash
# optional - increase stack size to 300M (TODO: check if this could be lower)
ulimit -s 300000

# start prover service
RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin zksync_os_prover_service -- --base-url http://localhost:3124 --app-bin-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs --max-snark-latency 3600
```

Specify optional `--iterations` argument to run SNARK prover N times and then exit.
Specify `--max-snark-latency` OR `--max-fris-per-snark` to define latency (in seconds) OR max amount FRI proofs per SNARK for exiting FRI prover and starting SNARK prover. You can not specify them both in the same time.

## Development / WIP

- Add information on how to setup GPU for snark wraper

## FAQ

If you get the error like `cargo::rustc-check-cfg=cfg(no_cuda)` during compilation, you might have to install
Bellman Cuda (see instructions below).

## Installing bellman-cuda

```shell
git clone https://github.com/ADI-Foundation-Labs/ADI-Stack-Lib-Bellman-CUDA --branch main bellman-cuda && \
cmake -Bbellman-cuda/build -Sbellman-cuda/ -DCMAKE_BUILD_TYPE=Release && \
cmake --build bellman-cuda/build/
```

And then:

```shell
export BELLMAN_CUDA_DIR=...
```

## Policies

- [Contribution policy](CONTRIBUTING.md)

## License

ZKsync OS repositories are distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/blog/license/mit/>)

at your option.

## Official Links

- [Website](https://adi.foundation)
- [Docs](https://docs.adi.foundation/)
- [Github](https://github.com/ADI-Foundation-Labs/)
- [X](https://x.com/adi_foundation)
- [X for ADI Chain announcements](https://x.com/ADIChain_)
- [LinkedIn](https://www.linkedin.com/company/adifoundation/)
- [Discord](http://discord.gg/adi-foundation)
