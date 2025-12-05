# Setting up Linux VM for development

## Resource requirements

Assuming you want to run the entire stack (sequencer & prover), you'll need a machine with some modern CPU (aim for at least 8 cores), ~80GB of RAM and >= 20 GB of VRAM (more is marginally better, but not required for development). Assumption is you'll run some modern Ubuntu (currently we're developing against 24.04).

## Setting up the machine

> NOTE: Check `scripts` section, if you want to speedrun this.

### 1. Install rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.bashrc
```

### 2. Development packages

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev pkg-config clang cmake
```

### 3. Install foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup
```

### 4. Install CUDA

```bash
# either follow https://developer.nvidia.com/cuda-12-9-0-download-archive?target_os=Linux&target_arch=x86_64&Distribution=Ubuntu&target_version=24.04&target_type=deb_network or simply run the commands below
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get -y install cuda-toolkit-12-9
sudo apt-get install -y nvidia-open
# check if everything works fine
nvidia-smi # should report the current state of your GPU card
# and make it visible for processes by adding the following to ~/.bashrc:
---
# CUDA
export CUDA_HOME=/usr/local/cuda
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/cuda/lib64:/usr/local/cuda/extras/CUPTI/lib64
export PATH=$PATH:$CUDA_HOME/bin
---
source ~/.bashrc
```

### 5. Compile era-bellman-cuda

```bash
# needed for SNARKing
git clone https://github.com/ADI-Foundation-Labs/ADI-Stack-Lib-Bellman-CUDA.git
cmake -Bera-bellman-cuda/build -Sera-bellman-cuda/ -DCMAKE_BUILD_TYPE=Release
cmake --build era-bellman-cuda/build/
# and the following in your ~/.bashrc
---
export BELLMAN_CUDA_DIR=<PATH_TO>/era-bellman-cuda
---
source ~/.bashrc
```

### 6. Clone repos

```bash
git clone https://github.com/ADI-Foundation-Labs/ADI-Stack-Server.git # sequencer
git clone https://github.com/ADI-Foundation-Labs/ADI-Stack-Airbender-Prover.git # prover
```

### 7. Download CRS file

```bash
curl  https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_compact.key --output zksync-airbender-prover/crs/setup_compact.key
```

### 8. Start local L1

```bash
cd zksync-os-server
anvil --load-state zkos-l1-state.json --port 8545
```

### 9. Start sequencer (with proving enabled)

```bash
# in a new terminal/session
cd zksync-os-server
prover_api_fake_fri_provers_enabled=false prover_api_fake_snark_provers_enabled=false cargo run --release
```

### 10. Start FRI prover

```bash
# in a new terminal/session
cd zksync-airbender-prover
cargo run --release --features gpu --bin zksync_os_fri_prover
```

### 11. (OPTIONAL) Generate load

```bash
# in a new terminal/session
cd zksync-os-server/loadbase
cargo run --release -- --rpc-url 'http://127.0.0.1:3050' --rich-privkey 0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110 --duration 240m --max-in-flight 1 --wallets 1 --dest random
```

> NOTE: If you generate too many batches and there's no FRI prover to take them, the system will backpressure until FRI proofs are generated. Put differently, the sequencer will keep in memory a specific number of FRI inputs before it backpressures.

> NOTE2: If you generate too many FRI proofs, but not SNARKs, the system will backpressure until enough FRIs are consumed. Put differently, the sequencer will keep in memory a specific number of FRI proofs before it backpressures.

### 12. Start the SNARK prover

```bash
# in same terminal session as the FRI prover, but first cancel FRI prover
ulimit -s 300000
RUST_BACKTRACE=full RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-url http://localhost:3124 --binary-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs
```

> NOTE: Even if you have enough VRAM to run both processes, by default, the provers will simply consume all the VRAM available. You can either run SNARK or FRI at any one given time. There's also the intermitent (that runs some FRIs, then a SNARK, etc.), you can read more in the main [README](https://github.com/ADI-Foundation-Labs/ADI-Stack-Airbender-Prover), under [Usage section](https://github.com/ADI-Foundation-Labs/ADI-Stack-Airbender-Prover?tab=readme-ov-file#usage). Look for `ZKsync OS Prover Service`.

## Typical workflow

1. Start sequencer
2. Start FRI prover
3. Generate load for ~10 batches of FRI proofs
4. Stop FRI prover & start SNARK prover
5. Observe SNARK hitting on L1

If you want to troubleshoot at any layer, the above workflow allows you to go through the entire lifecycle of the stack.

## Scripts

If you navigate to `scripts/` in the root of this repo, there's `scripts/ubuntu_setup.sh`. It already does all the setup up to point 7 (inclusive). You can get a machine and start everything with:

```bash
curl -sL https://github.com/ADI-Foundation-Labs/ADI-Stack-Airbender-Prover/main/scripts/ubuntu_setup.sh | bash
```
