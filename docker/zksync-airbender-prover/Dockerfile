FROM nvidia/cuda:12.9.1-cudnn-devel-ubuntu24.04 AS chef

COPY rust-toolchain.toml rust-toolchain.toml

ARG DEBIAN_FRONTEND=noninteractive

# set of args for use of sccache
ARG SCCACHE_GCS_BUCKET
ARG SCCACHE_GCS_SERVICE_ACCOUNT
ARG SCCACHE_GCS_RW_MODE
ARG RUSTC_WRAPPER

ARG CUDA_ARCH=89;100
ENV CUDAARCHS=${CUDA_ARCH}

RUN apt-get update && apt-get install -y curl clang openssl libssl-dev gcc g++ git \
    pkg-config build-essential libclang-dev cmake sccache && \
    rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

RUN cargo install cargo-chef --version 0.1.72

WORKDIR /usr/src/zksync

FROM chef AS planner
COPY . .
RUN cargo chef prepare --bin zksync-os-prover-service --recipe-path recipe.json

FROM chef AS builder

RUN curl -Lo /setup_compact.key https://storage.googleapis.com/matterlabs-setup-keys-europe/setup-keys/setup_compact.key

# Bellman-cuda is needed during compilation.
RUN git clone --depth 1 https://github.com/matter-labs/era-bellman-cuda.git --branch main bellman-cuda && \
    cmake -Bbellman-cuda/build -Sbellman-cuda/ -DCMAKE_BUILD_TYPE=Release && \
    cmake --build bellman-cuda/build/

COPY --from=planner /usr/src/zksync/recipe.json recipe.json
RUN BELLMAN_CUDA_DIR=$PWD/bellman-cuda cargo chef cook -p zksync_os_prover_service --release --features gpu --recipe-path recipe.json

COPY . .
RUN BELLMAN_CUDA_DIR=$PWD/bellman-cuda cargo build -p zksync_os_prover_service --release --features gpu

FROM nvidia/cuda:12.2.0-runtime-ubuntu22.04

COPY docker/zksync-airbender-prover/entrypoint.sh /entrypoint.sh
COPY --from=builder /setup_compact.key /setup_compact.key

RUN apt-get update && apt-get install -y curl libpq5 ca-certificates && rm -rf /var/lib/apt/lists/*
RUN chmod +x /entrypoint.sh

COPY multiblock_batch.bin /multiblock_batch.bin
COPY --from=builder /usr/src/zksync/target/release/zksync-os-prover-service /usr/bin/zksync-airbender-prover

ENTRYPOINT ["/entrypoint.sh"]
