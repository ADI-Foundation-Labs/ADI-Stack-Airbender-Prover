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
    PATH=/usr/local/cargo/bin:${PATH}

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

# We only pay the installation cost once,
# it will be cached from the second build onwards
RUN cargo install cargo-chef --version 0.1.72

WORKDIR /usr/src/zksync

FROM chef AS planner
COPY . .
RUN cargo chef prepare --bin zksync_os_fri_prover --recipe-path recipe.json


FROM chef AS builder

COPY --from=planner /usr/src/zksync/recipe.json recipe.json
# Build dependencies
RUN cargo chef cook -p zksync_os_fri_prover --release --features gpu --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build -p zksync_os_fri_prover --release --features gpu

FROM nvidia/cuda:12.2.0-runtime-ubuntu22.04

RUN apt-get update && apt-get install -y curl libpq5 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY multiblock_batch.bin /multiblock_batch.bin
COPY --from=builder /usr/src/zksync/target/release/zksync_os_fri_prover /usr/bin/

ENTRYPOINT ["zksync_os_fri_prover"]
