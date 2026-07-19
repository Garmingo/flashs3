# FlashS3 engine image
FROM rust:1.93-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p flash-s3-engine

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/flash-s3-engine /usr/local/bin/flash-s3-engine
ENV FLASHS3_BIND=0.0.0.0:9000 \
    FLASHS3_DATA_DIR=/data \
    FLASHS3_CACHE_POLICY=InMemoryLRU
EXPOSE 9000
VOLUME ["/data"]
ENTRYPOINT ["flash-s3-engine"]
