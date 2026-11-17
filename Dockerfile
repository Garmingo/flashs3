# FlashS3 engine image
#
# VERSION is set by the GitHub Actions release workflow from the tag (e.g. v0.2.0). The leading
# `v` is stripped so Cargo gets a semver package version.
FROM rust:1.93-bookworm AS builder
WORKDIR /app
ARG VERSION=0.4.2
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN VER="${VERSION#v}" \
    && sed -i "s/^version = \".*\"/version = \"${VER}\"/" Cargo.toml \
    && cargo build --release -p flash-s3-engine

FROM debian:bookworm-slim
ARG VERSION=0.4.2
LABEL org.opencontainers.image.version="${VERSION}"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/flash-s3-engine /usr/local/bin/flash-s3-engine
ENV FLASHS3_BIND=0.0.0.0:9000 \
    FLASHS3_DATA_DIR=/data \
    FLASHS3_CACHE_POLICY=InMemoryLRU
EXPOSE 9000
VOLUME ["/data"]
ENTRYPOINT ["flash-s3-engine"]
