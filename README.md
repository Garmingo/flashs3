# FlashS3

Minimal, high-performance **S3-compatible** object storage engine written in Rust.

The core application, `flash-s3-engine`, is fully standalone: S3 HTTP, an in-memory
[`moka`](https://github.com/moka-rs/moka) cache, and direct disk I/O. The Kubernetes
operator is optional.

Built for small footprints: release images are published for `linux/amd64` on
Docker Hub.

## Quick start (local)

```bash
export FLASHS3_DATA_DIR=./.data
export FLASHS3_CACHE_POLICY=InMemoryLRU
export FLASHS3_CACHE_MAX_BYTES=268435456
export FLASHS3_ACCESS_KEY=flash
export FLASHS3_SECRET_KEY=flashsecret
cargo run -p flash-s3-engine
```

```bash
aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://demo
aws --endpoint-url http://127.0.0.1:9000 s3 cp ./file.bin s3://demo/
aws --endpoint-url http://127.0.0.1:9000 s3 cp s3://demo/file.bin ./out.bin

# Public-read object (for example, a CDN origin)
aws --endpoint-url http://127.0.0.1:9000 s3api put-object-acl \
  --bucket demo --key file.bin --acl public-read
curl -f http://127.0.0.1:9000/demo/file.bin -o /dev/null

# Browser uploads: allow CORS preflight from a local web app
cat > /tmp/cors.json <<'EOF'
{
  "CORSRules": [
    {
      "AllowedOrigins": ["http://localhost:3001"],
      "AllowedMethods": ["PUT", "GET", "HEAD"],
      "AllowedHeaders": ["*"],
      "ExposeHeaders": ["ETag", "x-amz-request-id"],
      "MaxAgeSeconds": 3000
    }
  ]
}
EOF
aws --endpoint-url http://127.0.0.1:9000 s3api put-bucket-cors \
  --bucket demo --cors-configuration file:///tmp/cors.json
```

Ops endpoints: `/healthz`, `/readyz`, `/metrics`.

## Workspace

| Crate | Role |
|-------|--------|
| `flash-s3-common` | Shared types for ACLs, policies, CORS, errors, and environment variables |
| `flash-s3-engine` | Standalone S3 storage engine |
| `flash-s3-operator` | Optional kube-rs operator for `FlashS3Bucket` resources |

## Features

- Path-style and virtual-hosted-style S3 API
- Buckets, Objects, Multipart (incl. ListMultipartUploads / UploadPartCopy), CopyObject
- DeleteObjects, Object/Bucket Tagging, GetBucketLocation
- ListObjects V1/V2 with delimiter / CommonPrefixes
- SigV4 + Presigned URLs
- Multiple API keys (`credentials.json` in the data directory)
- Rich S3 ACLs (bucket and object ACLs, canned ACLs, and grants)
- Bucket policies (allow/deny, principals, prefixes, actions, common Condition operators)
- Bucket CORS (`PutBucketCors` / `GetBucketCors` / `DeleteBucketCors`, browser `OPTIONS` preflight, `Access-Control-*` on GET/PUT/HEAD)
- SSE-S3 (`AES256`), flexible checksums (CRC32/CRC32C/SHA1/SHA256), conditional PutObject
- Hybrid cache: small objects are written through to disk and cached in moka's byte-LRU; large objects stream directly to disk
- Four-hex filesystem sharding (`aa/bb/<hash>/current/`)
- Prometheus metrics, graceful shutdown, and panic isolation

## Container images

Release tags trigger GitLab CI (Kaniko), which publishes two public images to Docker Hub:

| Image | Path |
|-------|------|
| Engine | `docker.io/garmingo/flashs3:<tag>` |
| Operator | `docker.io/garmingo/flashs3-operator:<tag>` |

Both images also receive the `latest` tag. Example using a fixed release:

```text
docker.io/garmingo/flashs3:v0.4.0
docker.io/garmingo/flashs3-operator:v0.4.0
```

Release builds set the binary version from the Git tag (`VERSION` build argument → `CARGO_PKG_VERSION`). A `v0.4.0` tag makes `flash-s3-engine --version` report `0.4.0`.

### Run the engine standalone (without the operator)

```bash
docker pull docker.io/garmingo/flashs3:latest

docker run --rm -p 9000:9000 \
  -e FLASHS3_ACCESS_KEY=flash \
  -e FLASHS3_SECRET_KEY=flashsecret \
  -v flashs3-data:/data \
  docker.io/garmingo/flashs3:latest
```

Local/dev with a bootstrap bucket and open CORS (browser uploads from any origin):

```bash
docker run --rm -p 9000:9000 \
  -e FLASHS3_ACCESS_KEY=flash \
  -e FLASHS3_SECRET_KEY=flashsecret \
  -e FLASHS3_DEFAULT_BUCKET_NAME=demo \
  -e FLASHS3_DEFAULT_BUCKET_CORS_ALLOW_ALL=true \
  -v flashs3-data:/data \
  docker.io/garmingo/flashs3:latest
```

The release repositories are public, so neither `docker login` nor a Kubernetes
`imagePullSecret` is required.

## Kubernetes Operator

The operator reconciles `FlashS3Bucket` custom resources into a PVC, Secret, Deployment, and Service.

### 1. Install the CRD

```bash
kubectl apply -f deploy/crds/flashs3bucket.yaml
```

### 2. Deploy the operator

```bash
kubectl apply -f deploy/operator/rbac.yaml

kubectl apply -f deploy/operator/deployment.yaml
```

The operator Deployment explicitly mounts the ServiceAccount token through a projected volume.
Without this mount, `kube::Client::try_default()` fails with
`failed to read the default namespace`.

For production, pin the operator image to a release tag (for example,
`docker.io/garmingo/flashs3-operator:v0.4.0`).

```bash
kubectl -n flashs3-system rollout status deploy/flash-s3-operator
kubectl -n flashs3-system logs -l app.kubernetes.io/name=flash-s3-operator -f
```

### 3. Create a bucket

```bash
kubectl apply -f deploy/examples/bucket.yaml
kubectl get flashs3buckets
kubectl get svc,pvc,deploy -l app.kubernetes.io/managed-by=flash-s3-operator
```

Example custom resource (`deploy/examples/bucket.yaml`):

```yaml
apiVersion: storage.flashs3.io/v1alpha1
kind: FlashS3Bucket
metadata:
  name: media
  namespace: default
spec:
  size: 50Gi
  # storageClassName: longhorn
  image: docker.io/garmingo/flashs3:latest
  # Created automatically when the engine starts.
  defaultBucketName: media-assets
  defaultObjectAcl: private
  # Applied to defaultBucketName on every engine start (browser uploads).
  # Dev shortcut: cors: { allowAll: true }
  cors:
    rules:
      - allowedOrigins:
          - http://localhost:3001
        allowedMethods: [PUT, GET, HEAD]
        allowedHeaders: ["*"]
        exposeHeaders: [ETag, x-amz-request-id]
        maxAgeSeconds: 3000
  cache:
    policy: InMemoryLRU
    maxSizeInBytes: 2147483648
    objectMaxSizeInBytes: 4194304
  service:
    type: ClusterIP
    port: 9000
  retainPvc: true
```

Credentials: if `spec.auth.secretRef` is omitted, the operator creates a Secret with a cryptographically random `accessKey` (`flash_ak_` + 32 chars) and `secretKey` (`flash_sk_` + 64 chars) via OS CSPRNG; created once, never rotated. `spec.defaultBucketName` is optional; when set, the engine creates that bucket idempotently on startup. `spec.defaultObjectAcl` and `spec.cors` are re-applied to that bucket on **every** engine start (change the CR and restart/roll the pod). `spec.cors` requires `defaultBucketName`; use either `allowAll: true` (permissive, local/dev) or explicit `rules` (not both). Removing `spec.cors` leaves an existing `cors.xml` unchanged. The operator maps CORS to `FLASHS3_DEFAULT_BUCKET_CORS_ALLOW_ALL` / `FLASHS3_DEFAULT_BUCKET_CORS`. CORS can also be managed at runtime with the S3 API (`put-bucket-cors`). The resulting endpoint is, for example, `http://media.default.svc:9000`.

## Env

| Variable | Default |
|----------|---------|
| `FLASHS3_DATA_DIR` | `./.data` |
| `FLASHS3_BIND` | `0.0.0.0:9000` |
| `FLASHS3_CACHE_POLICY` | `InMemoryLRU` |
| `FLASHS3_CACHE_MAX_BYTES` | `268435456` |
| `FLASHS3_CACHE_OBJECT_MAX_BYTES` | `4194304` |
| `FLASHS3_ACCESS_KEY` / `FLASHS3_SECRET_KEY` | Bootstrap root key |
| `FLASHS3_CREDENTIALS_KEY` | Optional — encrypts secrets in `credentials.json` (AES-256-GCM); plaintext when unset |
| `FLASHS3_REGION` | `us-east-1` |
| `FLASHS3_DEFAULT_OBJECT_ACL` | `private` |
| `FLASHS3_DEFAULT_BUCKET_NAME` | Optional bucket created idempotently on startup |
| `FLASHS3_DEFAULT_BUCKET_CORS` | Optional camelCase JSON CORS (`{"rules":[…]}` or `{"allowAll":true}`) for the default bucket |
| `FLASHS3_DEFAULT_BUCKET_CORS_ALLOW_ALL` | `false` — when `true`, apply permissive `*` CORS to the default bucket (local/dev; overrides `FLASHS3_DEFAULT_BUCKET_CORS`) |
| `FLASHS3_SSE_S3_KEY` | Optional passphrase to derive the SSE-S3 AES-256 key |
| `FLASHS3_VIRTUAL_HOST_BASE` | Optional DNS base for virtual-hosted-style (`{bucket}.{base}`) |

When `FLASHS3_CREDENTIALS_KEY` is set, each `secret_key` in `credentials.json` is stored as
`enc:v1:…`. The same key is required on every start; losing it makes encrypted secrets unrecoverable.

## Tests

```bash
cargo test
```

Coverage includes ACL/policy/CORS/identity unit tests plus engine integration tests
(storage, HTTP/SigV4, CORS preflight, cache, multipart, copy, presigned uploads, S3 parity).

### Ceph s3-tests coverage benchmark (optional)

Not part of `cargo test` and not a CI gate. Runs [ceph/s3-tests](https://github.com/ceph/s3-tests)
against a temporary local engine to see remaining API gaps:

```bash
./scripts/test-spec-coverage.sh
# optional narrower filter:
S3_TESTS_FILTER='s3tests/functional/test_s3.py' ./scripts/test-spec-coverage.sh
```

Requires `cargo`, `python3` (+`venv`), `curl`, and network access on first run
(clones into `.cache/s3-tests`, creates `.cache/s3-tests-venv`). The script always
exits 0; inspect `.cache/s3tests-last.out` for the summary.
## Benchmarks

### FlashS3-only benchmarks

**HTTP end-to-end** (write, first read, and a second read with the LRU cache warm):

```bash
cargo build --release -p flash-s3-engine
python3 scripts/benchmark.py --objects 200 --size 65536 --concurrency 4
python3 scripts/benchmark.py --profile latency   # many 4KiB objects
python3 scripts/benchmark.py --endpoint http://127.0.0.1:9000
```

**In-process micro-bench** (disk write/read vs moka cache hits, no HTTP/SigV4):

```bash
cargo run -p flash-s3-engine --example micro_bench --release
BENCH_OBJECTS=1000 BENCH_SIZE=4096 cargo run -p flash-s3-engine --example micro_bench --release
```

Output includes ops/s, MiB/s, and p50/p90/p95/p99 (HTTP script). Optional `--json-out results.json`.

### Reproducible comparison: FlashS3, MinIO, and Garage

`scripts/benchmark_compare.py` runs the same path-style S3 HTTP/SigV4 workload
against all three backends. It starts one Docker container at a time and resets
its volume before each run, so the backends do not contend for system resources
and no data survives from a previous measurement.

The benchmark environment is:

| Property | Value |
|----------|-------|
| Host | 14-inch MacBook Pro |
| CPU | Apple M3 Pro |
| Memory | 18 GB |
| Storage | Docker Desktop virtual disk on the local SSD |
| Container platform | `linux/amd64` for all backends (emulated by Docker Desktop on Apple Silicon) |
| Workload matrix | 2,000 objects × 64 KiB, 128 KiB, and 1 MiB × 16, 32, and 1 concurrent clients |
| Protocol | Path-style S3 over HTTP with AWS SigV4 |
| FlashS3 cache | `InMemoryLRU`, 512 MiB maximum |
| FlashS3 | `docker.io/garmingo/flashs3:v0.4.0` |
| MinIO | `minio/minio:RELEASE.2025-04-22T22-12-26Z` |
| Garage | `dxflrs/garage:v2.3.0` in single-node mode |

Run the comparison:

```bash
cp benchmarks/.env.example benchmarks/.env
python3 scripts/benchmark_compare.py
```

The runner pulls FlashS3 from Docker Hub; it does not build the
local Dockerfile. To compare another released FlashS3 version, update
`FLASHS3_IMAGE` in `benchmarks/.env`.

The default command runs all nine workloads (27 backend executions). For a
short custom run, use `--single`:

```bash
python3 scripts/benchmark_compare.py --single --objects 2000 --size 65536 --concurrency 16
```

Each run produces the raw per-backend results and a combined report under
`benchmarks/results/`. The report records the exact Docker image IDs, host
metadata, workload, throughput, latency percentiles, and error count.

#### Results

The complete 3 × 3 matrix below completed on 2026-07-19 with zero benchmark
errors across 162,000 S3 operations. Each cell shows **MiB/s · p50 · p90**,
with p50 and p90 in milliseconds. Results are specific to the documented local
Docker Desktop environment; they are not production or distributed-cluster
benchmarks.

**PUT**

| Workload | FlashS3 (MiB/s · p50 · p90) | MinIO (MiB/s · p50 · p90) | Garage (MiB/s · p50 · p90) |
|----------|---------|-------|--------|
| 2,000 × 64 KiB, 16 clients | 56.15 · 16.07 ms · 23.54 ms | 80.26 · 10.74 ms · 17.39 ms | 47.80 · 16.15 ms · 23.68 ms |
| 2,000 × 64 KiB, 32 clients | 65.51 · 27.54 ms · 39.47 ms | 77.23 · 22.07 ms · 41.20 ms | 51.91 · 32.56 ms · 43.78 ms |
| 2,000 × 64 KiB, 1 client | 14.62 · 3.89 ms · 5.18 ms | 17.18 · 3.30 ms · 4.43 ms | 16.63 · 3.03 ms · 4.43 ms |
| 2,000 × 128 KiB, 16 clients | 83.37 · 21.92 ms · 33.94 ms | 105.75 · 17.39 ms · 27.80 ms | 64.12 · 24.51 ms · 37.25 ms |
| 2,000 × 128 KiB, 32 clients | 88.94 · 41.09 ms · 63.91 ms | 105.61 · 35.43 ms · 54.65 ms | 77.67 · 41.46 ms · 57.83 ms |
| 2,000 × 128 KiB, 1 client | 23.86 · 4.67 ms · 6.28 ms | 33.08 · 3.28 ms · 4.60 ms | 36.47 · 3.04 ms · 4.04 ms |
| 2,000 × 1 MiB, 16 clients | 141.64 · 109.35 ms · 126.04 ms | 147.04 · 106.10 ms · 118.30 ms | 127.80 · 118.94 ms · 133.17 ms |
| 2,000 × 1 MiB, 32 clients | 145.96 · 210.02 ms · 235.00 ms | 157.84 · 195.43 ms · 212.84 ms | 131.17 · 226.70 ms · 269.12 ms |
| 2,000 × 1 MiB, 1 client | 65.38 · 13.62 ms · 19.04 ms | 75.86 · 11.48 ms · 16.54 ms | 77.86 · 11.26 ms · 15.95 ms |

**GET after write**

| Workload | FlashS3 (MiB/s · p50 · p90) | MinIO (MiB/s · p50 · p90) | Garage (MiB/s · p50 · p90) |
|----------|---------|-------|--------|
| 2,000 × 64 KiB, 16 clients | 156.19 · 5.49 ms · 8.54 ms | 131.02 · 6.66 ms · 9.93 ms | 75.01 · 11.16 ms · 15.11 ms |
| 2,000 × 64 KiB, 32 clients | 169.54 · 10.73 ms · 16.50 ms | 144.03 · 12.26 ms · 19.00 ms | 78.12 · 21.96 ms · 31.01 ms |
| 2,000 × 64 KiB, 1 client | 41.45 · 1.16 ms · 2.06 ms | 36.75 · 1.38 ms · 2.30 ms | 20.65 · 2.65 ms · 3.85 ms |
| 2,000 × 128 KiB, 16 clients | 178.96 · 10.28 ms · 15.55 ms | 167.41 · 10.73 ms · 16.26 ms | 110.63 · 16.42 ms · 21.41 ms |
| 2,000 × 128 KiB, 32 clients | 190.14 · 19.52 ms · 29.20 ms | 167.50 · 21.93 ms · 32.66 ms | 107.63 · 33.08 ms · 51.74 ms |
| 2,000 × 128 KiB, 1 client | 86.82 · 1.16 ms · 1.92 ms | 60.11 · 1.62 ms · 2.77 ms | 42.20 · 2.58 ms · 3.56 ms |
| 2,000 × 1 MiB, 16 clients | 233.97 · 63.99 ms · 84.46 ms | 238.96 · 65.58 ms · 83.77 ms | 239.31 · 63.86 ms · 80.27 ms |
| 2,000 × 1 MiB, 32 clients | 261.34 · 118.14 ms · 150.09 ms | 297.28 · 105.16 ms · 124.84 ms | 238.07 · 129.58 ms · 150.89 ms |
| 2,000 × 1 MiB, 1 client | 170.81 · 5.06 ms · 6.74 ms | 157.15 · 5.46 ms · 7.41 ms | 134.34 · 6.55 ms · 8.24 ms |

**Repeat GET**

| Workload | FlashS3 (MiB/s · p50 · p90) | MinIO (MiB/s · p50 · p90) | Garage (MiB/s · p50 · p90) |
|----------|---------|-------|--------|
| 2,000 × 64 KiB, 16 clients | 152.96 · 5.87 ms · 9.24 ms | 153.88 · 5.87 ms · 8.68 ms | 85.48 · 11.19 ms · 14.41 ms |
| 2,000 × 64 KiB, 32 clients | 157.60 · 11.70 ms · 17.25 ms | 137.31 · 13.51 ms · 20.65 ms | 89.89 · 21.84 ms · 28.51 ms |
| 2,000 × 64 KiB, 1 client | 43.47 · 1.14 ms · 1.94 ms | 33.21 · 1.50 ms · 2.59 ms | 22.07 · 2.42 ms · 3.40 ms |
| 2,000 × 128 KiB, 16 clients | 193.79 · 9.58 ms · 14.05 ms | 174.60 · 10.58 ms · 16.03 ms | 116.57 · 16.30 ms · 21.21 ms |
| 2,000 × 128 KiB, 32 clients | 203.00 · 18.58 ms · 27.40 ms | 170.40 · 22.23 ms · 32.21 ms | 112.39 · 33.76 ms · 46.61 ms |
| 2,000 × 128 KiB, 1 client | 86.40 · 1.15 ms · 1.97 ms | 69.84 · 1.47 ms · 2.37 ms | 38.23 · 2.92 ms · 3.97 ms |
| 2,000 × 1 MiB, 16 clients | 241.70 · 64.86 ms · 82.85 ms | 233.57 · 65.53 ms · 85.36 ms | 237.10 · 63.51 ms · 83.32 ms |
| 2,000 × 1 MiB, 32 clients | 258.39 · 115.86 ms · 156.19 ms | 253.97 · 116.18 ms · 155.75 ms | 236.10 · 127.28 ms · 160.90 ms |
| 2,000 × 1 MiB, 1 client | 157.50 · 5.15 ms · 7.19 ms | 167.20 · 5.13 ms · 6.64 ms | 135.37 · 6.52 ms · 8.18 ms |

Each backend is measured after writing the objects and then reading the same
objects twice. Therefore, the GET figures include each system's cache behavior
(including the host OS page cache) and must not be interpreted as cold-disk
read results. Do not compare them with FlashS3's in-process micro-benchmark:
it intentionally excludes HTTP, SigV4, and container overhead.

## License

MIT
