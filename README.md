# FlashS3

Minimal, high-performance **S3-compatible** object storage engine written in Rust.

The core application, `flash-s3-engine`, is fully standalone: S3 HTTP, an in-memory
[`moka`](https://github.com/moka-rs/moka) cache, and direct disk I/O. The Kubernetes
operator is optional.

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
```

Ops endpoints: `/healthz`, `/readyz`, `/metrics`.

## Workspace

| Crate | Role |
|-------|--------|
| `flash-s3-common` | Shared types for ACLs, policies, errors, and environment variables |
| `flash-s3-engine` | Standalone S3 storage engine |
| `flash-s3-operator` | Optional kube-rs operator for `FlashS3Bucket` resources |

## Features

- Path-style S3 API: Buckets, Objects, Multipart, CopyObject
- SigV4 + Presigned URLs
- Multiple API keys (`credentials.json` in the data directory)
- Rich S3 ACLs (bucket and object ACLs, canned ACLs, and grants)
- Bucket policies (allow/deny, key principals, prefixes, and actions)
- Hybrid cache: small objects are written through to disk and cached in moka's byte-LRU; large objects stream directly to disk
- Four-hex filesystem sharding (`aa/bb/<hash>/current/`)
- Prometheus metrics, graceful shutdown, and panic isolation

## Container images

Release tags trigger GitLab CI (Kaniko), which publishes two images to the Garmingo registry:

| Image | Path |
|-------|------|
| Engine | `registry.garmingo.net/garmingo/flashs3/engine:<tag>` |
| Operator | `registry.garmingo.net/garmingo/flashs3/operator:<tag>` |

Both images also receive the `latest` tag. Example using a fixed release:

```text
registry.garmingo.net/garmingo/flashs3/engine:v0.2.0
registry.garmingo.net/garmingo/flashs3/operator:v0.2.0
```

Release builds set the binary version from the Git tag (`VERSION` build argument → `CARGO_PKG_VERSION`). A `v0.2.0` tag makes `flash-s3-engine --version` report `0.2.0`.

### Run the engine standalone (without the operator)

```bash
docker pull registry.garmingo.net/garmingo/flashs3/engine:latest

docker run --rm -p 9000:9000 \
  -e FLASHS3_ACCESS_KEY=flash \
  -e FLASHS3_SECRET_KEY=flashsecret \
  -v flashs3-data:/data \
  registry.garmingo.net/garmingo/flashs3/engine:latest
```

For a private registry, authenticate first (`docker login registry.garmingo.net`) or configure an `imagePullSecret` in your cluster.

## Kubernetes Operator

The operator reconciles `FlashS3Bucket` custom resources into a PVC, Secret, Deployment, and Service.

### 1. Install the CRD

```bash
kubectl apply -f deploy/crds/flashs3bucket.yaml
```

### 2. Deploy the operator

```bash
kubectl apply -f deploy/operator/rbac.yaml

# Optional: pull secret for registry.garmingo.net
kubectl create secret docker-registry garmingo-registry \
  --namespace flashs3-system \
  --docker-server=registry.garmingo.net \
  --docker-username=<user> \
  --docker-password=<token>

kubectl apply -f deploy/operator/deployment.yaml
```

The operator Deployment explicitly mounts the ServiceAccount token through a projected volume.
Without this mount, `kube::Client::try_default()` fails with
`failed to read the default namespace`.

If needed, enable `imagePullSecrets` in `deploy/operator/deployment.yaml` and pin the image to a release tag (for example, `…/operator:v0.2.0`).

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
  image: registry.garmingo.net/garmingo/flashs3/engine:latest
  defaultObjectAcl: private
  cache:
    policy: InMemoryLRU
    maxSizeInBytes: 2147483648
    objectMaxSizeInBytes: 4194304
  service:
    type: ClusterIP
    port: 9000
  retainPvc: true
```

Credentials: if `spec.auth.secretRef` is omitted, the operator creates a Secret containing root keys. The resulting endpoint is, for example, `http://media.default.svc:9000`.

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

When `FLASHS3_CREDENTIALS_KEY` is set, each `secret_key` in `credentials.json` is stored as
`enc:v1:…`. The same key is required on every start; losing it makes encrypted secrets unrecoverable.

## Tests

```bash
cargo test
```

Coverage includes ACL/policy/identity unit tests plus engine integration tests
(storage, HTTP/SigV4, cache, multipart, copy).

## Benchmarks

**HTTP end-to-end** (write, cold read with cache disabled, warm read with LRU):

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

Output includes ops/s, MiB/s, and p50/p95/p99 (HTTP script). Optional `--json-out results.json`.

## License

MIT
