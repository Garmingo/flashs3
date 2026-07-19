# FlashS3

Minimalistische, hochperformante **S3-kompatible** Object-Storage-Engine in Rust.

Die Kernanwendung `flash-s3-engine` ist vollständig autark: S3-HTTP, In-Memory-Cache (moka) und direktes Disk-I/O. Der Kubernetes-Operator ist optional.

## Quick start (lokal)

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

# Public-read object (CDN)
aws --endpoint-url http://127.0.0.1:9000 s3api put-object-acl \
  --bucket demo --key file.bin --acl public-read
curl -f http://127.0.0.1:9000/demo/file.bin -o /dev/null
```

Ops endpoints: `/healthz`, `/readyz`, `/metrics`.

## Workspace

| Crate | Rolle |
|-------|--------|
| `flash-s3-common` | Shared Types (ACL, Policy, Errors, Env) |
| `flash-s3-engine` | Autarke S3 Storage Engine |
| `flash-s3-operator` | Optionaler kube-rs Operator (`FlashS3Bucket`) |

## Features

- Path-style S3 API: Buckets, Objects, Multipart, CopyObject
- SigV4 + Presigned URLs
- Multi API-Keys (`credentials.json` unter Data-Dir)
- Rich S3 ACLs (Bucket + Object, Canned + Grants)
- Bucket Policies (Allow/Deny, Principal=Key, Prefix/Action)
- Hybrid Cache: kleine Objekte write-through + moka Byte-LRU; große Objekte streamen
- 4-Hex FS-Sharding (`aa/bb/<hash>/current/`)
- Prometheus metrics, graceful shutdown, panic isolation

## Container images

Release-Tags triggern GitLab CI (Kaniko) und pushen zwei Images in die Garmingo Registry:

| Image | Pfad |
|-------|------|
| Engine | `registry.garmingo.net/garmingo/flashs3/engine:<tag>` |
| Operator | `registry.garmingo.net/garmingo/flashs3/operator:<tag>` |

Zusätzlich gibt es jeweils das Tag `latest`. Beispiel mit festem Release:

```text
registry.garmingo.net/garmingo/flashs3/engine:v0.1.0
registry.garmingo.net/garmingo/flashs3/operator:v0.1.0
```

### Engine standalone (ohne Operator)

```bash
docker pull registry.garmingo.net/garmingo/flashs3/engine:latest

docker run --rm -p 9000:9000 \
  -e FLASHS3_ACCESS_KEY=flash \
  -e FLASHS3_SECRET_KEY=flashsecret \
  -v flashs3-data:/data \
  registry.garmingo.net/garmingo/flashs3/engine:latest
```

Private Registry: vorher einloggen (`docker login registry.garmingo.net`) bzw. im Cluster ein `imagePullSecret` setzen.

## Kubernetes Operator

Der Operator reconciled `FlashS3Bucket`-CRs zu PVC + Secret + Deployment + Service.

### 1. CRD installieren

```bash
kubectl apply -f deploy/crds/flashs3bucket.yaml
```

### 2. Operator deployen

```bash
kubectl apply -f deploy/operator/rbac.yaml

# Optional: Pull-Secret für registry.garmingo.net
kubectl create secret docker-registry garmingo-registry \
  --namespace flashs3-system \
  --docker-server=registry.garmingo.net \
  --docker-username=<user> \
  --docker-password=<token>

kubectl apply -f deploy/operator/deployment.yaml
```

Das Operator-Deployment mountet das ServiceAccount-Token explizit (projected Volume).
Ohne dieses Mount scheitert `kube::Client::try_default()` mit
`failed to read the default namespace`.

In `deploy/operator/deployment.yaml` bei Bedarf `imagePullSecrets` aktivieren und das Image-Tag auf ein Release setzen (z. B. `…/operator:v0.1.0`).

```bash
kubectl -n flashs3-system rollout status deploy/flash-s3-operator
kubectl -n flashs3-system logs -l app.kubernetes.io/name=flash-s3-operator -f
```

### 3. Bucket anlegen

```bash
kubectl apply -f deploy/examples/bucket.yaml
kubectl get flashs3buckets
kubectl get svc,pvc,deploy -l app.kubernetes.io/managed-by=flash-s3-operator
```

Beispiel-CR (`deploy/examples/bucket.yaml`):

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

Credentials: ohne `spec.auth.secretRef` erzeugt der Operator ein Secret mit Root-Keys. Endpoint danach z. B. `http://media.default.svc:9000`.

## Env

| Variable | Default |
|----------|---------|
| `FLASHS3_DATA_DIR` | `./.data` |
| `FLASHS3_BIND` | `0.0.0.0:9000` |
| `FLASHS3_CACHE_POLICY` | `InMemoryLRU` |
| `FLASHS3_CACHE_MAX_BYTES` | `268435456` |
| `FLASHS3_CACHE_OBJECT_MAX_BYTES` | `4194304` |
| `FLASHS3_ACCESS_KEY` / `FLASHS3_SECRET_KEY` | Bootstrap Root-Key |
| `FLASHS3_CREDENTIALS_KEY` | optional — encrypts secrets in `credentials.json` (AES-256-GCM); unset = plaintext |
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
