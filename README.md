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

## Kubernetes

```bash
kubectl apply -f deploy/crds/flashs3bucket.yaml
# Operator-Image deployen, dann:
kubectl apply -f deploy/examples/bucket.yaml
```

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
