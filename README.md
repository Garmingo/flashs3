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
| `FLASHS3_REGION` | `us-east-1` |
| `FLASHS3_DEFAULT_OBJECT_ACL` | `private` |

## License

MIT
