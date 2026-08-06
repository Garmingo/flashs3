//! Environment variable names shared by engine and operator.
//!
//! Keeping the string constants in one place avoids drift when the operator maps
//! CRD fields onto container env vars for the engine.

/// Root directory for buckets, index, and credentials.
pub const ENV_DATA_DIR: &str = "FLASHS3_DATA_DIR";
/// Cache policy name: `None` or `InMemoryLRU`.
pub const ENV_CACHE_POLICY: &str = "FLASHS3_CACHE_POLICY";
/// Maximum total cached object bytes (moka capacity).
pub const ENV_CACHE_MAX_BYTES: &str = "FLASHS3_CACHE_MAX_BYTES";
/// Objects larger than this are never inserted into the cache.
pub const ENV_CACHE_OBJECT_MAX_BYTES: &str = "FLASHS3_CACHE_OBJECT_MAX_BYTES";
/// Listen address, e.g. `0.0.0.0:9000`.
pub const ENV_BIND: &str = "FLASHS3_BIND";
/// Bootstrap access key (creates the first root credential if the store is empty).
pub const ENV_ACCESS_KEY: &str = "FLASHS3_ACCESS_KEY";
/// Bootstrap secret key paired with [`ENV_ACCESS_KEY`].
pub const ENV_SECRET_KEY: &str = "FLASHS3_SECRET_KEY";
/// Optional master key for encrypting secrets in `credentials.json` at rest.
///
/// When unset, secrets are stored in plaintext. When set, each `secret_key` is
/// stored as AES-256-GCM ciphertext (`enc:v1:…`).
pub const ENV_CREDENTIALS_KEY: &str = "FLASHS3_CREDENTIALS_KEY";
/// AWS-style region used in SigV4 scope (default `us-east-1`).
pub const ENV_REGION: &str = "FLASHS3_REGION";
/// When true, unauthenticated requests are rejected more aggressively.
pub const ENV_AUTH_REQUIRED: &str = "FLASHS3_AUTH_REQUIRED";
/// Default canned ACL applied to new objects without `x-amz-acl`.
pub const ENV_DEFAULT_OBJECT_ACL: &str = "FLASHS3_DEFAULT_OBJECT_ACL";
/// Optional S3 bucket created idempotently when the engine starts.
pub const ENV_DEFAULT_BUCKET_NAME: &str = "FLASHS3_DEFAULT_BUCKET_NAME";
/// Optional camelCase JSON CORS config applied to the default bucket on startup.
///
/// Example:
/// `{"rules":[{"allowedOrigins":["http://localhost:3001"],"allowedMethods":["PUT","GET","HEAD"],"allowedHeaders":["*"]}]}`
///
/// Or the lazy/dev form `{"allowAll":true}`.
pub const ENV_DEFAULT_BUCKET_CORS: &str = "FLASHS3_DEFAULT_BUCKET_CORS";
/// When `true`/`1`/`yes`, apply a permissive `*` CORS config to the default bucket.
///
/// Convenience for local Docker/dev; equivalent to `FLASHS3_DEFAULT_BUCKET_CORS={"allowAll":true}`.
/// Requires [`ENV_DEFAULT_BUCKET_NAME`]. Takes precedence over [`ENV_DEFAULT_BUCKET_CORS`].
pub const ENV_DEFAULT_BUCKET_CORS_ALLOW_ALL: &str = "FLASHS3_DEFAULT_BUCKET_CORS_ALLOW_ALL";
/// When true, root API keys bypass ACL/policy checks (break-glass admin).
pub const ENV_ROOT_BYPASSES_ACL: &str = "FLASHS3_ROOT_BYPASSES_ACL";
/// Optional passphrase used to derive the SSE-S3 AES-256 key at rest.
///
/// When unset, a deterministic key is derived from `FLASHS3_CREDENTIALS_KEY` if
/// set, otherwise from a fixed local-dev salt (not for production).
pub const ENV_SSE_S3_KEY: &str = "FLASHS3_SSE_S3_KEY";
/// DNS base for virtual-hosted-style requests (e.g. `s3.example.com`).
///
/// When set, `Host: {bucket}.{base}` routes to that bucket. Path-style still works.
pub const ENV_VIRTUAL_HOST_BASE: &str = "FLASHS3_VIRTUAL_HOST_BASE";

/// Default bind address for the engine HTTP server.
pub const DEFAULT_BIND: &str = "0.0.0.0:9000";
/// Default SigV4 region.
pub const DEFAULT_REGION: &str = "us-east-1";
/// Default cache capacity: 256 MiB.
pub const DEFAULT_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Default per-object cache eligibility threshold: 4 MiB.
pub const DEFAULT_CACHE_OBJECT_MAX_BYTES: u64 = 4 * 1024 * 1024;
