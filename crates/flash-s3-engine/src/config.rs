//! Engine configuration loaded from CLI flags and environment variables.

use std::path::PathBuf;

use clap::Parser;
use flash_s3_common::{
    CacheConfig, CachePolicyKind, CannedAcl, DEFAULT_BIND, DEFAULT_CACHE_MAX_BYTES,
    DEFAULT_CACHE_OBJECT_MAX_BYTES, DEFAULT_REGION, ENV_ACCESS_KEY, ENV_AUTH_REQUIRED, ENV_BIND,
    ENV_CACHE_MAX_BYTES, ENV_CACHE_OBJECT_MAX_BYTES, ENV_CACHE_POLICY, ENV_CREDENTIALS_KEY,
    ENV_DATA_DIR, ENV_DEFAULT_BUCKET_NAME, ENV_DEFAULT_OBJECT_ACL, ENV_REGION,
    ENV_ROOT_BYPASSES_ACL, ENV_SECRET_KEY,
};

/// Process configuration for `flash-s3-engine`.
///
/// Every field can be set via `--flag` or the matching `FLASHS3_*` env var
/// (see `flash_s3_common::env`).
#[derive(Debug, Clone, Parser)]
#[command(
    name = "flash-s3-engine",
    version = flash_s3_common::VERSION,
    about = "FlashS3 autonomous S3 storage engine"
)]
pub struct Config {
    /// Local data directory (buckets, index, credentials).
    #[arg(long, env = ENV_DATA_DIR, default_value = "./.data")]
    pub data_dir: PathBuf,

    /// HTTP listen address.
    #[arg(long, env = ENV_BIND, default_value = DEFAULT_BIND)]
    pub bind: String,

    /// Cache policy name (`None` / `InMemoryLRU`).
    #[arg(long, env = ENV_CACHE_POLICY, default_value = "InMemoryLRU")]
    pub cache_policy: String,

    /// Total cache capacity in bytes.
    #[arg(long, env = ENV_CACHE_MAX_BYTES, default_value_t = DEFAULT_CACHE_MAX_BYTES)]
    pub cache_max_bytes: u64,

    /// Per-object cache eligibility threshold in bytes.
    #[arg(
        long,
        env = ENV_CACHE_OBJECT_MAX_BYTES,
        default_value_t = DEFAULT_CACHE_OBJECT_MAX_BYTES
    )]
    pub cache_object_max_bytes: u64,

    /// Bootstrap access key (creates root credential if store empty).
    #[arg(long, env = ENV_ACCESS_KEY)]
    pub access_key: Option<String>,

    /// Bootstrap secret key.
    #[arg(long, env = ENV_SECRET_KEY)]
    pub secret_key: Option<String>,

    /// Optional master key to encrypt secrets in `credentials.json` at rest.
    ///
    /// When unset, secrets are stored plaintext. When set, AES-256-GCM is used.
    #[arg(long, env = ENV_CREDENTIALS_KEY)]
    pub credentials_key: Option<String>,

    /// SigV4 region string.
    #[arg(long, env = ENV_REGION, default_value = DEFAULT_REGION)]
    pub region: String,

    /// Stricter anonymous rejection when true.
    #[arg(long, env = ENV_AUTH_REQUIRED, default_value_t = false)]
    pub auth_required: bool,

    /// Default canned ACL for new objects.
    #[arg(long, env = ENV_DEFAULT_OBJECT_ACL, default_value = "private")]
    pub default_object_acl: String,

    /// Optional bucket created idempotently during engine startup.
    #[arg(long, env = ENV_DEFAULT_BUCKET_NAME)]
    pub default_bucket_name: Option<String>,

    /// Allow root keys to bypass ACL/policy checks.
    #[arg(long, env = ENV_ROOT_BYPASSES_ACL, default_value_t = true)]
    pub root_bypasses_acl: bool,
}

impl Config {
    /// Resolve cache settings for [`crate::cache::ObjectCache`].
    pub fn cache_config(&self) -> CacheConfig {
        CacheConfig {
            policy: CachePolicyKind::parse(&self.cache_policy),
            max_size_in_bytes: self.cache_max_bytes,
            object_max_size_in_bytes: self.cache_object_max_bytes,
        }
    }

    /// Parse [`Self::default_object_acl`], falling back to `private`.
    pub fn default_object_acl(&self) -> CannedAcl {
        CannedAcl::parse(&self.default_object_acl).unwrap_or(CannedAcl::Private)
    }
}
