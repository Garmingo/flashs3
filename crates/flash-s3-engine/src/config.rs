use std::path::PathBuf;

use clap::Parser;
use flash_s3_common::{
    CacheConfig, CachePolicyKind, CannedAcl, DEFAULT_BIND, DEFAULT_CACHE_MAX_BYTES,
    DEFAULT_CACHE_OBJECT_MAX_BYTES, DEFAULT_REGION, ENV_ACCESS_KEY, ENV_AUTH_REQUIRED, ENV_BIND,
    ENV_CACHE_MAX_BYTES, ENV_CACHE_OBJECT_MAX_BYTES, ENV_CACHE_POLICY, ENV_DATA_DIR,
    ENV_DEFAULT_OBJECT_ACL, ENV_REGION, ENV_ROOT_BYPASSES_ACL, ENV_SECRET_KEY,
};

#[derive(Debug, Clone, Parser)]
#[command(name = "flash-s3-engine", about = "FlashS3 autonomous S3 storage engine")]
pub struct Config {
    #[arg(long, env = ENV_DATA_DIR, default_value = "./.data")]
    pub data_dir: PathBuf,

    #[arg(long, env = ENV_BIND, default_value = DEFAULT_BIND)]
    pub bind: String,

    #[arg(long, env = ENV_CACHE_POLICY, default_value = "InMemoryLRU")]
    pub cache_policy: String,

    #[arg(long, env = ENV_CACHE_MAX_BYTES, default_value_t = DEFAULT_CACHE_MAX_BYTES)]
    pub cache_max_bytes: u64,

    #[arg(
        long,
        env = ENV_CACHE_OBJECT_MAX_BYTES,
        default_value_t = DEFAULT_CACHE_OBJECT_MAX_BYTES
    )]
    pub cache_object_max_bytes: u64,

    #[arg(long, env = ENV_ACCESS_KEY)]
    pub access_key: Option<String>,

    #[arg(long, env = ENV_SECRET_KEY)]
    pub secret_key: Option<String>,

    #[arg(long, env = ENV_REGION, default_value = DEFAULT_REGION)]
    pub region: String,

    #[arg(long, env = ENV_AUTH_REQUIRED, default_value_t = false)]
    pub auth_required: bool,

    #[arg(long, env = ENV_DEFAULT_OBJECT_ACL, default_value = "private")]
    pub default_object_acl: String,

    #[arg(long, env = ENV_ROOT_BYPASSES_ACL, default_value_t = true)]
    pub root_bypasses_acl: bool,
}

impl Config {
    pub fn cache_config(&self) -> CacheConfig {
        CacheConfig {
            policy: CachePolicyKind::parse(&self.cache_policy),
            max_size_in_bytes: self.cache_max_bytes,
            object_max_size_in_bytes: self.cache_object_max_bytes,
        }
    }

    pub fn default_object_acl(&self) -> CannedAcl {
        CannedAcl::parse(&self.default_object_acl).unwrap_or(CannedAcl::Private)
    }
}
