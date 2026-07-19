//! Environment variable names shared by engine and operator.

pub const ENV_DATA_DIR: &str = "FLASHS3_DATA_DIR";
pub const ENV_CACHE_POLICY: &str = "FLASHS3_CACHE_POLICY";
pub const ENV_CACHE_MAX_BYTES: &str = "FLASHS3_CACHE_MAX_BYTES";
pub const ENV_CACHE_OBJECT_MAX_BYTES: &str = "FLASHS3_CACHE_OBJECT_MAX_BYTES";
pub const ENV_BIND: &str = "FLASHS3_BIND";
pub const ENV_ACCESS_KEY: &str = "FLASHS3_ACCESS_KEY";
pub const ENV_SECRET_KEY: &str = "FLASHS3_SECRET_KEY";
pub const ENV_REGION: &str = "FLASHS3_REGION";
pub const ENV_AUTH_REQUIRED: &str = "FLASHS3_AUTH_REQUIRED";
pub const ENV_DEFAULT_OBJECT_ACL: &str = "FLASHS3_DEFAULT_OBJECT_ACL";
pub const ENV_ROOT_BYPASSES_ACL: &str = "FLASHS3_ROOT_BYPASSES_ACL";

pub const DEFAULT_BIND: &str = "0.0.0.0:9000";
pub const DEFAULT_REGION: &str = "us-east-1";
pub const DEFAULT_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_CACHE_OBJECT_MAX_BYTES: u64 = 4 * 1024 * 1024;
