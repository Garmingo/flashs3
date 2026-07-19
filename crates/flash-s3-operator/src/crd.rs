use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "storage.flashs3.io",
    version = "v1alpha1",
    kind = "FlashS3Bucket",
    plural = "flashs3buckets",
    shortname = "fs3b",
    namespaced,
    status = "FlashS3BucketStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Endpoint","type":"string","jsonPath":".status.endpoint"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct FlashS3BucketSpec {
    /// PVC storage size, e.g. 50Gi
    pub size: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class_name: Option<String>,
    #[serde(default = "default_image")]
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthSpec>,
    #[serde(default = "default_acl")]
    pub default_object_acl: String,
    #[serde(default)]
    pub cache: CacheSpec,
    #[serde(default)]
    pub service: ServiceSpec,
    #[serde(default = "default_true")]
    pub retain_pvc: bool,
}

fn default_image() -> String {
    "ghcr.io/garmingo/flash-s3-engine:latest".into()
}
fn default_acl() -> String {
    "private".into()
}
fn default_true() -> bool {
    true
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretRef>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    pub name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheSpec {
    #[serde(default = "default_cache_policy")]
    pub policy: String,
    #[serde(default = "default_cache_bytes")]
    pub max_size_in_bytes: u64,
    #[serde(default = "default_object_max")]
    pub object_max_size_in_bytes: u64,
}

impl Default for CacheSpec {
    fn default() -> Self {
        Self {
            policy: default_cache_policy(),
            max_size_in_bytes: default_cache_bytes(),
            object_max_size_in_bytes: default_object_max(),
        }
    }
}

fn default_cache_policy() -> String {
    "InMemoryLRU".into()
}
fn default_cache_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}
fn default_object_max() -> u64 {
    4 * 1024 * 1024
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    #[serde(default = "default_svc_type")]
    pub r#type: String,
    #[serde(default = "default_port")]
    pub port: i32,
}

impl Default for ServiceSpec {
    fn default() -> Self {
        Self {
            r#type: default_svc_type(),
            port: default_port(),
        }
    }
}

fn default_svc_type() -> String {
    "ClusterIP".into()
}
fn default_port() -> i32 {
    9000
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct FlashS3BucketStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
