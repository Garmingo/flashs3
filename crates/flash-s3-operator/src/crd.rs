//! `FlashS3Bucket` Custom Resource definitions (kube-rs + schemars).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Desired state for one FlashS3 engine instance backed by a PVC.
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
    /// PVC storage size, e.g. `50Gi`.
    pub size: String,
    /// Optional StorageClass for the PVC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class_name: Option<String>,
    /// Engine container image.
    #[serde(default = "default_image")]
    pub image: String,
    /// Credentials source; if omitted, the operator creates a Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthSpec>,
    /// Default canned ACL for new objects (`private`, `public-read`, …).
    #[serde(default = "default_acl")]
    pub default_object_acl: String,
    /// Cache settings mapped to `FLASHS3_CACHE_*` env vars.
    #[serde(default)]
    pub cache: CacheSpec,
    /// Kubernetes Service exposure.
    #[serde(default)]
    pub service: ServiceSpec,
    /// Keep the PVC on CR delete (default `true` to avoid data loss).
    #[serde(default = "default_true")]
    pub retain_pvc: bool,
}

fn default_image() -> String {
    "registry.garmingo.net/garmingo/flashs3/engine:latest".into()
}
fn default_acl() -> String {
    "private".into()
}
fn default_true() -> bool {
    true
}

/// Authentication configuration for the engine pod.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthSpec {
    /// Existing Secret with keys `accessKey` / `secretKey`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretRef>,
}

/// Reference to a Kubernetes Secret holding S3 credentials.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    /// Secret name in the same namespace.
    pub name: String,
}

/// In-memory cache settings forwarded to the engine.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheSpec {
    /// `None` or `InMemoryLRU`.
    #[serde(default = "default_cache_policy")]
    pub policy: String,
    /// Total cache byte budget.
    #[serde(default = "default_cache_bytes")]
    pub max_size_in_bytes: u64,
    /// Max object size eligible for caching.
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

/// Service settings for the S3 endpoint.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Service type (`ClusterIP`, `NodePort`, `LoadBalancer`).
    #[serde(default = "default_svc_type")]
    pub r#type: String,
    /// Service / container port (default 9000).
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

/// Observed state written by the operator.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct FlashS3BucketStatus {
    /// High-level phase (`Pending`, `Ready`, `Failed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// Cluster-internal HTTP endpoint for S3 clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional human-readable status detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
