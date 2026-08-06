//! Reconcile loop: map a [`FlashS3Bucket`] CR to Kubernetes objects.
//!
//! Creates/updates PVC, credentials Secret, single-replica Deployment, and
//! Service. On delete, removes Deployment/Service and optionally the PVC.

use std::sync::Arc;

use flash_s3_common::{
    ENV_ACCESS_KEY, ENV_CACHE_MAX_BYTES, ENV_CACHE_OBJECT_MAX_BYTES, ENV_CACHE_POLICY,
    ENV_DATA_DIR, ENV_DEFAULT_BUCKET_CORS, ENV_DEFAULT_BUCKET_CORS_ALLOW_ALL,
    ENV_DEFAULT_BUCKET_NAME, ENV_DEFAULT_OBJECT_ACL, ENV_SECRET_KEY,
};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    Container, EnvVar, EnvVarSource, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    PersistentVolumeClaimVolumeSource, PodSpec, PodTemplateSpec, Secret, SecretKeySelector,
    Service, ServicePort, ServiceSpec, Volume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
use kube::{Api, Client, Resource, ResourceExt};
use serde_json::json;
use thiserror::Error;

use crate::crd::FlashS3Bucket;

const FINALIZER: &str = "flashs3.io/finalizer";

/// Shared controller context (Kubernetes API client).
pub struct ContextData {
    /// Default kube client for the operator pod.
    pub client: Client,
}

/// Reconcile errors surfaced to the controller runtime.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying kube-rs / API error.
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
    /// CR without namespace (should not happen for namespaced resources).
    #[error("missing namespace")]
    MissingNamespace,
    /// Catch-all for finalizer / apply failures.
    #[error("{0}")]
    Other(String),
    /// Invalid CR combination (e.g. cors without defaultBucketName).
    #[error("invalid FlashS3Bucket spec: {0}")]
    InvalidSpec(String),
}

/// Controller entrypoint: apply or cleanup under a finalizer.
pub async fn reconcile(obj: Arc<FlashS3Bucket>, ctx: Arc<ContextData>) -> Result<Action, Error> {
    let ns = obj.namespace().ok_or(Error::MissingNamespace)?;
    let api: Api<FlashS3Bucket> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(b) => apply(b, ctx.clone()).await,
            FinalizerEvent::Cleanup(b) => cleanup(b, ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| Error::Other(e.to_string()))
}

async fn apply(bucket: Arc<FlashS3Bucket>, ctx: Arc<ContextData>) -> Result<Action, Error> {
    let ns = bucket.namespace().ok_or(Error::MissingNamespace)?;
    let name = bucket.name_any();
    let client = &ctx.client;

    ensure_pvc(client, &ns, &name, &bucket).await?;
    let secret_name = ensure_secret(client, &ns, &name, &bucket).await?;
    ensure_deployment(client, &ns, &name, &bucket, &secret_name).await?;
    ensure_service(client, &ns, &name, &bucket).await?;

    let endpoint = format!(
        "http://{name}.{ns}.svc:{}",
        bucket.spec.service.port
    );
    patch_status(client, &ns, &name, "Ready", &endpoint, None).await?;

    Ok(Action::requeue(std::time::Duration::from_secs(60)))
}

async fn cleanup(bucket: Arc<FlashS3Bucket>, ctx: Arc<ContextData>) -> Result<Action, Error> {
    let ns = bucket.namespace().ok_or(Error::MissingNamespace)?;
    let name = bucket.name_any();
    let client = &ctx.client;

    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);
    let _ = deploy_api.delete(&name, &Default::default()).await;
    let _ = svc_api.delete(&name, &Default::default()).await;

    if !bucket.spec.retain_pvc {
        let pvc_api: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &ns);
        let _ = pvc_api.delete(&pvc_name(&name), &Default::default()).await;
    }

    Ok(Action::await_change())
}

fn pvc_name(name: &str) -> String {
    format!("{name}-data")
}

fn owner_ref(bucket: &FlashS3Bucket) -> OwnerReference {
    OwnerReference {
        api_version: FlashS3Bucket::api_version(&()).to_string(),
        kind: FlashS3Bucket::kind(&()).to_string(),
        name: bucket.name_any(),
        uid: bucket.meta().uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

async fn ensure_pvc(
    client: &Client,
    ns: &str,
    name: &str,
    bucket: &FlashS3Bucket,
) -> Result<(), Error> {
    let api: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), ns);
    let pvc = PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(pvc_name(name)),
            namespace: Some(ns.to_string()),
            owner_references: Some(vec![owner_ref(bucket)]),
            labels: Some(labels(name)),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".into()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(
                    [("storage".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity(bucket.spec.size.clone()))]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            }),
            storage_class_name: bucket.spec.storage_class_name.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };
    api.patch(
        &pvc_name(name),
        &PatchParams::apply("flash-s3-operator").force(),
        &Patch::Apply(&pvc),
    )
    .await?;
    Ok(())
}

async fn ensure_secret(
    client: &Client,
    ns: &str,
    name: &str,
    bucket: &FlashS3Bucket,
) -> Result<String, Error> {
    if let Some(auth) = &bucket.spec.auth {
        if let Some(r) = &auth.secret_ref {
            return Ok(r.name.clone());
        }
    }
    let secret_name = format!("{name}-creds");
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    // Only create if missing — do not rotate existing secrets
    if api.get(&secret_name).await.is_ok() {
        return Ok(secret_name);
    }
    let access = format!("flash{}", &uuid_like(name)[..8.min(uuid_like(name).len())]);
    let secret_key = format!("sk-{}", uuid_like(&format!("{name}-secret")));
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(ns.to_string()),
            owner_references: Some(vec![owner_ref(bucket)]),
            labels: Some(labels(name)),
            ..Default::default()
        },
        string_data: Some(
            [
                ("accessKey".to_string(), access),
                ("secretKey".to_string(), secret_key),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    };
    api.patch(
        &secret_name,
        &PatchParams::apply("flash-s3-operator").force(),
        &Patch::Apply(&secret),
    )
    .await?;
    Ok(secret_name)
}

fn uuid_like(s: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:x}", h.finish())
}

async fn ensure_deployment(
    client: &Client,
    ns: &str,
    name: &str,
    bucket: &FlashS3Bucket,
    secret_name: &str,
) -> Result<(), Error> {
    let api: Api<Deployment> = Api::namespaced(client.clone(), ns);
    let labels = labels(name);
    let mut container_env = vec![
        env(ENV_DATA_DIR, "/data"),
        env(ENV_CACHE_POLICY, &bucket.spec.cache.policy),
        env(
            ENV_CACHE_MAX_BYTES,
            &bucket.spec.cache.max_size_in_bytes.to_string(),
        ),
        env(
            ENV_CACHE_OBJECT_MAX_BYTES,
            &bucket.spec.cache.object_max_size_in_bytes.to_string(),
        ),
        env(ENV_DEFAULT_OBJECT_ACL, &bucket.spec.default_object_acl),
        env_from_secret(ENV_ACCESS_KEY, secret_name, "accessKey"),
        env_from_secret(ENV_SECRET_KEY, secret_name, "secretKey"),
    ];
    if let Some(default_bucket_name) = &bucket.spec.default_bucket_name {
        container_env.push(env(ENV_DEFAULT_BUCKET_NAME, default_bucket_name));
    }
    if let Some(cors) = &bucket.spec.cors {
        if bucket.spec.default_bucket_name.is_none() {
            return Err(Error::InvalidSpec(
                "spec.cors requires spec.defaultBucketName".into(),
            ));
        }
        if cors.allow_all && !cors.rules.is_empty() {
            return Err(Error::InvalidSpec(
                "spec.cors.allowAll cannot be combined with spec.cors.rules".into(),
            ));
        }
        if cors.allow_all {
            container_env.push(env(ENV_DEFAULT_BUCKET_CORS_ALLOW_ALL, "true"));
        } else if cors.rules.is_empty() {
            return Err(Error::InvalidSpec(
                "spec.cors requires allowAll: true or at least one rule".into(),
            ));
        } else {
            let cors_json = serde_json::to_string(cors)
                .map_err(|e| Error::Other(format!("serialize cors: {e}")))?;
            container_env.push(env(ENV_DEFAULT_BUCKET_CORS, &cors_json));
        }
    }
    let deploy = Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            owner_references: Some(vec![owner_ref(bucket)]),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            // The PVC is mounted read-write by one engine instance. Recreate
            // prevents a rolling update from briefly running old and new pods
            // against that same local store.
            strategy: Some(DeploymentStrategy {
                type_: Some("Recreate".into()),
                ..Default::default()
            }),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "flash-s3-engine".into(),
                        image: Some(bucket.spec.image.clone()),
                        ports: Some(vec![k8s_openapi::api::core::v1::ContainerPort {
                            container_port: bucket.spec.service.port,
                            name: Some("s3".into()),
                            ..Default::default()
                        }]),
                        env: Some(container_env),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "data".into(),
                            mount_path: "/data".into(),
                            ..Default::default()
                        }]),
                        readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
                            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                                path: Some("/readyz".into()),
                                port: IntOrString::Int(bucket.spec.service.port),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        liveness_probe: Some(k8s_openapi::api::core::v1::Probe {
                            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                                path: Some("/healthz".into()),
                                port: IntOrString::Int(bucket.spec.service.port),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    volumes: Some(vec![Volume {
                        name: "data".into(),
                        persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                            claim_name: pvc_name(name),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    api.patch(
        name,
        &PatchParams::apply("flash-s3-operator").force(),
        &Patch::Apply(&deploy),
    )
    .await?;
    Ok(())
}

async fn ensure_service(
    client: &Client,
    ns: &str,
    name: &str,
    bucket: &FlashS3Bucket,
) -> Result<(), Error> {
    let api: Api<Service> = Api::namespaced(client.clone(), ns);
    let svc = Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            owner_references: Some(vec![owner_ref(bucket)]),
            labels: Some(labels(name)),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some(bucket.spec.service.r#type.clone()),
            selector: Some(labels(name)),
            ports: Some(vec![ServicePort {
                name: Some("s3".into()),
                port: bucket.spec.service.port,
                target_port: Some(IntOrString::Int(bucket.spec.service.port)),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };
    api.patch(
        name,
        &PatchParams::apply("flash-s3-operator").force(),
        &Patch::Apply(&svc),
    )
    .await?;
    Ok(())
}

async fn patch_status(
    client: &Client,
    ns: &str,
    name: &str,
    phase: &str,
    endpoint: &str,
    message: Option<&str>,
) -> Result<(), Error> {
    let api: Api<FlashS3Bucket> = Api::namespaced(client.clone(), ns);
    let status = json!({
        "status": {
            "phase": phase,
            "endpoint": endpoint,
            "message": message,
        }
    });
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&status))
        .await?;
    Ok(())
}

fn labels(name: &str) -> std::collections::BTreeMap<String, String> {
    [
        ("app.kubernetes.io/name".into(), "flash-s3".into()),
        ("app.kubernetes.io/instance".into(), name.to_string()),
        ("app.kubernetes.io/managed-by".into(), "flash-s3-operator".into()),
    ]
    .into_iter()
    .collect()
}

fn env(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: Some(value.into()),
        ..Default::default()
    }
}

fn env_from_secret(name: &str, secret: &str, key: &str) -> EnvVar {
    EnvVar {
        name: name.into(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                name: secret.into(),
                key: key.into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

