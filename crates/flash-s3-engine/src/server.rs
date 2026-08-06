//! Shared application state wired into Axum handlers.

use std::sync::Arc;

use flash_s3_common::{CorsConfiguration, FlashError};

use crate::auth::{Authorizer, CredentialStore};
use crate::cache::ObjectCache;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::storage::ObjectStore;

/// Cloneable handle passed to every HTTP handler via Axum `State`.
#[derive(Clone)]
pub struct AppState {
    /// Process configuration.
    pub config: Arc<Config>,
    /// Disk + index backend.
    pub store: ObjectStore,
    /// Optional in-memory object cache.
    pub cache: Arc<ObjectCache>,
    /// API key store.
    pub creds: CredentialStore,
    /// Policy/ACL authorizer.
    pub authorizer: Arc<Authorizer>,
    /// Prometheus metrics.
    pub metrics: Metrics,
}

impl AppState {
    /// Construct store, cache, credentials, and metrics from `config`.
    pub fn new(config: Config) -> Result<Self, FlashError> {
        let metrics = Metrics::new().map_err(|e| FlashError::Internal(e.to_string()))?;
        let store = ObjectStore::open(config.data_dir.clone(), metrics.clone())?;
        let cache = Arc::new(ObjectCache::new(config.cache_config(), metrics.clone()));
        let creds = CredentialStore::open(
            &config.data_dir,
            config.access_key.as_deref(),
            config.secret_key.as_deref(),
            config.credentials_key.as_deref(),
        )?;
        let authorizer = Arc::new(Authorizer {
            root_bypasses: config.root_bypasses_acl,
            auth_required: config.auth_required,
        });
        Ok(Self {
            config: Arc::new(config),
            store,
            cache,
            creds,
            authorizer,
            metrics,
        })
    }

    /// Create the configured startup bucket, if any.
    ///
    /// The operation is idempotent so restarts retain the existing bucket and
    /// its contents. A root credential is required to own the initial bucket.
    ///
    /// On every start (including when the bucket already exists):
    /// - [`Config::default_object_acl`] is written to `bucket.json`
    /// - when CORS env is set, the CORS configuration is (re)applied so CRD/env
    ///   changes take effect after a pod restart without a separate S3 API call
    pub async fn initialize_default_bucket(&self) -> Result<(), FlashError> {
        let Some(name) = self.config.default_bucket_name.as_deref() else {
            if self.config.default_bucket_cors_allow_all || self.config.default_bucket_cors.is_some()
            {
                return Err(FlashError::InvalidRequest(
                    "FLASHS3_DEFAULT_BUCKET_CORS(_ALLOW_ALL) requires FLASHS3_DEFAULT_BUCKET_NAME"
                        .into(),
                ));
            }
            return Ok(());
        };
        let owner = self
            .creds
            .list()
            .into_iter()
            .find(|key| key.is_root)
            .ok_or_else(|| {
                FlashError::InvalidRequest(
                    "FLASHS3_DEFAULT_BUCKET_NAME requires a bootstrap root credential".into(),
                )
            })?;

        match self
            .store
            .create_bucket(
                name,
                owner.canonical_id,
                &owner.display_name,
                self.config.default_object_acl(),
            )
            .await
        {
            Ok(_) | Err(FlashError::BucketAlreadyOwnedByYou) => {}
            Err(error) => return Err(error),
        }

        // Re-apply on every start so CRD/env changes take effect after restart.
        self.store
            .set_default_object_acl(name, self.config.default_object_acl())
            .await?;

        let cors = if self.config.default_bucket_cors_allow_all {
            Some(CorsConfiguration::allow_all())
        } else if let Some(cors_json) = self.config.default_bucket_cors.as_deref() {
            Some(CorsConfiguration::parse_json(cors_json)?)
        } else {
            None
        };
        if let Some(cors) = cors {
            self.store.put_bucket_cors(name, &cors.to_xml()).await?;
        }
        Ok(())
    }
}
