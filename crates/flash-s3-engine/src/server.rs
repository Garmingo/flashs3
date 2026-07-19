use std::sync::Arc;

use flash_s3_common::FlashError;

use crate::auth::{Authorizer, CredentialStore};
use crate::cache::ObjectCache;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::storage::ObjectStore;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: ObjectStore,
    pub cache: Arc<ObjectCache>,
    pub creds: CredentialStore,
    pub authorizer: Arc<Authorizer>,
    pub metrics: Metrics,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, FlashError> {
        let metrics = Metrics::new().map_err(|e| FlashError::Internal(e.to_string()))?;
        let store = ObjectStore::open(config.data_dir.clone(), metrics.clone())?;
        let cache = Arc::new(ObjectCache::new(config.cache_config(), metrics.clone()));
        let creds = CredentialStore::open(
            &config.data_dir,
            config.access_key.as_deref(),
            config.secret_key.as_deref(),
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
}
