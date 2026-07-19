mod crd;
mod reconcile;

use std::sync::Arc;

use futures_util::StreamExt;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client};
use tracing_subscriber::EnvFilter;

use crate::crd::FlashS3Bucket;
use crate::reconcile::{reconcile, ContextData, Error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let client = Client::try_default().await?;
    let buckets = Api::<FlashS3Bucket>::all(client.clone());
    let ctx = Arc::new(ContextData { client });

    tracing::info!("flash-s3-operator starting");

    Controller::new(buckets, WatcherConfig::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => tracing::info!(?o, "reconciled"),
                Err(e) => tracing::error!(error = %e, "reconcile failed"),
            }
        })
        .await;

    Ok(())
}

fn error_policy(_obj: Arc<FlashS3Bucket>, error: &Error, _ctx: Arc<ContextData>) -> Action {
    tracing::warn!(error = %error, "requeue after error");
    Action::requeue(std::time::Duration::from_secs(15))
}
