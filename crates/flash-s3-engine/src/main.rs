//! `flash-s3-engine` binary entrypoint.
//!
//! Boots tracing, loads [`flash_s3_engine::Config`], serves the Axum router,
//! and shuts down gracefully on Ctrl+C / SIGTERM.

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use flash_s3_engine::api::router;
use flash_s3_engine::{AppState, Config};
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();
    tracing::info!(
        version = flash_s3_common::VERSION,
        bind = %config.bind,
        data_dir = %config.data_dir.display(),
        "starting flash-s3-engine"
    );

    let state = AppState::new(config).context("failed to initialize engine")?;
    state
        .initialize_default_bucket()
        .await
        .context("failed to initialize default bucket")?;
    let bind = state.config.bind.clone();
    let app = router(state);

    let addr: SocketAddr = bind.parse().context("invalid FLASHS3_BIND")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    tracing::info!(%addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    tracing::info!("shutdown complete");
    Ok(())
}

/// Wait for Ctrl+C or SIGTERM before draining in-flight requests.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
