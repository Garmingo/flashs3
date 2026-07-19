//! FlashS3 autonomous S3-compatible storage engine.
//!
//! The engine is intentionally **Kubernetes-free**: it speaks S3 over HTTP,
//! caches hot objects in RAM, and persists to a local directory. Run it with
//! `cargo run -p flash-s3-engine` or as a container; the optional operator only
//! wires env vars + a PVC.

pub mod api;
pub mod auth;
pub mod cache;
pub mod config;
pub mod metrics;
pub mod server;
pub mod storage;

pub use config::Config;
pub use server::AppState;
