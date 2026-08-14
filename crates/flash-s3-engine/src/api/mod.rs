//! HTTP / S3 API layer (Axum).
//!
//! Path-style routing: `/{bucket}` and `/{bucket}/{key…}` plus ops endpoints
//! `/healthz`, `/readyz`, `/metrics`.

mod aws_chunked;
mod error;
mod post_object;
mod router;
mod xml;

pub use error::s3_error_response;
pub use router::router;
