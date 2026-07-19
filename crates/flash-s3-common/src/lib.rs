//! Shared primitives for FlashS3 engine and operator.
//!
//! This crate intentionally has **no** Tokio/Axum/Kubernetes dependencies so both
//! binaries can share types (ACLs, policies, env keys, errors) without pulling in
//! each other's runtime stack.

#![warn(missing_docs)]

mod acl;
mod cache;
mod env;
mod error;
mod identity;
mod policy;

pub use acl::*;
pub use cache::*;
pub use env::*;
pub use error::*;
pub use identity::*;
pub use policy::*;
