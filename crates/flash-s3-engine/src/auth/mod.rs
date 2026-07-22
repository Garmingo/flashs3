//! Authentication and authorization.
//!
//! Pipeline per request:
//! 1. [`sigv4`] verifies AWS Signature V4 (header or presigned query)
//! 2. [`credentials`] resolves the access key to a [`StoredKey`]
//! 3. [`authorize`] applies bucket policy then rich ACLs

mod authorize;
mod credentials;
mod sigv4;

pub use authorize::{AuthContext, Authorizer, S3Action};
pub use credentials::{CredentialStore, StoredKey};
pub use sigv4::{hash_payload, verify_request, AuthResult, ChunkSigning};
