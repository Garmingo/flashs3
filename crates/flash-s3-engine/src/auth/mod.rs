//! Authentication and authorization.
//!
//! Pipeline per request:
//! 1. [`sigv4`] verifies AWS Signature V4 (header or presigned query)
//! 2. [`credentials`] resolves the access key to a [`StoredKey`]
//! 3. [`authorize`] applies bucket policy then rich ACLs

mod authorize;
mod credentials;
mod post_policy;
mod sigv4;

pub(crate) use post_policy::{verify_anonymous_post_allowed, verify_post_policy, PostFormFields};
pub(crate) use post_policy::resolve_post_object_key;

pub use authorize::{AuthContext, Authorizer, S3Action};
pub use credentials::{CredentialStore, StoredKey};
pub use sigv4::{hash_payload, verify_request, AuthResult, ChunkSigning};
