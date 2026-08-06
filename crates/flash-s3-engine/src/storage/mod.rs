//! Local filesystem object store (source of truth).
//!
//! Layout under `$FLASHS3_DATA_DIR`:
//! ```text
//! buckets/<name>/objects/<aa>/<bb>/<sha256>/current/{data,meta.json}
//! buckets/<name>/multipart/<uploadId>/
//! buckets/<name>/policy.json
//! buckets/<name>/cors.xml
//! index/objects.redb
//! credentials.json
//! ```
//!
//! Object keys are **not** used as directory paths; see [`layout`] for the
//! 4-hex (2+2) hash sharding strategy.

mod checksum;
mod index;
pub mod layout;
mod sse;
mod store;

pub use checksum::verify_and_collect as verify_checksums;
pub use index::{IndexEntry, ObjectListResult};
pub use sse::{derive_sse_key, decrypt as sse_decrypt, encrypt as sse_encrypt, request_wants_sse_s3};
pub use store::{BucketInfo, ObjectMeta, ObjectStore, PutObjectOpts};
