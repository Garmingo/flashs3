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

mod index;
pub mod layout;
mod store;

pub use index::IndexEntry;
pub use store::{BucketInfo, ObjectMeta, ObjectStore, PutObjectOpts};
