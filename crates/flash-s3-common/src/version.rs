//! Build/release version of the FlashS3 workspace crates.
//!
//! Local builds use `[workspace.package].version` from `Cargo.toml`.
//! Release images override that version at Docker build time from the Git tag
//! (`VERSION` build-arg, e.g. `v0.2.0` → `0.2.0`).

/// Semver version string embedded at compile time (`CARGO_PKG_VERSION`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
