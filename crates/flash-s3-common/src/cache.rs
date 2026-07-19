//! Cache configuration types shared by engine config and the operator CRD.

use serde::{Deserialize, Serialize};

/// Which in-process cache implementation the engine should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum CachePolicyKind {
    /// Disable caching; every read hits disk.
    None,
    /// Byte-weighted LRU via the `moka` crate (default).
    #[default]
    InMemoryLru,
}

impl CachePolicyKind {
    /// Parse a case-insensitive policy name from env / CRD strings.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Self::None,
            "inmemorylru" | "in_memory_lru" | "lru" => Self::InMemoryLru,
            _ => Self::InMemoryLru,
        }
    }
}

/// Fully resolved cache settings used at engine startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Active policy.
    pub policy: CachePolicyKind,
    /// Total byte budget for cached object bodies.
    pub max_size_in_bytes: u64,
    /// Hard cap: objects above this size are never cached.
    pub object_max_size_in_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            policy: CachePolicyKind::InMemoryLru,
            max_size_in_bytes: crate::env::DEFAULT_CACHE_MAX_BYTES,
            object_max_size_in_bytes: crate::env::DEFAULT_CACHE_OBJECT_MAX_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_names() {
        assert_eq!(CachePolicyKind::parse("none"), CachePolicyKind::None);
        assert_eq!(CachePolicyKind::parse("InMemoryLRU"), CachePolicyKind::InMemoryLru);
        assert_eq!(CachePolicyKind::parse("lru"), CachePolicyKind::InMemoryLru);
    }
}
